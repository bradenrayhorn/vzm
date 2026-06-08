package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var (
	outboundClient    = &http.Client{Transport: newOutboundTransport()}
	controlUnixPath   string
	approvalRequestID uint64
)

func newOutboundTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	transport.TLSClientConfig = &tls.Config{NextProtos: []string{"http/1.1"}}
	return transport
}

var secretPattern = regexp.MustCompile(`\{vzm:([^}]+)\}`)

const maxSecretScanBodySize int64 = 1 << 20

type approvalRequest struct {
	ID      string   `json:"id"`
	Type    string   `json:"type"`
	Domain  string   `json:"domain"`
	Method  string   `json:"method"`
	Path    string   `json:"path"`
	Secrets []string `json:"secrets"`
}

type approvalResponse struct {
	ID            string            `json:"id"`
	Approved      bool              `json:"approved"`
	Substitutions map[string]string `json:"substitutions,omitempty"`
}

func askForApproval(requestType, domain, method, path string, secrets []string) approvalResponse {
	if controlUnixPath == "" {
		log.Printf("approval denied: no control socket configured for %s %s %s %s", requestType, method, domain, path)
		return approvalResponse{Approved: false}
	}

	conn, err := net.Dial("unix", controlUnixPath)
	if err != nil {
		log.Printf("approval denied: connect control socket: %v", err)
		return approvalResponse{Approved: false}
	}
	defer conn.Close()

	request := approvalRequest{
		ID:      nextApprovalRequestID(),
		Type:    requestType,
		Domain:  domain,
		Method:  method,
		Path:    path,
		Secrets: secrets,
	}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		log.Printf("approval denied: write request: %v", err)
		return approvalResponse{Approved: false}
	}

	var response approvalResponse
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		log.Printf("approval denied: read response: %v", err)
		return approvalResponse{Approved: false}
	}
	if response.ID != request.ID {
		log.Printf("approval denied: mismatched response id %q for request %q", response.ID, request.ID)
		return approvalResponse{Approved: false}
	}

	return response
}

func nextApprovalRequestID() string {
	return strconv.FormatUint(atomic.AddUint64(&approvalRequestID, 1), 10)
}

func main() {
	listenUnixPath := flag.String("listen-unix", "", "Unix domain socket path for the proxy listener")
	listenTCPAddr := flag.String("listen-tcp", ":26604", "TCP address for the proxy listener when --listen-unix is not set")
	caCertPath := flag.String("ca-cert", "", "Path to write the MITM CA certificate PEM")
	flag.StringVar(&controlUnixPath, "control-unix", "", "Unix domain socket path for approval requests")
	flag.Parse()

	pemPath := *caCertPath
	if pemPath == "" {
		var err error
		pemPath, err = writeCertificateAuthorityPEMToWorkingDir()
		if err != nil {
			log.Fatal(err)
		}
	} else if err := writeCertificateAuthorityPEMToPath(pemPath); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote MITM CA PEM to %s", pemPath)

	listener, err := listen(*listenUnixPath, *listenTCPAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	if *listenUnixPath != "" {
		defer os.Remove(*listenUnixPath)
	}

	server := &http.Server{
		Handler: http.HandlerFunc(handleProxy),
	}
	log.Printf("proxy listening on %s", listener.Addr())
	log.Fatal(server.Serve(listener))
}

func listen(unixPath, tcpAddr string) (net.Listener, error) {
	if unixPath == "" {
		return net.Listen("tcp", tcpAddr)
	}

	_ = os.Remove(unixPath)
	listener, err := net.Listen("unix", unixPath)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(unixPath, 0o600); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}

func handleProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "Only CONNECT allowed", http.StatusMethodNotAllowed)
		return
	}

	targetHost, targetPort, err := connectTarget(r)
	if err != nil {
		log.Printf("blocked invalid CONNECT target %q: %v", r.Host, err)
		http.Error(w, "Invalid CONNECT target", http.StatusBadRequest)
		return
	}

	switch targetPort {
	case "22":
		handleSSHTunnel(w, targetHost, targetPort)
	case "443":
		handleHTTPSConnect(w, targetHost, targetPort)
	default:
		log.Printf("blocked CONNECT to unsupported port %s for %s", targetPort, targetHost)
		http.Error(w, "CONNECT port not allowed", http.StatusForbidden)
	}
}

func connectTarget(r *http.Request) (string, string, error) {
	target := r.Host
	if target == "" && r.URL != nil {
		target = r.URL.Host
	}

	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return "", "", err
	}
	host = normalizeDomain(host)
	if host == "" || port == "" {
		return "", "", fmt.Errorf("invalid host or port")
	}
	return host, port, nil
}

func handleSSHTunnel(w http.ResponseWriter, targetHost, targetPort string) {
	if !askForApproval("SSH", targetHost, "CONNECT", targetPort, nil).Approved {
		http.Error(w, "Blocked by Host Application", http.StatusForbidden)
		return
	}

	upstreamConn, err := dialPublicTCP(targetHost, targetPort)
	if err != nil {
		log.Printf("SSH tunnel dial failed for %s:%s: %v", targetHost, targetPort, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer upstreamConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, clientBuffer, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	tunnelRawConnections(clientConn, clientBuffer, upstreamConn)
}

func dialPublicTCP(host, port string) (net.Conn, error) {
	if ip := net.ParseIP(host); ip != nil {
		if !isAllowedDestinationIP(ip) {
			return nil, fmt.Errorf("blocked destination address %s", ip.String())
		}
		return net.DialTimeout("tcp", net.JoinHostPort(ip.String(), port), 15*time.Second)
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for _, ip := range ips {
		if !isAllowedDestinationIP(ip) {
			log.Printf("blocked destination address %s for %s", ip.String(), host)
			continue
		}

		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), port), 15*time.Second)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no public addresses for %s", host)
}

func isAllowedDestinationIP(ip net.IP) bool {
	return ip != nil &&
		ip.IsGlobalUnicast() &&
		!ip.IsLoopback() &&
		!ip.IsPrivate() &&
		!ip.IsLinkLocalUnicast()
}

func handleHTTPSConnect(w http.ResponseWriter, targetHost, targetPort string) {
	if !askForApproval("CONNECT", targetHost, "", "", nil).Approved {
		http.Error(w, "Blocked by Host Application", http.StatusForbidden)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	cert, err := generateFakeCertForDomain(targetHost)
	if err != nil {
		log.Println("Error generating certificate:", err)
		return
	}
	tlsConn := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
	})
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer tlsConn.Close()

	bufReader := bufio.NewReader(tlsConn)
	for {
		innerReq, err := http.ReadRequest(bufReader)
		if err != nil {
			if err != io.EOF {
				log.Println("Error reading inner request:", err)
			}
			break
		}

		if !hostHeaderMatches(innerReq.Host, targetHost, targetPort) {
			log.Printf("Domain fronting detected! CONNECT: %s, Host: %s", net.JoinHostPort(targetHost, targetPort), innerReq.Host)
			break
		}

		secretNames, err := findRequestSecrets(innerReq)
		if err != nil {
			log.Println("Error scanning request for secrets:", err)
			tlsConn.Write([]byte("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
			break
		}

		approval := askForApproval("REQUEST", targetHost, innerReq.Method, approvalPath(innerReq), secretNames)
		if !approval.Approved {
			tlsConn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
			break
		}
		if err := applySecretSubstitutions(innerReq, approval.Substitutions); err != nil {
			log.Println("Error substituting request secrets:", err)
			tlsConn.Write([]byte("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
			break
		}

		innerReq.URL.Scheme = "https"
		innerReq.URL.Host = innerReq.Host
		innerReq.RequestURI = ""
		stripHopByHopHeaders(innerReq.Header)
		innerReq.Close = false

		resp, err := outboundClient.Do(innerReq)
		if err != nil {
			log.Println("Error executing upstream request:", err)
			tlsConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
			break
		}

		stripHopByHopHeaders(resp.Header)
		if err := resp.Write(tlsConn); err != nil {
			log.Println("Error writing response:", err)
		}
		resp.Body.Close()
	}
}

func hostHeaderMatches(header, targetHost, targetPort string) bool {
	host, port, err := net.SplitHostPort(strings.TrimSpace(header))
	if err == nil {
		return normalizeDomain(host) == targetHost && port == targetPort
	}

	// Host headers often omit the default HTTPS port.
	host = strings.Trim(strings.TrimSpace(header), "[]")
	return normalizeDomain(host) == targetHost
}

func tunnelRawConnections(clientConn net.Conn, clientBuffer *bufio.ReadWriter, upstreamConn net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstreamConn, clientBuffer)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(clientConn, upstreamConn)
		done <- struct{}{}
	}()
	<-done
}

func approvalPath(r *http.Request) string {
	if r.URL == nil {
		return ""
	}
	if r.URL.RawQuery == "" {
		return r.URL.Path
	}
	return r.URL.Path + "?" + r.URL.RawQuery
}

func findRequestSecrets(r *http.Request) ([]string, error) {
	secretSet := map[string]struct{}{}

	collectURLSecretNames(r.URL, secretSet)

	for _, values := range r.Header {
		for _, value := range values {
			collectSecretNames(value, secretSet)
		}
	}

	body, inspected, err := readInspectableBody(r)
	if err != nil {
		return nil, err
	}
	if inspected {
		collectSecretNames(string(body), secretSet)
	}
	return sortedSecretNames(secretSet), nil
}

func collectURLSecretNames(u *url.URL, secretSet map[string]struct{}) {
	if u == nil {
		return
	}

	collectSecretNames(u.Path, secretSet)
	collectSecretNames(u.RawPath, secretSet)
	for key, values := range u.Query() {
		collectSecretNames(key, secretSet)
		for _, value := range values {
			collectSecretNames(value, secretSet)
		}
	}
}

func collectSecretNames(text string, secretSet map[string]struct{}) {
	for _, match := range secretPattern.FindAllStringSubmatch(text, -1) {
		if len(match) < 2 {
			continue
		}
		name := strings.TrimSpace(match[1])
		if name != "" {
			secretSet[name] = struct{}{}
		}
	}
}

func sortedSecretNames(secretSet map[string]struct{}) []string {
	return slices.Sorted(maps.Keys(secretSet))
}

func applySecretSubstitutions(r *http.Request, substitutions map[string]string) error {
	if len(substitutions) == 0 {
		return nil
	}

	applyURLSecretSubstitutions(r.URL, substitutions)

	for key, values := range r.Header {
		for i, value := range values {
			values[i] = substituteSecrets(value, substitutions)
		}
		r.Header[key] = values
	}

	body, inspected, err := readInspectableBody(r)
	if err != nil {
		return err
	}
	if !inspected {
		return nil
	}

	rewritten := substituteSecretsBytes(body, substitutions)
	r.Body = io.NopCloser(bytes.NewReader(rewritten))
	r.ContentLength = int64(len(rewritten))
	r.Header.Set("Content-Length", strconv.Itoa(len(rewritten)))
	r.TransferEncoding = nil
	return nil
}

func applyURLSecretSubstitutions(u *url.URL, substitutions map[string]string) {
	if u == nil {
		return
	}

	if rewrittenPath := substituteSecrets(u.Path, substitutions); rewrittenPath != u.Path {
		u.Path = rewrittenPath
		u.RawPath = ""
	} else if rewrittenRawPath := substituteSecrets(u.RawPath, substitutions); rewrittenRawPath != u.RawPath {
		u.RawPath = rewrittenRawPath
	}

	query := u.Query()
	for key, values := range query {
		newKey := substituteSecrets(key, substitutions)
		for i, value := range values {
			values[i] = substituteSecrets(value, substitutions)
		}
		if newKey != key {
			delete(query, key)
			query[newKey] = values
		}
	}
	u.RawQuery = query.Encode()
}

func readInspectableBody(r *http.Request) ([]byte, bool, error) {
	if r.Body == nil {
		return nil, false, nil
	}
	if r.ContentLength < 0 || r.ContentLength > maxSecretScanBodySize || hasExpectContinue(r) {
		return nil, false, nil
	}

	originalBody := r.Body
	body, err := io.ReadAll(io.LimitReader(originalBody, maxSecretScanBodySize+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(body)) > maxSecretScanBodySize {
		r.Body = struct {
			io.Reader
			io.Closer
		}{
			Reader: io.MultiReader(bytes.NewReader(body), originalBody),
			Closer: originalBody,
		}
		return nil, false, nil
	}

	originalBody.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body, true, nil
}

func substituteSecrets(text string, substitutions map[string]string) string {
	return string(substituteSecretsBytes([]byte(text), substitutions))
}

func substituteSecretsBytes(data []byte, substitutions map[string]string) []byte {
	return secretPattern.ReplaceAllFunc(data, func(match []byte) []byte {
		parts := secretPattern.FindSubmatch(match)
		if len(parts) < 2 {
			return match
		}
		name := strings.TrimSpace(string(parts[1]))
		if value, ok := substitutions[name]; ok {
			return []byte(value)
		}
		return match
	})
}

func hasExpectContinue(r *http.Request) bool {
	for _, value := range r.Header.Values("Expect") {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), "100-continue") {
				return true
			}
		}
	}
	return false
}

func stripHopByHopHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			if name = strings.TrimSpace(name); name != "" {
				header.Del(name)
			}
		}
	}

	for _, name := range []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Proxy-Connection",
		"TE",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		header.Del(name)
	}
}
