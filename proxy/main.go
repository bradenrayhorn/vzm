package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	publicDialer = &net.Dialer{
		Timeout:        15 * time.Second,
		ControlContext: rejectBlockedDialDestination,
	}
	outboundClient = &http.Client{
		Transport: newOutboundTransport(),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	controlUnixPath   string
	approvalRequestID uint64
)

var errBlockedDestination = errors.New("blocked destination")

func newOutboundTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = dialPublicTCPContext
	transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	transport.TLSClientConfig = &tls.Config{NextProtos: []string{"http/1.1"}}
	return transport
}

var secretPattern = regexp.MustCompile(`\{vzm:([^}]+)\}`)

const (
	maxSecretScanBodySize int64 = 1 << 20
	maxApprovalBodySize   int64 = 64 << 10
)

var publicIPv6GlobalUnicastPrefix = mustPrefix("2000::/3")

// IANA special-purpose and non-public destination ranges. IPv4-mapped IPv6
// addresses are handled by Unmap so the embedded IPv4 address follows IPv4 policy.
var blockedDestinationPrefixes = []netip.Prefix{
	mustPrefix("0.0.0.0/8"),         // "this" network
	mustPrefix("10.0.0.0/8"),        // private-use
	mustPrefix("100.64.0.0/10"),     // carrier-grade NAT
	mustPrefix("127.0.0.0/8"),       // loopback
	mustPrefix("169.254.0.0/16"),    // link-local
	mustPrefix("172.16.0.0/12"),     // private-use
	mustPrefix("192.0.0.0/24"),      // IETF protocol assignments
	mustPrefix("192.0.2.0/24"),      // documentation
	mustPrefix("192.31.196.0/24"),   // AS112
	mustPrefix("192.52.193.0/24"),   // AMT
	mustPrefix("192.88.99.0/24"),    // deprecated 6to4 relay anycast
	mustPrefix("192.168.0.0/16"),    // private-use
	mustPrefix("192.175.48.0/24"),   // AS112
	mustPrefix("198.18.0.0/15"),     // benchmarking
	mustPrefix("198.51.100.0/24"),   // documentation
	mustPrefix("203.0.113.0/24"),    // documentation
	mustPrefix("224.0.0.0/4"),       // multicast
	mustPrefix("240.0.0.0/4"),       // reserved/broadcast
	mustPrefix("::/128"),            // unspecified
	mustPrefix("::1/128"),           // loopback
	mustPrefix("64:ff9b::/96"),      // IPv4/IPv6 translation
	mustPrefix("64:ff9b:1::/48"),    // IPv4/IPv6 translation
	mustPrefix("100::/64"),          // discard-only
	mustPrefix("2001::/23"),         // IETF protocol assignments
	mustPrefix("2001:2::/48"),       // benchmarking
	mustPrefix("2001:db8::/32"),     // documentation
	mustPrefix("2002::/16"),         // 6to4
	mustPrefix("2620:4f:8000::/48"), // AS112
	mustPrefix("3fff::/20"),         // documentation
	mustPrefix("5f00::/16"),         // SRv6 SIDs
	mustPrefix("fc00::/7"),          // unique local
	mustPrefix("fe80::/10"),         // link-local
	mustPrefix("fec0::/10"),         // deprecated site-local
	mustPrefix("ff00::/8"),          // multicast
}

func mustPrefix(prefix string) netip.Prefix {
	parsed, err := netip.ParsePrefix(prefix)
	if err != nil {
		panic(err)
	}
	return parsed
}

type approvalRequest struct {
	ID       string           `json:"id"`
	Type     string           `json:"type"`
	Domain   string           `json:"domain"`
	Method   string           `json:"method"`
	URL      string           `json:"url"`
	Headers  []approvalHeader `json:"headers"`
	Body     *approvalBody    `json:"body,omitempty"`
	Warnings []string         `json:"warnings"`
	Secrets  []string         `json:"secrets"`
}

type approvalHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type approvalBody struct {
	Text string `json:"text"`
}

type approvalResponse struct {
	ID            string            `json:"id"`
	Approved      bool              `json:"approved"`
	Substitutions map[string]string `json:"substitutions,omitempty"`
}

func askForApproval(request approvalRequest) approvalResponse {
	if controlUnixPath == "" {
		log.Printf("approval denied: no control socket configured for %s %s %s %s", request.Type, request.Method, request.Domain, request.URL)
		return approvalResponse{Approved: false}
	}
	request.ID = nextApprovalRequestID()
	if request.Headers == nil {
		request.Headers = []approvalHeader{}
	}
	if request.Secrets == nil {
		request.Secrets = []string{}
	}
	if request.Warnings == nil {
		request.Warnings = []string{}
	}

	conn, err := net.Dial("unix", controlUnixPath)
	if err != nil {
		log.Printf("approval denied: connect control socket: %v", err)
		return approvalResponse{Approved: false}
	}
	defer conn.Close()

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
	parentPID := flag.Int("parent-pid", 0, "PID of the parent vzm process; exit if it disappears")
	flag.StringVar(&controlUnixPath, "control-unix", "", "Unix domain socket path for approval requests")
	flag.Parse()

	if *parentPID > 0 {
		go exitWhenParentDisappears(*parentPID)
	}

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

func exitWhenParentDisappears(parentPID int) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if os.Getppid() != parentPID {
			os.Exit(0)
		}
		if err := syscall.Kill(parentPID, 0); err != nil {
			os.Exit(0)
		}
	}
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
		handleSSHTunnel(w, targetHost, targetPort, approvalHeadersForRequest(r))
	case "443":
		handleHTTPSConnect(w, targetHost, targetPort, approvalHeadersForRequest(r))
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

func handleSSHTunnel(w http.ResponseWriter, targetHost, targetPort string, headers []approvalHeader) {
	if !askForApproval(approvalRequest{Type: "SSH", Domain: targetHost, Method: "CONNECT", URL: net.JoinHostPort(targetHost, targetPort), Headers: headers}).Approved {
		http.Error(w, "Blocked by Host Application", http.StatusForbidden)
		return
	}

	upstreamConn, err := dialPublicTCP(targetHost, targetPort)
	if err != nil {
		log.Printf("SSH tunnel dial failed for %s:%s: %v", targetHost, targetPort, err)
		if errors.Is(err, errBlockedDestination) {
			http.Error(w, "Destination not allowed", http.StatusForbidden)
		} else {
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		}
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
	return dialPublicTCPContext(context.Background(), "tcp", net.JoinHostPort(host, port))
}

func dialPublicTCPContext(ctx context.Context, network, address string) (net.Conn, error) {
	return publicDialer.DialContext(ctx, network, address)
}

func rejectBlockedDialDestination(_ context.Context, network, address string, _ syscall.RawConn) error {
	if !strings.HasPrefix(network, "tcp") {
		return nil
	}

	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: invalid resolved address %q", errBlockedDestination, address)
	}
	addr := addrPort.Addr()
	if !isAllowedDestinationAddr(addr) {
		return fmt.Errorf("%w: %s", errBlockedDestination, addr)
	}
	return nil
}

func isAllowedDestinationAddr(addr netip.Addr) bool {
	if !addr.IsValid() || addr.Zone() != "" {
		return false
	}

	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() ||
		addr.IsUnspecified() ||
		addr.IsLoopback() ||
		addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsMulticast() {
		return false
	}
	if addr.Is6() && !publicIPv6GlobalUnicastPrefix.Contains(addr) {
		return false
	}
	return !isBlockedDestinationAddr(addr)
}

func isBlockedDestinationAddr(addr netip.Addr) bool {
	for _, prefix := range blockedDestinationPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func handleHTTPSConnect(w http.ResponseWriter, targetHost, targetPort string, headers []approvalHeader) {
	if !askForApproval(approvalRequest{Type: "CONNECT", Domain: targetHost, Method: "CONNECT", URL: net.JoinHostPort(targetHost, targetPort), Headers: headers}).Approved {
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

		body, warnings := approvalBodyForRequest(innerReq)
		approval := askForApproval(approvalRequest{
			Type:     "REQUEST",
			Domain:   targetHost,
			Method:   innerReq.Method,
			URL:      approvalURL(innerReq, targetHost),
			Headers:  approvalHeadersForRequest(innerReq),
			Body:     body,
			Warnings: warnings,
			Secrets:  secretNames,
		})
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
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
			log.Println("Error executing upstream request:", err)
			if errors.Is(err, errBlockedDestination) {
				tlsConn.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
			} else {
				tlsConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
			}
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

func approvalURL(r *http.Request, fallbackHost string) string {
	host := r.Host
	if host == "" {
		host = fallbackHost
	}
	if r.RequestURI == "" {
		text, _ := approvalDisplayBytes([]byte(host))
		return text
	}
	text, _ := approvalDisplayBytes([]byte(host + r.RequestURI))
	return text
}

func approvalHeadersForRequest(r *http.Request) []approvalHeader {
	if r == nil {
		return nil
	}

	headers := make([]approvalHeader, 0, len(r.Header)+1)
	host := r.Host
	if host == "" {
		host = r.Header.Get("Host")
	}
	if host != "" {
		headers = append(headers, approvalHeaderForDisplay("Host", host))
	}

	displayHeader := make(http.Header, len(r.Header)+1)
	for name, values := range r.Header {
		if strings.EqualFold(name, "Host") || strings.EqualFold(name, "Transfer-Encoding") {
			continue
		}
		displayHeader[name] = values
	}
	if len(r.TransferEncoding) > 0 {
		displayHeader.Set("Transfer-Encoding", strings.Join(r.TransferEncoding, ", "))
	}

	for _, name := range slices.Sorted(maps.Keys(displayHeader)) {
		for _, value := range displayHeader[name] {
			headers = append(headers, approvalHeaderForDisplay(name, value))
		}
	}
	return headers
}

func approvalHeaderForDisplay(name, value string) approvalHeader {
	displayName, _ := approvalDisplayBytes([]byte(name))
	displayValue, _ := approvalDisplayBytes([]byte(value))
	return approvalHeader{Name: displayName, Value: displayValue}
}

func approvalBodyForRequest(r *http.Request) (*approvalBody, []string) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, nil
	}
	warn := func(message string) (*approvalBody, []string) { return nil, []string{message} }
	if hasExpectContinue(r) {
		return warn("Request body uses Expect: 100-continue; body was not shown.")
	}

	body, tooLarge, err := readApprovalBody(r)
	if err != nil {
		return warn("Request body could not be read for approval.")
	}
	if len(body) == 0 {
		return nil, nil
	}
	if tooLarge {
		return warn("Request body is too large to show.")
	}
	if encoding := strings.TrimSpace(r.Header.Get("Content-Encoding")); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return warn("Request body is compressed or encoded; body was not shown.")
	}
	if contentType := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])); strings.HasPrefix(contentType, "multipart/") {
		return warn("Request body is multipart; body was not shown.")
	}
	text, escaped := approvalDisplayBytes(body)
	if escaped {
		return &approvalBody{Text: text}, []string{"Request body contains non-printable or non-ASCII bytes; showing escaped bytes."}
	}
	return &approvalBody{Text: text}, nil
}

func readApprovalBody(r *http.Request) ([]byte, bool, error) {
	originalBody := r.Body
	body, err := io.ReadAll(io.LimitReader(originalBody, maxApprovalBodySize+1))
	tooLarge := int64(len(body)) > maxApprovalBodySize
	if err != nil || tooLarge {
		r.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(body), originalBody), originalBody}
		return body, tooLarge, err
	}
	originalBody.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body, false, nil
}

func approvalDisplayBytes(data []byte) (string, bool) {
	escape := false
	for _, c := range data {
		if c != '\n' && c != '\r' && c != '\t' && (c < 0x20 || c > 0x7e) {
			escape = true
			break
		}
	}
	if !escape {
		return string(data), false
	}

	var b strings.Builder
	for _, c := range data {
		switch c {
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if c >= 0x20 && c <= 0x7e {
				b.WriteByte(c)
			} else {
				fmt.Fprintf(&b, `\x%02X`, c)
			}
		}
	}
	return b.String(), true
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
