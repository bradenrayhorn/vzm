package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
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

type approvalRequest struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Domain string `json:"domain"`
	Method string `json:"method"`
	Path   string `json:"path"`
}

type approvalResponse struct {
	ID       string `json:"id"`
	Approved bool   `json:"approved"`
}

func askForApproval(requestType, domain, method, path string) bool {
	if controlUnixPath == "" {
		log.Printf("auto-approving %s %s %s %s", requestType, method, domain, path)
		return true
	}

	conn, err := net.Dial("unix", controlUnixPath)
	if err != nil {
		log.Printf("approval denied: connect control socket: %v", err)
		return false
	}
	defer conn.Close()

	request := approvalRequest{
		ID:     nextApprovalRequestID(),
		Type:   requestType,
		Domain: domain,
		Method: method,
		Path:   path,
	}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		log.Printf("approval denied: write request: %v", err)
		return false
	}

	var response approvalResponse
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		log.Printf("approval denied: read response: %v", err)
		return false
	}
	if response.ID != request.ID {
		log.Printf("approval denied: mismatched response id %q for request %q", response.ID, request.ID)
		return false
	}

	return response.Approved
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
	// 1. We ONLY intercept HTTPS CONNECT requests.
	if r.Method != http.MethodConnect {
		http.Error(w, "Only HTTPS CONNECT allowed", http.StatusMethodNotAllowed)
		return
	}

	targetDomain := r.Host // e.g., "api.github.com:443"
	cleanDomain := strings.Split(targetDomain, ":")[0]

	// 2. CONNECT Approval Gate
	if !askForApproval("CONNECT", cleanDomain, r.Method, "") {
		http.Error(w, "Blocked by Host Application", http.StatusForbidden)
		return
	}

	// 3. Hijack the connection from the standard HTTP server
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

	// 4. Tell the VM the tunnel is established
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// 5. Initiate TLS MITM. Force HTTP/1.1 via NextProtos
	cert, err := generateFakeCertForDomain(cleanDomain)
	if err != nil {
		log.Println("Error generating certificate:", err)
		return
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"}, // STRATEGY: Disable HTTP/2
	}
	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return // Handshake failed (VM rejected cert or dropped)
	}
	defer tlsConn.Close()

	// 6. Read inner requests in a loop (Keep-Alive)
	bufReader := bufio.NewReader(tlsConn)
	for {
		innerReq, err := http.ReadRequest(bufReader)
		if err != nil {
			if err != io.EOF {
				log.Println("Error reading inner request:", err)
			}
			break
		}

		// 7. Domain Fronting Check
		// Ensure the decrypted inner Host header matches the CONNECT tunnel
		if innerReq.Host != cleanDomain && innerReq.Host != targetDomain {
			log.Printf("Domain fronting detected! SNI: %s, Host: %s", cleanDomain, innerReq.Host)
			break // Kill connection
		}

		// 8. Inner Request Approval Gate
		if !askForApproval("REQUEST", cleanDomain, innerReq.Method, approvalPath(innerReq)) {
			// Write a synthetic 403 back to the VM
			tlsConn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
			break
		}

		// 9. Execute the approved request to the real internet
		innerReq.URL.Scheme = "https"
		innerReq.URL.Host = innerReq.Host
		innerReq.RequestURI = "" // Must be cleared for client requests
		stripHopByHopHeaders(innerReq.Header)
		innerReq.Close = false

		resp, err := outboundClient.Do(innerReq)
		if err != nil {
			log.Println("Error executing upstream request:", err)
			tlsConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
			break
		}

		// 10. Stream the response back to the VM
		// Write response headers
		stripHopByHopHeaders(resp.Header)
		if err := resp.Write(tlsConn); err != nil {
			log.Println("Error writing response:", err)
		}
		resp.Body.Close()
	}
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
