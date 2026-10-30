package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// A second, independently configured stack acts as the guest kernel. Tests run
// real ARP, IP, DNS, TCP, and TLS over the same datagram transport as VZ, without
// requiring root, an actual VM, Internet access, or HTTP proxy configuration.
type testGuest struct {
	host  *virtualNetwork
	stack *stack.Stack
}

func newTestGuest(t *testing.T) *testGuest {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range fds {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 256*1024); err != nil {
			t.Fatal(err)
		}
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1024*1024); err != nil {
			t.Fatal(err)
		}
	}
	host, err := networkFromFD(fds[0])
	if err != nil {
		unix.Close(fds[1])
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fds[1]), "test-guest")
	wire, err := net.FileConn(file)
	file.Close()
	if err != nil {
		host.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	link := channel.New(256, networkMTU+header.EthernetMinimumSize, tcpip.LinkAddress(guestMAC))
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	if err := s.CreateNIC(1, ethernet.New(link)); err != nil {
		t.Fatal(err)
	}
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4(netip.MustParseAddr(guestIP).As4()), PrefixLen: 24},
	}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, Gateway: tcpip.AddrFrom4(netip.MustParseAddr(gatewayIP).As4()), NIC: 1}})
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		if err := host.Run(ctx); err != nil && ctx.Err() == nil {
			t.Error(err)
		}
	}()
	go func() {
		defer wg.Done()
		for {
			pkt := link.ReadContext(ctx)
			if pkt == nil {
				return
			}
			view := pkt.ToView()
			err := writeEthernet(ctx, wire, view.AsSlice())
			view.Release()
			pkt.DecRef()
			if err != nil {
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		frame := make([]byte, 65536)
		for {
			size, err := wire.Read(frame)
			if err != nil {
				return
			}
			if size < header.EthernetMinimumSize {
				continue
			}
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), frame[:size]...))})
			link.InjectInbound(header.Ethernet(frame[:size]).Type(), pkt)
			pkt.DecRef()
		}
	}()
	t.Cleanup(func() {
		cancel()
		wire.Close()
		host.Close()
		s.Close()
		link.Close()
		wg.Wait()
		s.Wait()
		link.Drain()
	})
	return &testGuest{host: host, stack: s}
}

func (g *testGuest) dial(ctx context.Context, ip string, port uint16) (net.Conn, error) {
	return gonet.DialContextTCP(ctx, g.stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(netip.MustParseAddr(ip).As4()), Port: port}, ipv4.ProtocolNumber)
}

func (g *testGuest) udp(ip string, port uint16) (*gonet.UDPConn, error) {
	return gonet.DialUDP(g.stack, nil, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(netip.MustParseAddr(ip).As4()), Port: port}, ipv4.ProtocolNumber)
}

func (g *testGuest) resolver() *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		if strings.HasPrefix(network, "tcp") {
			return g.dial(ctx, gatewayIP, 53)
		}
		return g.udp(gatewayIP, 53)
	}}
}

func testRoots(t *testing.T) *x509.CertPool {
	t.Helper()
	pem, err := certificateAuthorityPEM()
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("invalid CA")
	}
	return roots
}

func (g *testGuest) client(t *testing.T) *http.Client {
	t.Helper()
	transport := &http.Transport{
		Proxy:           nil, // No HTTP_PROXY, CONNECT, or proxy-aware guest code.
		TLSClientConfig: &tls.Config{RootCAs: testRoots(t)},
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			ips, err := g.resolver().LookupNetIP(ctx, "ip4", host)
			if err != nil {
				return nil, err
			}
			var p uint16
			if _, err := fmt.Sscan(port, &p); err != nil {
				return nil, err
			}
			return g.dial(ctx, ips[0].String(), p)
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

func testApprovals(t *testing.T, decide func(approvalRequest) approvalResponse) {
	t.Helper()
	// macOS Unix socket path limit is shorter than many testing.TempDir paths.
	dir, err := os.MkdirTemp("", "vzm-a-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "a")
	listener, err := net.Listen("unix", path)
	if err != nil {
		os.RemoveAll(dir)
		t.Fatal(err)
	}
	old := controlUnixPath
	controlUnixPath = path
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				var request approvalRequest
				if err := json.NewDecoder(conn).Decode(&request); err != nil {
					t.Error(err)
					return
				}
				if request.Type == "NETWORK_ACTIVITY" {
					return
				}
				response := decide(request)
				response.ID = request.ID
				_ = json.NewEncoder(conn).Encode(response)
			}()
		}
	}()
	t.Cleanup(func() { listener.Close(); wg.Wait(); controlUnixPath = old; os.RemoveAll(dir) })
}

type testRoundTripper func(*http.Request) (*http.Response, error)

func (f testRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testOutbound(t *testing.T, transport http.RoundTripper) {
	t.Helper()
	old := outboundClient
	outboundClient = &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(func() { outboundClient.CloseIdleConnections(); outboundClient = old })
}

func TestPrivateNetworkHTTPS(t *testing.T) {
	var connects, requests atomic.Int32
	testApprovals(t, func(r approvalRequest) approvalResponse {
		if r.Domain != "example.test" {
			t.Errorf("approval domain = %s", r.Domain)
		}
		if r.Type == "CONNECT" {
			connects.Add(1)
		} else {
			requests.Add(1)
			if len(r.Secrets) != 1 || r.Secrets[0] != "token" {
				t.Errorf("secrets = %v", r.Secrets)
			}
		}
		return approvalResponse{Approved: true, Substitutions: map[string]string{"token": "host-secret"}}
	})
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "example.test" || r.Header.Get("Authorization") != "Bearer host-secret" {
			t.Errorf("upstream request: host=%s auth=%s", r.Host, r.Header.Get("Authorization"))
		}
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write(append([]byte("echo:"), body...))
	}))
	t.Cleanup(upstream.Close)
	transport := upstream.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.ServerName = "example.com"
	// Only this test transport may reach the loopback upstream. The
	// production transport still rejects all private destinations.
	transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", upstream.Listener.Addr().String())
	}
	testOutbound(t, transport)
	defer transport.CloseIdleConnections()
	guest := newTestGuest(t)
	client := guest.client(t)
	for i := 0; i < 4; i++ {
		payload := "payload"
		if i >= 2 {
			payload = strings.Repeat("large transfer;", 1<<17)
		}
		var reader io.Reader = strings.NewReader(payload)
		if i == 3 {
			reader = io.NopCloser(reader)
		} // unknown-length/chunked upload
		req, _ := http.NewRequest(http.MethodPost, "https://example.test/upload", reader)
		req.Header.Set("Authorization", "Bearer {vzm:token}")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %d (payload=%d): %v; guest sent=%d retrans=%d drops=%d host recv=%d invalid=%d checksum=%d", i, len(payload), err, guest.stack.Stats().TCP.SegmentsSent.Value(), guest.stack.Stats().TCP.Retransmits.Value(), guest.stack.Stats().DroppedPackets.Value(), guest.host.stack.Stats().TCP.ValidSegmentsReceived.Value(), guest.host.stack.Stats().TCP.InvalidSegmentsReceived.Value(), guest.host.stack.Stats().TCP.ChecksumErrors.Value())
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 || string(body) != "echo:"+payload {
			t.Fatalf("status=%d body length=%d want=%d err=%v", resp.StatusCode, len(body), len("echo:"+payload), err)
		}
	}
	if requests.Load() != 4 {
		t.Fatalf("request approvals=%d", requests.Load())
	}
	if connects.Load() != 1 {
		t.Fatalf("CONNECT approvals=%d want 1 (keepalive)", connects.Load())
	}
}

func TestPrivateNetworkDenialAndIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, sni, host, request            string
		denyConnect, denyRequest, untrusted bool
		wantStatus                          int
	}{
		{name: "connect denied", denyConnect: true},
		{name: "request denied", denyRequest: true, wantStatus: 403},
		{name: "untrusted CA", untrusted: true},
		{name: "wrong SNI", sni: "other.test"},
		{name: "wrong Host", host: "other.test"},
		{name: "CONNECT tunnel", request: "CONNECT other.test:443 HTTP/1.1\r\nHost: example.test\r\n\r\n", wantStatus: 403},
		{name: "absolute authority", request: "GET https://other.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n", wantStatus: 403},
		{name: "plaintext absolute URL", request: "GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n", wantStatus: 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testApprovals(t, func(r approvalRequest) approvalResponse {
				return approvalResponse{Approved: !(tc.denyConnect && r.Type == "CONNECT") && !(tc.denyRequest && r.Type == "REQUEST")}
			})
			testOutbound(t, testRoundTripper(func(*http.Request) (*http.Response, error) {
				t.Error("denied request reached upstream")
				return nil, fmt.Errorf("unexpected upstream")
			}))
			guest := newTestGuest(t)
			ip, _ := guest.host.dns.address("example.test")
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := guest.dial(ctx, netip.AddrFrom4(ip).String(), 443)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			name := tc.sni
			if name == "" {
				name = "example.test"
			}
			roots := testRoots(t)
			if tc.untrusted {
				roots = x509.NewCertPool()
			}
			tlsConn := tls.Client(conn, &tls.Config{ServerName: name, RootCAs: roots})
			err = tlsConn.HandshakeContext(ctx)
			if tc.denyConnect || tc.untrusted || tc.sni != "" {
				if err == nil {
					t.Fatal("TLS unexpectedly accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer tlsConn.Close()
			_ = tlsConn.SetDeadline(time.Now().Add(time.Second))
			request := tc.request
			if request == "" {
				host := tc.host
				if host == "" {
					host = "example.test"
				}
				request = "GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
			}
			_, _ = io.WriteString(tlsConn, request)
			resp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
			if tc.wantStatus != 0 {
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				if resp.StatusCode != tc.wantStatus {
					t.Fatalf("status=%d", resp.StatusCode)
				}
			} else if err == nil {
				resp.Body.Close()
				t.Fatal("identity mismatch accepted")
			}
		})
	}
}

func TestPrivateNetworkOnlyMediatedTraffic(t *testing.T) {
	guest := newTestGuest(t)
	ip, _ := guest.host.dns.address("example.test")
	for _, target := range []struct {
		ip   string
		port uint16
	}{
		{netip.AddrFrom4(ip).String(), 80}, {"8.8.8.8", 80},
		{netip.AddrFrom4(ip).String(), 22}, {netip.AddrFrom4(ip).String(), 5432},
		{"127.0.0.1", 443}, {"10.0.0.1", 443}, {"169.254.169.254", 443}, {"198.18.100.100", 443},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		conn, err := guest.dial(ctx, target.ip, target.port)
		cancel()
		if err == nil {
			conn.Close()
			t.Errorf("unmediated connection accepted: %+v", target)
		}
	}
}

func TestPrivateNetworkDNSOverUDPAndTCP(t *testing.T) {
	guest := newTestGuest(t)
	for _, network := range []string{"udp", "tcp"} {
		resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			if network == "tcp" {
				return guest.dial(ctx, gatewayIP, 53)
			}
			return guest.udp(gatewayIP, 53)
		}}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		ips, err := resolver.LookupNetIP(ctx, "ip4", "Example.Test")
		cancel()
		if err != nil || len(ips) != 1 {
			t.Fatalf("%s DNS: %v %v", network, ips, err)
		}
		if host, ok := guest.host.dns.hostname(ips[0].String()); !ok || host != "example.test" {
			t.Fatalf("DNS mapping: %s %v", host, ok)
		}
	}
}

func TestSyntheticDNSBoundedAndStable(t *testing.T) {
	dns := newSyntheticDNS()
	first, _ := dns.address("example.test")
	for i := 1; i < maxSyntheticHosts; i++ {
		if _, ok := dns.address(fmt.Sprintf("h%d.test", i)); !ok {
			t.Fatal("capacity reached too soon")
		}
	}
	if _, ok := dns.address("overflow.test"); ok {
		t.Fatal("unbounded DNS mappings")
	}
	if got, ok := dns.address("example.test"); !ok || got != first {
		t.Fatal("mapping recycled")
	}
	for _, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA, dnsmessage.TypeTXT} {
		query := dnsmessage.Message{Header: dnsmessage.Header{ID: 42, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("example.test."), Type: typ, Class: dnsmessage.ClassINET}}}
		packet, _ := query.Pack()
		var reply dnsmessage.Message
		if err := reply.Unpack(dns.answer(packet)); err != nil {
			t.Fatal(err)
		}
		if reply.ID != 42 || !reply.Response {
			t.Fatal("invalid DNS reply")
		}
		if typ != dnsmessage.TypeA && len(reply.Answers) != 0 {
			t.Fatalf("unsupported records exposed: %v", reply)
		}
	}
}

func FuzzSyntheticDNS(f *testing.F) {
	query := dnsmessage.Message{Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	packet, _ := query.Pack()
	f.Add(packet)
	f.Add([]byte{0, 1, 2})
	f.Fuzz(func(t *testing.T, packet []byte) {
		if reply := newSyntheticDNS().answer(packet); reply != nil {
			var msg dnsmessage.Message
			if err := msg.Unpack(reply); err != nil {
				t.Fatal(err)
			}
		}
	})
}
