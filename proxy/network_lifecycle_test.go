package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPrivateNetworkShutdownCancelsPendingApproval(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	testApprovals(t, func(approvalRequest) approvalResponse {
		close(entered)
		<-release
		return approvalResponse{Approved: true}
	})
	guest := newTestGuest(t)
	ip, _ := guest.host.dns.address("example.test")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := guest.dial(ctx, netip.AddrFrom4(ip).String(), 443)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tlsConn := tls.Client(conn, &tls.Config{ServerName: "example.test", RootCAs: testRoots(t)})
	handshake := make(chan error, 1)
	go func() { handshake <- tlsConn.HandshakeContext(ctx) }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("approval not reached")
	}
	done := make(chan struct{})
	go func() { guest.host.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown waited for approval UI")
	}
	if err := <-handshake; err == nil {
		t.Fatal("cancelled approval accepted")
	}
}

func TestPrivateNetworkConnectionLimit(t *testing.T) {
	guest := newTestGuest(t)
	for i := 0; i < maxNetworkConnections; i++ {
		guest.host.slots <- struct{}{}
	}
	defer func() {
		for i := 0; i < maxNetworkConnections; i++ {
			<-guest.host.slots
		}
	}()
	ip, _ := guest.host.dns.address("example.test")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if conn, err := guest.dial(ctx, netip.AddrFrom4(ip).String(), 443); err == nil {
		conn.Close()
		t.Fatal("connection cap ignored")
	}
}

type congestedEthernet struct {
	failures int
	calls    int
	frame    []byte
}

func (w *congestedEthernet) Write(frame []byte) (int, error) {
	w.calls++
	if w.calls <= w.failures {
		return 0, unix.ENOBUFS
	}
	w.frame = append([]byte(nil), frame...)
	return len(frame), nil
}

func TestEthernetRetriesDarwinBackpressure(t *testing.T) {
	writer := &congestedEthernet{failures: 3}
	if err := writeEthernet(context.Background(), writer, []byte("one complete frame")); err != nil {
		t.Fatal(err)
	}
	if writer.calls != 4 || string(writer.frame) != "one complete frame" {
		t.Fatal("frame lost under backpressure")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := writeEthernet(ctx, &congestedEthernet{failures: 100}, []byte("cancel")); err != context.Canceled {
		t.Fatalf("cancelled backpressure: %v", err)
	}
}

func TestNetworkFDRejectsStreamSocket(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[1])
	if network, err := networkFromFD(fds[0]); err == nil {
		network.Close()
		t.Fatal("stream socket accepted for Ethernet")
	}
}

func TestPrivateNetworkIPLiteralWithoutSNI(t *testing.T) {
	testApprovals(t, func(r approvalRequest) approvalResponse {
		if r.Domain != "8.8.8.8" {
			t.Errorf("IP literal authority=%s", r.Domain)
		}
		return approvalResponse{Approved: true}
	})
	testOutbound(t, testRoundTripper(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, ProtoMajor: 1, ProtoMinor: 1, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("literal")), ContentLength: 7, Request: r}, nil
	}))
	guest := newTestGuest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := guest.dial(ctx, "8.8.8.8", 443)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// crypto/tls deliberately omits SNI for IP literals, while still checking
	// the certificate IP SAN against ServerName and verifying the CA.
	tlsConn := tls.Client(conn, &tls.Config{ServerName: "8.8.8.8", RootCAs: testRoots(t)})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	defer tlsConn.Close()
	_ = tlsConn.SetDeadline(time.Now().Add(time.Second))
	_, _ = fmt.Fprint(tlsConn, "GET / HTTP/1.1\r\nHost: 8.8.8.8\r\n\r\n")
	buf := make([]byte, 1024)
	if n, err := tlsConn.Read(buf); err != nil || !strings.Contains(string(buf[:n]), "200 OK") {
		t.Fatalf("literal response=%q err=%v", buf[:n], err)
	}
}
