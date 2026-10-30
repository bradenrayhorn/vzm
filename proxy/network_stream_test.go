package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPrivateNetworkStreamingAndRedirects(t *testing.T) {
	var connects, requests atomic.Int32
	testApprovals(t, func(r approvalRequest) approvalResponse {
		if r.Type == "CONNECT" {
			connects.Add(1)
		} else {
			requests.Add(1)
		}
		return approvalResponse{Approved: true}
	})
	body, producer := io.Pipe()
	defer body.Close()
	defer producer.Close()
	release := make(chan struct{})
	defer close(release)
	const event = "event: message\ndata: streaming works\n\n"
	testOutbound(t, testRoundTripper(func(r *http.Request) (*http.Response, error) {
		resp := &http.Response{StatusCode: 200, ProtoMajor: 1, ProtoMinor: 1, Header: make(http.Header), Request: r}
		if r.URL.Path == "/redirect" {
			resp.StatusCode = 302
			resp.Header.Set("Location", "https://other.test/event")
			resp.Body = http.NoBody
		} else {
			if r.Host != "other.test" {
				t.Errorf("redirect authority=%s", r.Host)
			}
			resp.Header.Set("Content-Type", "text/event-stream")
			resp.Body = body
			resp.ContentLength = -1
			resp.Uncompressed = true
			go func() { _, _ = io.WriteString(producer, event); <-release; producer.Close() }()
		}
		return resp, nil
	}))
	guest := newTestGuest(t)
	resp, err := guest.client(t).Get("https://example.test/redirect")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got := make([]byte, len(event))
	if _, err := io.ReadFull(resp.Body, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != event {
		t.Fatalf("event=%q", got)
	}
	if connects.Load() != 2 || requests.Load() != 2 {
		t.Fatalf("redirect skipped policy: connects=%d requests=%d", connects.Load(), requests.Load())
	}
}

func TestPrivateNetworkShutdownClosesIdleConnections(t *testing.T) {
	testApprovals(t, func(approvalRequest) approvalResponse { return approvalResponse{Approved: true} })
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
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	dns, err := guest.dial(ctx, gatewayIP, 53)
	if err != nil {
		t.Fatal(err)
	}
	defer dns.Close()
	done := make(chan struct{})
	go func() { guest.host.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown stuck on idle guest connections")
	}
}

func TestHTTPStreamWebSocketUpgrade(t *testing.T) {
	var approvals atomic.Int32
	testApprovals(t, func(r approvalRequest) approvalResponse {
		if r.Type != "WEBSOCKET" {
			t.Errorf("approval type=%s", r.Type)
		}
		approvals.Add(1)
		return approvalResponse{Approved: true}
	})
	// The production dialer remains restricted. This test alone can connect to
	// the loopback echo server, and restores it after both tunnel halves exit.
	old := publicDialer
	publicDialer = &net.Dialer{Timeout: time.Second}
	defer func() { publicDialer = old }()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		_ = rw.Flush()
		_, _ = io.Copy(conn, rw)
	}))
	defer upstream.Close()
	host, port, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	proxy, client := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() { defer close(done); defer proxy.Close(); serveHTTPStream(proxy, host, port, "http") }()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = fmt.Fprintf(client, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", upstream.Listener.Addr())
	reader := bufio.NewReader(client)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 101 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	_, _ = io.WriteString(client, "opaque websocket bytes")
	got := make([]byte, len("opaque websocket bytes"))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "opaque websocket bytes" || approvals.Load() != 1 {
		t.Fatal("upgrade not mediated/relayed")
	}
	client.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("WebSocket tunnel did not stop")
	}
}

func TestHTTPHeaderSizeLimit(t *testing.T) {
	proxy, client := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() { defer close(done); defer proxy.Close(); serveHTTPStream(proxy, "example.test", "443", "https") }()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	_, _ = io.WriteString(client, "GET / HTTP/1.1\r\nHost: example.test\r\nX-Large: "+strings.Repeat("x", 128*1024)+"\r\n\r\n")
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("oversized header not rejected")
	}
}
