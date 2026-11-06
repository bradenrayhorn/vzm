package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func newTestGuestWithRawTCPDial(t *testing.T, dial func(context.Context, string, string) (net.Conn, error)) *testGuest {
	t.Helper()
	return newTestGuest(t, func(n *virtualNetwork) { n.dialRawTCP = dial })
}

func TestPrivateNetworkRawTCP(t *testing.T) {
	for _, tc := range []struct {
		host string
		port uint16
	}{
		{"db.example.test", 5432},
		{"ssh.example.test", 22},
		{"tls.example.test", 8443},
		{"8.8.8.8", 80},
		{"10.20.30.40", 5432},
		{"100.64.1.20", 3306},
	} {
		t.Run(fmt.Sprintf("%s:%d", tc.host, tc.port), func(t *testing.T) {
			target := net.JoinHostPort(tc.host, fmt.Sprint(tc.port))
			var approvals, dials atomic.Int32
			entered, release := make(chan struct{}), make(chan struct{})
			// Release a blocked approval even if an assertion fails.
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			testApprovals(t, func(r approvalRequest) approvalResponse {
				if r.Type != "TCP_CONNECT" || r.Method != "CONNECT" || r.Domain != tc.host || r.URL != target {
					t.Errorf("raw TCP approval = %+v", r)
				}
				if approvals.Add(1) == 1 {
					close(entered)
					<-release
					return approvalResponse{Approved: true}
				}
				return approvalResponse{Approved: false}
			})

			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			serverDone := make(chan error, 1)
			go func() {
				server, err := listener.Accept()
				if err != nil {
					serverDone <- err
					return
				}
				defer server.Close()
				_ = server.SetDeadline(time.Now().Add(5 * time.Second))
				// Server-first protocols must prompt without client payload.
				if _, err := io.WriteString(server, "ready"); err != nil {
					serverDone <- err
					return
				}
				payload, err := io.ReadAll(server)
				if err == nil && string(payload) != "ping\x00\xff" {
					err = fmt.Errorf("upstream payload = %q", payload)
				}
				if err == nil {
					_, err = io.WriteString(server, "pong")
				}
				serverDone <- err
			}()
			guest := newTestGuestWithRawTCPDial(t, func(ctx context.Context, network, address string) (net.Conn, error) {
				dials.Add(1)
				if network != "tcp" || address != target {
					t.Errorf("dial = %s %s, want tcp %s", network, address, target)
				}
				return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
			})

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			ip := tc.host
			if net.ParseIP(ip) == nil {
				ips, err := guest.resolver().LookupNetIP(ctx, "ip4", tc.host)
				if err != nil {
					t.Fatal(err)
				}
				ip = ips[0].String()
			}
			conn, err := guest.dial(ctx, ip, tc.port)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("raw TCP did not prompt")
			}
			if dials.Load() != 0 {
				t.Fatal("upstream dialed before approval")
			}
			close(release)
			greeting := make([]byte, 5)
			if _, err := io.ReadFull(conn, greeting); err != nil || string(greeting) != "ready" {
				t.Fatalf("server-first greeting = %q, %v", greeting, err)
			}
			if _, err := io.WriteString(conn, "ping\x00\xff"); err != nil {
				t.Fatal(err)
			}
			// A guest half-close must reach the server without dropping its reply.
			if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			reply, err := io.ReadAll(conn)
			if err != nil || string(reply) != "pong" {
				t.Fatalf("reply = %q, %v", reply, err)
			}
			if err := <-serverDone; err != nil {
				t.Fatal(err)
			}

			// Same host/port, new connection: prompt again and honor denial.
			denied, err := guest.dial(ctx, ip, tc.port)
			if err != nil {
				t.Fatal(err)
			}
			defer denied.Close()
			_ = denied.SetDeadline(time.Now().Add(time.Second))
			n, err := denied.Read(make([]byte, 1))
			if n != 0 || err == nil {
				t.Fatal("denied connection forwarded data")
			}
			if e, ok := err.(net.Error); ok && e.Timeout() {
				t.Fatal("denied connection was not closed")
			}
			if approvals.Load() != 2 || dials.Load() != 1 {
				t.Fatalf("approvals=%d dials=%d", approvals.Load(), dials.Load())
			}
		})
	}
}

func TestPrivateNetworkRawTCPMissingApprovalFailsClosed(t *testing.T) {
	old := controlUnixPath
	controlUnixPath = ""
	t.Cleanup(func() { controlUnixPath = old })
	guest := newTestGuestWithRawTCPDial(t, func(context.Context, string, string) (net.Conn, error) {
		t.Error("dial without approval")
		return nil, fmt.Errorf("unexpected dial")
	})

	ip, _ := guest.host.dns.address("db.example.test")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := guest.dial(ctx, netip.AddrFrom4(ip).String(), 5432)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	_, err = conn.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("connection without control socket accepted")
	}
	if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("connection without approval was not closed")
	}
}

func TestPrivateNetworkHTTPSNeverFallsBackToRawTCP(t *testing.T) {
	var approvals atomic.Int32
	testApprovals(t, func(r approvalRequest) approvalResponse {
		approvals.Add(1)
		t.Errorf("plaintext on 443 prompted: %+v", r)
		return approvalResponse{Approved: true}
	})
	guest := newTestGuestWithRawTCPDial(t, func(context.Context, string, string) (net.Conn, error) {
		t.Error("HTTPS fell back to raw TCP")
		return nil, fmt.Errorf("unexpected dial")
	})

	ip, _ := guest.host.dns.address("example.test")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := guest.dial(ctx, netip.AddrFrom4(ip).String(), 443)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
	data, err := io.ReadAll(conn)
	if len(data) != 0 || err != nil {
		t.Fatalf("plaintext connection was not cleanly rejected: %q, %v", data, err)
	}
	if approvals.Load() != 0 {
		t.Fatal("raw TCP approval used for HTTPS")
	}
}

func TestPrivateNetworkShutdownCancelsRawTCPApproval(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	testApprovals(t, func(approvalRequest) approvalResponse {
		close(entered)
		<-release
		return approvalResponse{Approved: true}
	})
	guest := newTestGuestWithRawTCPDial(t, func(context.Context, string, string) (net.Conn, error) {
		t.Error("cancelled approval dialed upstream")
		return nil, fmt.Errorf("unexpected dial")
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := guest.dial(ctx, "10.20.30.40", 5432)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("approval not reached")
	}
	done := make(chan struct{})
	go func() { guest.host.Close(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("shutdown waited for approval")
	}
}

func TestPrivateNetworkShutdownCancelsRawTCPDialAndTunnel(t *testing.T) {
	for _, stage := range []string{"dial", "tunnel"} {
		t.Run(stage, func(t *testing.T) {
			testApprovals(t, func(approvalRequest) approvalResponse { return approvalResponse{Approved: true} })
			entered := make(chan struct{})
			var peer net.Conn
			closed := make(chan struct{})
			guest := newTestGuestWithRawTCPDial(t, func(ctx context.Context, _, _ string) (net.Conn, error) {
				if stage == "dial" {
					close(entered)
					<-ctx.Done()
					close(closed)
					return nil, ctx.Err()
				}
				upstream, server := net.Pipe()
				peer = server
				close(entered)
				go func() {
					_, _ = io.Copy(io.Discard, server)
					close(closed)
				}()
				return upstream, nil
			})

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			conn, err := guest.dial(ctx, "10.20.30.40", 5432)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("upstream not reached")
			}
			if peer != nil {
				defer peer.Close()
			}
			done := make(chan struct{})
			go func() { guest.host.Close(); close(done) }()
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("shutdown did not cancel raw TCP")
			}
			select {
			case <-closed:
			case <-ctx.Done():
				t.Fatal("upstream did not close")
			}
		})
	}
}

func TestIsAllowedRawTCPDestinationAddr(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		allowed bool
	}{
		{name: "public ipv4", addr: "8.8.8.8", allowed: true},
		{name: "private 10", addr: "10.20.30.40", allowed: true},
		{name: "private 172", addr: "172.20.30.40", allowed: true},
		{name: "private 192", addr: "192.168.1.20", allowed: true},
		{name: "carrier grade NAT", addr: "100.64.1.20", allowed: true},
		{name: "ipv6 unique local", addr: "fd00::20", allowed: true},
		{name: "mapped private ipv4", addr: "::ffff:10.20.30.40", allowed: true},
		{name: "loopback ipv4", addr: "127.0.0.1", allowed: false},
		{name: "loopback ipv6", addr: "::1", allowed: false},
		{name: "link local ipv4", addr: "169.254.1.20", allowed: false},
		{name: "link local ipv6", addr: "fe80::20", allowed: false},
		{name: "documentation ipv4", addr: "192.0.2.20", allowed: false},
		{name: "documentation ipv6", addr: "2001:db8::20", allowed: false},
		{name: "multicast ipv4", addr: "224.0.0.1", allowed: false},
		{name: "unspecified ipv4", addr: "0.0.0.0", allowed: false},
		{name: "scoped private ipv6", addr: "fd00::20%lo0", allowed: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := netip.MustParseAddr(tt.addr)
			if got := isAllowedRawTCPDestinationAddr(addr); got != tt.allowed {
				t.Fatalf("isAllowedRawTCPDestinationAddr(%s) = %v, want %v", tt.addr, got, tt.allowed)
			}
		})
	}
}

func TestRejectUnsafeRawTCPDialDestination(t *testing.T) {
	tests := []struct {
		name    string
		address string
		blocked bool
	}{
		{name: "public", address: "8.8.8.8:5432"},
		{name: "private", address: "10.20.30.40:5432"},
		{name: "carrier grade NAT", address: "100.64.1.20:5432"},
		{name: "unique local", address: "[fd00::20]:5432"},
		{name: "loopback", address: "127.0.0.1:5432", blocked: true},
		{name: "link local", address: "169.254.1.20:5432", blocked: true},
		{name: "reserved", address: "192.0.2.20:5432", blocked: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := rejectUnsafeRawTCPDialDestination(context.Background(), "tcp", tt.address, nil)
			if tt.blocked {
				if !errors.Is(err, errBlockedDestination) {
					t.Fatalf("rejectUnsafeRawTCPDialDestination() error = %v, want %v", err, errBlockedDestination)
				}
				return
			}
			if err != nil {
				t.Fatalf("rejectUnsafeRawTCPDialDestination() unexpected error: %v", err)
			}
		})
	}
}
