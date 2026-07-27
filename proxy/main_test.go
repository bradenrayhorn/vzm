package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestIsAllowedDestinationAddr(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		allowed bool
	}{
		{name: "public ipv4", addr: "8.8.8.8", allowed: true},
		{name: "public ipv6", addr: "2606:4700:4700::1111", allowed: true},
		{name: "public ipv4 mapped ipv6", addr: "::ffff:8.8.8.8", allowed: true},
		{name: "public scoped ipv6", addr: "2606:4700:4700::1111%lo0", allowed: false},
		{name: "private ipv4 mapped ipv6", addr: "::ffff:127.0.0.1", allowed: false},
		{name: "deprecated ipv6 site local", addr: "fec0::1", allowed: false},
		{name: "ipv6 documentation", addr: "3fff::1", allowed: false},
		{name: "reserved ipv6 outside global unicast allocation", addr: "4000::1", allowed: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := netip.MustParseAddr(tt.addr)
			if got := isAllowedDestinationAddr(addr); got != tt.allowed {
				t.Fatalf("isAllowedDestinationAddr(%s) = %v, want %v", tt.addr, got, tt.allowed)
			}
		})
	}
}

func TestBlockedDestinationPrefixesAreRejected(t *testing.T) {
	for _, prefix := range blockedDestinationPrefixes {
		t.Run(prefix.String(), func(t *testing.T) {
			addr := prefix.Addr()
			if got := isAllowedDestinationAddr(addr); got {
				t.Fatalf("isAllowedDestinationAddr(%s) = true, want false", addr)
			}
		})
	}
}

func TestRejectBlockedDialDestination(t *testing.T) {
	tests := []struct {
		name    string
		network string
		address string
		blocked bool
	}{
		{name: "public ipv4", network: "tcp4", address: "8.8.8.8:443"},
		{name: "public ipv6", network: "tcp6", address: "[2606:4700:4700::1111]:443"},
		{name: "private", network: "tcp4", address: "127.0.0.1:443", blocked: true},
		{name: "scoped", network: "tcp6", address: "[2606:4700:4700::1111%lo0]:443", blocked: true},
		{name: "mapped scoped", network: "tcp6", address: "[::ffff:8.8.8.8%lo0]:443", blocked: true},
		{name: "non tcp", network: "unix", address: "/tmp/socket"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := rejectBlockedDialDestination(context.Background(), tt.network, tt.address, nil)
			if tt.blocked {
				if !errors.Is(err, errBlockedDestination) {
					t.Fatalf("rejectBlockedDialDestination() error = %v, want %v", err, errBlockedDestination)
				}
				return
			}
			if err != nil {
				t.Fatalf("rejectBlockedDialDestination() unexpected error: %v", err)
			}
		})
	}
}

func TestConnectTarget(t *testing.T) {
	tests := []struct {
		target   string
		wantHost string
		wantPort string
		wantErr  bool
	}{
		{target: "DB.Example.COM.:5432", wantHost: "db.example.com", wantPort: "5432"},
		{target: "[2606:4700:4700::1111]:3306", wantHost: "2606:4700:4700::1111", wantPort: "3306"},
		{target: "db.example.com:0", wantErr: true},
		{target: "db.example.com:65536", wantErr: true},
		{target: "db.example.com:postgres", wantErr: true},
		{target: "db.example.com", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			host, port, err := connectTarget(&http.Request{Host: tt.target})
			if tt.wantErr {
				if err == nil {
					t.Fatalf("connectTarget() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if host != tt.wantHost || port != tt.wantPort {
				t.Fatalf("connectTarget() = %q, %q; want %q, %q", host, port, tt.wantHost, tt.wantPort)
			}
		})
	}
}

func TestRawTCPProxyRejectsNonConnect(t *testing.T) {
	recorder := httptest.NewRecorder()
	handleRawTCPProxy(recorder, httptest.NewRequest(http.MethodGet, "http://db.example.com:5432", nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusMethodNotAllowed)
	}
}

func TestRawTCPProxyRequiresApproval(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodConnect, "http://db.example.com:5432", nil)
	request.Host = "db.example.com:5432"
	handleRawTCPProxy(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
}

func TestRawTCPProxyTunnelsBytes(t *testing.T) {
	oldApproval := rawTCPAskForApproval
	oldDial := rawTCPDialContext
	defer func() {
		rawTCPAskForApproval = oldApproval
		rawTCPDialContext = oldDial
	}()

	upstreamProxy, upstreamServer := net.Pipe()
	rawTCPAskForApproval = func(request approvalRequest) approvalResponse {
		if request.Type != "TCP_CONNECT" || request.Domain != "db.example.com" || request.URL != "db.example.com:5432" {
			t.Errorf("unexpected approval request: %#v", request)
		}
		return approvalResponse{Approved: true}
	}
	rawTCPDialContext = func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "db.example.com:5432" {
			t.Errorf("unexpected dial: %s %s", network, address)
		}
		return upstreamProxy, nil
	}

	server := httptest.NewServer(http.HandlerFunc(handleRawTCPProxy))
	defer server.Close()
	client, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	upstreamDone := make(chan error, 1)
	go func() {
		defer upstreamServer.Close()
		payload := make([]byte, 4)
		if _, err := io.ReadFull(upstreamServer, payload); err != nil {
			upstreamDone <- err
			return
		}
		if string(payload) != "ping" {
			upstreamDone <- fmt.Errorf("upstream received %q", payload)
			return
		}
		_, err := upstreamServer.Write([]byte("pong"))
		upstreamDone <- err
	}()

	request := &http.Request{Method: http.MethodConnect}
	if _, err := fmt.Fprint(client, "CONNECT db.example.com:5432 HTTP/1.1\r\nHost: db.example.com:5432\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(client)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 4)
	if _, err := io.ReadFull(reader, payload); err != nil {
		t.Fatal(err)
	}
	if string(payload) != "pong" {
		t.Fatalf("client received %q, want pong", payload)
	}
	if err := <-upstreamDone; err != nil {
		t.Fatal(err)
	}
}

func TestApprovalHeadersForRequest(t *testing.T) {
	r := &http.Request{
		Host: "cache.example",
		Header: http.Header{
			"X-Zed":     {"z"},
			"Accept":    {"application/json", "text/plain"},
			"X-Unicode": {"ok🙂"},
		},
		TransferEncoding: []string{"chunked"},
	}

	got := approvalHeadersForRequest(r)
	want := []approvalHeader{
		{Name: "Host", Value: "cache.example"},
		{Name: "Accept", Value: "application/json"},
		{Name: "Accept", Value: "text/plain"},
		{Name: "Transfer-Encoding", Value: "chunked"},
		{Name: "X-Unicode", Value: `ok\xF0\x9F\x99\x82`},
		{Name: "X-Zed", Value: "z"},
	}

	if len(got) != len(want) {
		t.Fatalf("approvalHeadersForRequest() length = %d, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("approvalHeadersForRequest()[%d] = %#v, want %#v", i, got[i], want[i])
		}
	}
}

func TestBasicAuthSecretsAreScannedAndSubstituted(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("user:{vzm:basic-secret}"))
	r := &http.Request{
		Header: http.Header{
			"Authorization": {"Basic " + encoded},
		},
	}

	secrets, err := findRequestSecrets(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 1 || secrets[0] != "basic-secret" {
		t.Fatalf("findRequestSecrets() = %#v, want [basic-secret]", secrets)
	}

	if err := applySecretSubstitutions(r, map[string]string{"basic-secret": "s3cr3t"}); err != nil {
		t.Fatal(err)
	}
	got := r.Header.Get("Authorization")
	if !strings.HasPrefix(got, "Basic ") {
		t.Fatalf("Authorization header = %q, want Basic auth", got)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(got, "Basic "))
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != "user:s3cr3t" {
		t.Fatalf("decoded Authorization = %q, want %q", decoded, "user:s3cr3t")
	}
}

func TestParseGitProxyPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		wantHost string
		wantRepo string
		wantErr  bool
	}{
		{name: "github", path: "/github.com:owner/repo.git", wantHost: "github.com", wantRepo: "owner/repo.git"},
		{name: "gitlab nested", path: "/gitlab.com:group/subgroup/project.git", wantHost: "gitlab.com", wantRepo: "group/subgroup/project.git"},
		{name: "azure", path: "/ssh.dev.azure.com:v3/org/project/repo", wantHost: "ssh.dev.azure.com", wantRepo: "v3/org/project/repo"},
		{name: "normalizes host", path: "/GitHub.COM.:owner/repo.git", wantHost: "github.com", wantRepo: "owner/repo.git"},
		{name: "rejects ssh url path", path: "/github.com/owner/repo.git", wantErr: true},
		{name: "rejects single segment repo", path: "/github.com:repo.git", wantErr: true},
		{name: "rejects newline", path: "/github.com:owner/repo.git\n", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, repo, err := parseGitProxyPath(tt.path)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseGitProxyPath() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseGitProxyPath() unexpected error: %v", err)
			}
			if host != tt.wantHost || repo != tt.wantRepo {
				t.Fatalf("parseGitProxyPath() = %q, %q; want %q, %q", host, repo, tt.wantHost, tt.wantRepo)
			}
		})
	}
}

func TestApprovalBodyForAnyMethod(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			r := approvalBodyRequest(method, []byte("hello\nworld"))
			body := approvalBodyForRequest(r)
			if body == nil || body.Text != "hello\nworld" || body.Warning != "" {
				t.Fatalf("approvalBodyForRequest() body=%#v", body)
			}
			if got := readRequestBody(t, r); got != "hello\nworld" {
				t.Fatalf("body after preview = %q", got)
			}
		})
	}
}

func TestApprovalBodyDoesNotReadUnknownLengthBody(t *testing.T) {
	r := approvalBodyRequest(http.MethodPost, []byte("hello"))
	r.ContentLength = -1
	body := approvalBodyForRequest(r)
	if body == nil || body.Text != "" || body.Warning == "" {
		t.Fatalf("approvalBodyForRequest() body=%#v", body)
	}
	if got := readRequestBody(t, r); got != "hello" {
		t.Fatalf("body after warning = %q", got)
	}
}

func TestApprovalBodyWarningsRestoreBody(t *testing.T) {
	r := approvalBodyRequest(http.MethodPost, bytes.Repeat([]byte("a"), int(maxApprovalBodySize)+1))
	body := approvalBodyForRequest(r)
	if body == nil || body.Warning == "" || body.Text != "" {
		t.Fatalf("approvalBodyForRequest() body=%#v", body)
	}
	if got := readRequestBody(t, r); len(got) != int(maxApprovalBodySize)+1 {
		t.Fatalf("body length after warning = %d", len(got))
	}
}

func TestApprovalBodyEscapesInvisibleUnicode(t *testing.T) {
	r := approvalBodyRequest(http.MethodPost, []byte("ok🙂️\ue000\U000f0000"))
	body := approvalBodyForRequest(r)
	want := `ok\xF0\x9F\x99\x82\xEF\xB8\x8F\xEE\x80\x80\xF3\xB0\x80\x80`
	if body == nil || body.Warning == "" || body.Text != want {
		t.Fatalf("approvalBodyForRequest() body=%#v", body)
	}
}

func TestApprovalBodyEscapesInvalidUTF8(t *testing.T) {
	r := approvalBodyRequest(http.MethodPost, []byte{0xff, 'a'})
	body := approvalBodyForRequest(r)
	if body == nil || body.Warning == "" || body.Text != `\xFFa` {
		t.Fatalf("approvalBodyForRequest() body=%#v", body)
	}
}

func approvalBodyRequest(method string, body []byte) *http.Request {
	return &http.Request{Method: method, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body))}
}

func readRequestBody(t *testing.T, r *http.Request) string {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
