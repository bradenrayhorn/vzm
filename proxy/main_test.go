package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
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

func TestApprovalURLIncludesPathAndQuery(t *testing.T) {
	r := &http.Request{Host: "cache.example", RequestURI: "/pkg/a%2Fb?v=1&redirect=https%3A%2F%2Fx"}
	want := "cache.example/pkg/a%2Fb?v=1&redirect=https%3A%2F%2Fx"
	if got := approvalURL(r, "fallback.example"); got != want {
		t.Fatalf("approvalURL() = %q, want %q", got, want)
	}
}

func TestApprovalURLEscapesInvisibleUnicode(t *testing.T) {
	r := &http.Request{Host: "cache.example", RequestURI: "/x?q=\ue000\U000f0000"}
	want := `cache.example/x?q=\xEE\x80\x80\xF3\xB0\x80\x80`
	if got := approvalURL(r, "fallback.example"); got != want {
		t.Fatalf("approvalURL() = %q, want %q", got, want)
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

func TestApprovalBodyForAnyMethod(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			r := approvalBodyRequest(method, []byte("hello\nworld"))
			body, warnings := approvalBodyForRequest(r)
			if len(warnings) != 0 || body == nil || body.Text != "hello\nworld" {
				t.Fatalf("approvalBodyForRequest() body=%#v warnings=%v", body, warnings)
			}
			if got := readRequestBody(t, r); got != "hello\nworld" {
				t.Fatalf("body after preview = %q", got)
			}
		})
	}
}

func TestApprovalBodyDoesNotNeedContentLength(t *testing.T) {
	r := approvalBodyRequest(http.MethodPost, []byte("hello"))
	r.ContentLength = -1
	body, warnings := approvalBodyForRequest(r)
	if len(warnings) != 0 || body == nil || body.Text != "hello" {
		t.Fatalf("approvalBodyForRequest() body=%#v warnings=%v", body, warnings)
	}
}

func TestApprovalBodyWarningsRestoreBody(t *testing.T) {
	r := approvalBodyRequest(http.MethodPost, bytes.Repeat([]byte("a"), int(maxApprovalBodySize)+1))
	body, warnings := approvalBodyForRequest(r)
	if body != nil || len(warnings) == 0 {
		t.Fatalf("approvalBodyForRequest() body=%#v warnings=%v", body, warnings)
	}
	if got := readRequestBody(t, r); len(got) != int(maxApprovalBodySize)+1 {
		t.Fatalf("body length after warning = %d", len(got))
	}
}

func TestApprovalBodyEscapesInvisibleUnicode(t *testing.T) {
	r := approvalBodyRequest(http.MethodPost, []byte("ok🙂️\ue000\U000f0000"))
	body, warnings := approvalBodyForRequest(r)
	want := `ok\xF0\x9F\x99\x82\xEF\xB8\x8F\xEE\x80\x80\xF3\xB0\x80\x80`
	if body == nil || len(warnings) == 0 || body.Text != want {
		t.Fatalf("approvalBodyForRequest() body=%#v warnings=%v", body, warnings)
	}
}

func TestApprovalBodyEscapesInvalidUTF8(t *testing.T) {
	r := approvalBodyRequest(http.MethodPost, []byte{0xff, 'a'})
	body, warnings := approvalBodyForRequest(r)
	if body == nil || len(warnings) == 0 || body.Text != `\xFFa` {
		t.Fatalf("approvalBodyForRequest() body=%#v warnings=%v", body, warnings)
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
