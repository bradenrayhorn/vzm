package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestSecretLocationsUseSubstitutionInspectionNotDisplay(t *testing.T) {
	const placeholder = "{vzm:datadog-pat}"
	authReference := approvalSecret{Name: "datadog-pat", Location: secretInAuthorizationHeader}
	for _, tt := range []struct {
		name      string
		target    string
		body      string
		header    http.Header
		unread    bool
		wantExtra []approvalSecret
	}{
		{name: "authorization only"},
		{name: "path", target: "/api/" + placeholder, wantExtra: []approvalSecret{{"datadog-pat", secretInURLPath}}},
		{name: "encoded path", target: "/api/%7Bvzm:datadog-pat%7D", wantExtra: []approvalSecret{{"datadog-pat", secretInURLPath}}},
		{name: "query value", target: "/api?token=%7Bvzm%3Adatadog-pat%7D", wantExtra: []approvalSecret{{"datadog-pat", secretInURLQuery}}},
		{name: "query key", target: "/api?%7Bvzm%3Adatadog-pat%7D=value", wantExtra: []approvalSecret{{"datadog-pat", secretInURLQuery}}},
		{name: "other header", header: http.Header{"X-Token": {placeholder}}, wantExtra: []approvalSecret{{"datadog-pat", secretInHeader}}},
		{name: "body", body: placeholder, wantExtra: []approvalSecret{{"datadog-pat", secretInBody}}},
		{name: "above display limit", body: strings.Repeat("x", int(maxApprovalBodySize)) + placeholder, wantExtra: []approvalSecret{{"datadog-pat", secretInBody}}},
		{name: "encoded body", body: placeholder, header: http.Header{"Content-Encoding": {"gzip"}}, wantExtra: []approvalSecret{{"datadog-pat", secretInBody}}},
		{name: "multipart body", body: placeholder, header: http.Header{"Content-Type": {"multipart/form-data; boundary=x"}}, wantExtra: []approvalSecret{{"datadog-pat", secretInBody}}},
		{name: "additional secret", body: "{vzm:other}", wantExtra: []approvalSecret{{"other", secretInBody}}},
		{name: "uninspected body is never substituted", body: placeholder, unread: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			target := tt.target
			if target == "" {
				target = "/api/v2/logs/events/search"
			}
			r := httptest.NewRequest(http.MethodPost, "https://api.datadoghq.com"+target, strings.NewReader(tt.body))
			if tt.header != nil {
				r.Header = tt.header.Clone()
			}
			r.Header.Set("Authorization", "Bearer "+placeholder)
			if tt.unread {
				r.ContentLength = -1
			}
			inspection := inspectRequestBodyForTest(t, r)
			want := append([]approvalSecret{authReference}, tt.wantExtra...)
			if got := findRequestSecrets(r, inspection); !slices.Equal(got, want) {
				t.Fatalf("secret references = %v, want %v", got, want)
			}
			applySecretSubstitutions(r, inspection, map[string]string{"datadog-pat": "actual-pat"})
			if tt.unread && readRequestBody(t, r) != placeholder {
				t.Fatal("uninspected body was unexpectedly substituted")
			}
			r.Body.Close()
		})
	}
}

func TestSecretLocationsPreserveDistinctLocationsAndDeduplicateWithinEach(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost,
		"https://example.com/%7Bvzm:token%7D/{vzm:token}?x=%7Bvzm:token%7D&y=%7Bvzm:token%7D",
		strings.NewReader("{vzm:token}{vzm:token}"))
	r.Header["aUtHoRiZaTiOn"] = []string{"Bearer {vzm:token}"}
	r.Header.Set("X-One", "{vzm:token}")
	r.Header.Set("X-Two", "{vzm:token}")
	want := []approvalSecret{
		{"token", secretInAuthorizationHeader},
		{"token", secretInBody},
		{"token", secretInHeader},
		{"token", secretInURLPath},
		{"token", secretInURLQuery},
	}
	inspection := inspectRequestBodyForTest(t, r)
	if got := findRequestSecrets(r, inspection); !slices.Equal(got, want) {
		t.Fatalf("secret references = %v, want %v", got, want)
	}
	r.Body.Close()
}

func TestSecretLocationObjectsReachApproval(t *testing.T) {
	captured := make(chan approvalRequest, 1)
	testApprovals(t, func(r approvalRequest) approvalResponse {
		captured <- r
		return approvalResponse{Approved: false}
	})
	r := httptest.NewRequest(http.MethodPost, "https://api.datadoghq.com/api/v2/logs/events/search",
		strings.NewReader("{vzm:datadog-pat}"))
	r.RequestURI = r.URL.RequestURI()
	r.Header.Set("Authorization", "Bearer {vzm:datadog-pat}")
	proxy, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveHTTPRequest(proxy, bufio.NewReader(proxy), r, "api.datadoghq.com", "443", "https")
	}()
	defer func() { client.Close(); proxy.Close(); <-done }()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	response, err := http.ReadResponse(bufio.NewReader(client), r)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	select {
	case got := <-captured:
		want := []approvalSecret{
			{"datadog-pat", secretInAuthorizationHeader},
			{"datadog-pat", secretInBody},
		}
		if !slices.Equal(got.Secrets, want) {
			t.Fatalf("secret references = %v, want %v", got.Secrets, want)
		}
	default:
		t.Fatal("no approval request received")
	}
}

func TestSecretsOverPlainHTTPStillRejectBeforeApproval(t *testing.T) {
	testApprovals(t, func(approvalRequest) approvalResponse {
		t.Error("plain HTTP secrets reached approval")
		return approvalResponse{Approved: true}
	})
	r := httptest.NewRequest(http.MethodGet, "http://api.datadoghq.com/api/v2/users", nil)
	r.Header.Set("Authorization", "Bearer {vzm:datadog-pat}")
	proxy, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveHTTPRequest(proxy, bufio.NewReader(proxy), r, "api.datadoghq.com", "80", "http")
	}()
	defer func() { client.Close(); proxy.Close(); <-done }()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	response, err := http.ReadResponse(bufio.NewReader(client), r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.StatusCode)
	}
}
