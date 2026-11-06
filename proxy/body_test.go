package main

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

type trackedRequestBody struct {
	io.Reader
	readBytes int
	closes    int
}

func (b *trackedRequestBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.readBytes += n
	return n, err
}

func (b *trackedRequestBody) Close() error {
	b.closes++
	return nil
}

func inspectRequestBodyForTest(t *testing.T, r *http.Request) requestBodyInspection {
	t.Helper()
	inspection, err := inspectRequestBody(r)
	if err != nil {
		t.Fatal(err)
	}
	return inspection
}

func TestRequestBodyInspectionLimitsAndReplay(t *testing.T) {
	const placeholder = "{vzm:body}"
	for _, tt := range []struct {
		name      string
		size      int64
		declared  int64 // zero means use the actual length
		header    http.Header
		scan      bool
		warning   string
		readLimit int64
	}{
		{name: "display boundary", size: maxApprovalBodySize, scan: true, readLimit: maxApprovalBodySize},
		{name: "above display limit", size: maxApprovalBodySize + 1, scan: true, warning: "too large", readLimit: maxApprovalBodySize + 1},
		{name: "inspection boundary", size: maxInspectionBodySize, scan: true, warning: "too large", readLimit: maxInspectionBodySize},
		{name: "oversized declaration", size: 32, declared: maxInspectionBodySize + 1, warning: "too large"},
		{name: "understated length", size: maxInspectionBodySize + 2, declared: 1, warning: "too large", readLimit: maxInspectionBodySize + 1},
		{name: "unknown length", size: 32, declared: -1, warning: "unknown length"},
		{name: "expect continue", size: 32, header: http.Header{"Expect": {"other, 100-Continue"}}, warning: "Expect: 100-continue"},
		{name: "encoded", size: 32, header: http.Header{"Content-Encoding": {"gzip"}}, scan: true, warning: "compressed or encoded", readLimit: 32},
		{name: "multipart", size: 32, header: http.Header{"Content-Type": {"Multipart/Form-Data; boundary=x"}}, scan: true, warning: "multipart", readLimit: 32},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// The secret is beyond the display limit for large bodies.
			body := strings.Repeat("x", int(tt.size)-len(placeholder)) + placeholder
			r := approvalBodyRequest(http.MethodPost, []byte(body))
			if tt.header != nil {
				r.Header = tt.header.Clone()
			}
			if tt.declared != 0 {
				r.ContentLength = tt.declared
			}
			originalLength := r.ContentLength
			original := &trackedRequestBody{Reader: strings.NewReader(body)}
			r.Body = original

			inspection := inspectRequestBodyForTest(t, r)
			var wantNames []approvalSecret
			if tt.scan {
				wantNames = []approvalSecret{{Name: "body", Location: secretInBody}}
			}
			if names := findRequestSecrets(r, inspection); !slices.Equal(names, wantNames) {
				t.Fatalf("secrets = %v, want %v", names, wantNames)
			}
			display := approvalBodyForRequest(r, inspection)
			if tt.warning != "" {
				if display == nil || display.Text != "" || !strings.Contains(display.Warning, tt.warning) {
					t.Fatalf("display = %#v, want warning containing %q", display, tt.warning)
				}
			} else if display == nil || display.Text != body || display.Warning != "" {
				t.Fatal("display does not match body")
			}
			if int64(original.readBytes) != tt.readLimit {
				t.Fatalf("inspection read %d bytes, want %d", original.readBytes, tt.readLimit)
			}

			applySecretSubstitutions(r, inspection, map[string]string{"body": "replacement"})
			wantBody := body
			if tt.scan {
				wantBody = strings.ReplaceAll(body, placeholder, "replacement")
				if r.ContentLength != int64(len(wantBody)) || r.Header.Get("Content-Length") != strconv.Itoa(len(wantBody)) {
					t.Fatal("rewritten body length was not updated")
				}
			} else if r.ContentLength != originalLength || r.Header.Get("Content-Length") != "" {
				t.Fatal("uninspected body framing changed")
			}
			if got := readRequestBody(t, r); got != wantBody {
				t.Fatalf("replayed body differs: length %d, want %d", len(got), len(wantBody))
			}
			if err := r.Body.Close(); err != nil || original.closes != 1 {
				t.Fatalf("original body closed %d times: %v", original.closes, err)
			}
		})
	}
}

func TestRequestBodyReadFailureRejectsBeforeApproval(t *testing.T) {
	testApprovals(t, func(approvalRequest) approvalResponse {
		t.Error("unreadable body reached approval")
		return approvalResponse{Approved: false}
	})
	r := httptest.NewRequest(http.MethodPost, "https://example.com/", strings.NewReader("partial body"))
	original := &trackedRequestBody{Reader: io.MultiReader(strings.NewReader("partial"), failingBodyReader{})}
	r.Body = original
	proxy, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveHTTPRequest(proxy, bufio.NewReader(proxy), r, "example.com", "443", "https")
	}()
	defer func() {
		client.Close()
		proxy.Close()
		<-done
	}()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	response, err := http.ReadResponse(bufio.NewReader(client), r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	<-done
	if response.StatusCode != http.StatusInternalServerError || original.closes != 1 {
		t.Fatalf("status = %d, want 500; body closed %d times", response.StatusCode, original.closes)
	}
}

type failingBodyReader struct{}

func (failingBodyReader) Read([]byte) (int, error) { return 0, errors.New("body read failed") }
