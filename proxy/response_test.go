package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestProxyResponseCompressionFraming(t *testing.T) {
	payload := []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`)
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := payload
		if r.Header.Get("Accept-Encoding") == "gzip" {
			w.Header().Set("Content-Encoding", "gzip")
			body = compressed.Bytes()
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	}))
	defer upstream.Close()

	for _, encoding := range []string{"", "identity", "gzip"} {
		t.Run("accept_encoding="+encoding, func(t *testing.T) {
			transport := newOutboundTransport()
			// Only the test transport may dial the loopback test server.
			transport.DialContext = (&net.Dialer{}).DialContext
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport}
			req, err := http.NewRequest(http.MethodPost, upstream.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			if encoding != "" {
				req.Header.Set("Accept-Encoding", encoding)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.Uncompressed != (encoding == "") {
				t.Fatalf("Uncompressed = %v for encoding %q", resp.Uncompressed, encoding)
			}

			proxy, downstream := net.Pipe()
			defer proxy.Close()
			defer downstream.Close()
			_ = downstream.SetDeadline(time.Now().Add(time.Second))
			done := make(chan error, 1)
			// Deliberately leave the connection open after Write, as the
			// CONNECT loop does when waiting for the next HTTP request.
			go func() { done <- writeProxyResponse(proxy, resp) }()
			forwarded, err := http.ReadResponse(bufio.NewReader(downstream), req)
			if err != nil {
				t.Fatal(err)
			}
			defer forwarded.Body.Close()
			if forwarded.Close {
				t.Fatal("response unexpectedly requires closing the persistent connection")
			}
			got, err := io.ReadAll(forwarded.Body)
			if err != nil {
				t.Fatalf("reading forwarded body without closing connection: %v", err)
			}
			want := payload
			if encoding == "gzip" {
				want = compressed.Bytes()
				if forwarded.Header.Get("Content-Encoding") != "gzip" {
					t.Fatal("explicitly requested gzip encoding was lost")
				}
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("forwarded body = %q, want %q", got, want)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProxyResponseStreamsBeforeEOF(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		name := "unknown_length"
		if chunked {
			name = "upstream_chunked"
		}
		t.Run(name, func(t *testing.T) {
			body, producer := io.Pipe()
			defer body.Close()
			defer producer.Close()
			resp := &http.Response{
				StatusCode: http.StatusOK,
				ProtoMajor: 1, ProtoMinor: 1,
				Header:        http.Header{"Content-Type": {"text/event-stream"}},
				Body:          body,
				ContentLength: -1,
				Uncompressed:  !chunked,
			}
			if chunked {
				resp.TransferEncoding = []string{"chunked"}
			}
			proxy, downstream := net.Pipe()
			defer proxy.Close()
			defer downstream.Close()
			_ = downstream.SetDeadline(time.Now().Add(time.Second))
			done := make(chan error, 1)
			go func() { done <- writeProxyResponse(proxy, resp) }()
			forwarded, err := http.ReadResponse(bufio.NewReader(downstream), nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(forwarded.TransferEncoding) != 1 || forwarded.TransferEncoding[0] != "chunked" {
				t.Fatalf("missing chunked framing: %v", forwarded.TransferEncoding)
			}
			event := "event: message\ndata: {\"id\":2}\n\n"
			go func() { _, _ = io.WriteString(producer, event) }()
			got := make([]byte, len(event))
			if _, err := io.ReadFull(forwarded.Body, got); err != nil {
				t.Fatalf("reading SSE event before upstream EOF: %v", err)
			}
			if string(got) != event {
				t.Fatalf("SSE event = %q, want %q", got, event)
			}
			_ = producer.Close()
			if _, err := io.ReadAll(forwarded.Body); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProxyResponseDoesNotAddChunkingToBodylessResponses(t *testing.T) {
	for _, tc := range []struct {
		status int
		method string
	}{
		{http.StatusContinue, http.MethodGet},
		{http.StatusNoContent, http.MethodGet},
		{http.StatusNotModified, http.MethodGet},
		{http.StatusOK, http.MethodHead},
	} {
		resp := &http.Response{
			StatusCode: tc.status,
			ProtoMajor: 1, ProtoMinor: 1,
			Header:        make(http.Header),
			Body:          http.NoBody,
			ContentLength: -1,
			Request:       &http.Request{Method: tc.method},
		}
		var wire bytes.Buffer
		if err := writeProxyResponse(&wire, resp); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(wire.String(), "Transfer-Encoding:") {
			t.Fatalf("bodyless response has transfer encoding: %s", wire.String())
		}
	}
}
