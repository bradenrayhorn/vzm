package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

func serveTransparentTLS(ctx context.Context, conn net.Conn, destinationHost, port string) {
	host := destinationHost
	_ = conn.SetDeadline(time.Now().Add(networkHeaderTimeout))
	tlsConn := tls.Server(conn, &tls.Config{
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if name := normalizeDomain(hello.ServerName); name != "" {
				if !validDNSHostname(name) {
					return nil, fmt.Errorf("invalid TLS server name")
				}
				// A synthetic address identifies a particular DNS name. Do not
				// let SNI silently switch an already identified destination.
				if net.ParseIP(destinationHost) == nil && name != destinationHost {
					return nil, fmt.Errorf("TLS name does not match synthetic destination")
				}
				host = name
			}
			// Approval can be interactive; don't consume the handshake timeout
			// while waiting for the user. Cancellation still closes the socket.
			_ = conn.SetDeadline(time.Time{})
			approved := askForApprovalContext(ctx, approvalRequest{
				Type: "CONNECT", Domain: host, Method: "CONNECT", URL: net.JoinHostPort(host, port),
			}).Approved
			_ = conn.SetDeadline(time.Now().Add(networkHeaderTimeout))
			if !approved {
				return nil, fmt.Errorf("connection denied")
			}
			cert, err := generateFakeCertForDomain(host)
			return &cert, err
		},
	})
	defer tlsConn.Close()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	serveHTTPStreamContext(ctx, tlsConn, host, port, "https")
}
