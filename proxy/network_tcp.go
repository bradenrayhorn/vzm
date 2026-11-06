package main

import (
	"context"
	"net"
	"net/netip"
	"syscall"
	"time"
)

var rawTCPDialer = &net.Dialer{
	Timeout:        15 * time.Second,
	ControlContext: rejectUnsafeRawTCPDialDestination,
}

var carrierGradeNATPrefix = mustPrefix("100.64.0.0/10")

func rejectUnsafeRawTCPDialDestination(_ context.Context, network, address string, _ syscall.RawConn) error {
	return rejectDialDestination(network, address, isAllowedRawTCPDestinationAddr)
}

// isAllowedRawTCPDestinationAddr permits public destinations plus private-use
// and carrier-grade NAT addresses commonly reached over a VPN. Host loopback,
// link-local, multicast, unspecified, documentation, and other reserved ranges
// remain blocked even after the raw TCP connection is approved.
func isAllowedRawTCPDestinationAddr(addr netip.Addr) bool {
	if !addr.IsValid() || addr.Zone() != "" {
		return false
	}

	addr = addr.Unmap()
	if addr.IsPrivate() || carrierGradeNATPrefix.Contains(addr) {
		return true
	}
	return isAllowedDestinationAddr(addr)
}

// No upstream DNS lookup, socket, or payload forwarding happens until this
// particular connection is approved. TCP_CONNECT is always one-shot in vzm,
// even for known domains and in Approve Everything mode.
func (n *virtualNetwork) serveRawTCP(conn net.Conn, host, port string) error {
	target := net.JoinHostPort(host, port)
	if !askForApprovalContext(n.ctx, approvalRequest{
		Type: "TCP_CONNECT", Domain: host, Method: "CONNECT", URL: target,
	}).Approved {
		return nil
	}

	// This dialer checks the resolved address, allowing private/VPN databases
	// but still rejecting loopback, link-local, and other unsafe destinations.
	upstream, err := n.dialRawTCP(n.ctx, "tcp", target)
	if err != nil {
		return err
	}
	defer upstream.Close()
	stop := context.AfterFunc(n.ctx, func() { upstream.Close() })
	defer stop()

	return tunnelConnections(conn, conn, upstream, upstream)
}
