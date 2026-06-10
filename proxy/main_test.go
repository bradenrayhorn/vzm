package main

import (
	"context"
	"errors"
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
