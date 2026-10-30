//go:build linux

// A disposable initramfs init. No disks, credentials, or host shares are mounted.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

func command(args ...string) {
	out, err := exec.Command("/bin/busybox", args...).CombinedOutput()
	if err != nil {
		panic(fmt.Sprintf("%v: %s: %v", args, out, err))
	}
}

func check() {
	_ = os.MkdirAll("/proc", 0755)
	_ = os.MkdirAll("/sys", 0755)
	_ = os.MkdirAll("/dev", 0755)
	_ = syscall.Mount("proc", "/proc", "proc", 0, "")
	_ = syscall.Mount("sysfs", "/sys", "sysfs", 0, "")
	_ = syscall.Mount("devtmpfs", "/dev", "devtmpfs", 0, "")
	command("modprobe", "virtio_net")
	var nic string
	for i := 0; i < 50 && nic == ""; i++ {
		entries, _ := os.ReadDir("/sys/class/net")
		for _, entry := range entries {
			mac, _ := os.ReadFile("/sys/class/net/" + entry.Name() + "/address")
			if strings.TrimSpace(string(mac)) == "02:00:00:00:00:02" {
				nic = entry.Name()
			}
		}
		if nic == "" {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if nic == "" {
		panic("virtio NIC missing")
	}
	command("ip", "link", "set", "lo", "up")
	command("ip", "addr", "add", "192.168.127.2/24", "dev", nic)
	command("ip", "link", "set", nic, "up")
	command("ip", "route", "add", "default", "via", "192.168.127.1")
	_ = os.Remove("/etc/resolv.conf")
	if err := os.WriteFile("/etc/resolv.conf", []byte("nameserver 192.168.127.1\noptions timeout:2 attempts:1\n"), 0644); err != nil {
		panic(err)
	}
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		os.Unsetenv(key)
	}
	os.Setenv("SSL_CERT_FILE", "/etc/vzm-ca.pem")
	os.Setenv("SSL_CERT_DIR", "/nonexistent")
	ips, err := net.LookupIP("example.com")
	if err != nil || len(ips) != 1 || !strings.HasPrefix(ips[0].String(), "198.18.") {
		panic(fmt.Sprintf("synthetic DNS: %v %v", ips, err))
	}
	fmt.Println("PASS Linux virtio-net, ARP, synthetic DNS:", nic, ips)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second}
	for _, url := range []string{"https://example.com/", "https://cache.nixos.org/nix-cache-info"} {
		resp, err := client.Get(url)
		if err != nil {
			panic(fmt.Sprintf("%s: %v", url, err))
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 || len(body) == 0 {
			panic(fmt.Sprintf("%s: status=%d body=%q err=%v", url, resp.StatusCode, body, err))
		}
		fmt.Println("PASS ordinary guest HTTP client, no proxy variables:", url, "bytes", len(body))
	}
	if resp, err := client.Get("http://example.com/"); err == nil {
		resp.Body.Close()
		panic("plain HTTP accepted")
	}
	fmt.Println("PASS plain HTTP blocked")
	bad := transport.Clone()
	bad.TLSClientConfig = &tls.Config{RootCAs: x509.NewCertPool()}
	if resp, err := (&http.Client{Transport: bad, Timeout: 3 * time.Second}).Get("https://example.com/"); err == nil {
		resp.Body.Close()
		panic("untrusted CA accepted")
	}
	bad.CloseIdleConnections()
	fmt.Println("PASS MITM requires trusted CA")
	if resp, err := client.Get("https://denied.example/"); err == nil {
		resp.Body.Close()
		panic("denied connection accepted")
	}
	fmt.Println("PASS host CONNECT approval enforced")
	for _, target := range []string{"example.com:80", "example.com:22", "example.com:5432", "10.0.0.1:443", "169.254.169.254:443"} {
		conn, err := net.DialTimeout("tcp", target, 2*time.Second)
		if err == nil {
			conn.Close()
			panic("unmediated TCP accepted: " + target)
		}
	}
	fmt.Println("PASS arbitrary TCP and private/metadata destinations blocked")
	udp, err := net.DialTimeout("udp", "1.1.1.1:443", time.Second)
	if err != nil {
		panic(err)
	}
	_ = udp.SetDeadline(time.Now().Add(200 * time.Millisecond))
	_, _ = udp.Write([]byte("must not escape"))
	if _, err := udp.Read(make([]byte, 512)); err == nil {
		panic("arbitrary UDP accepted")
	}
	udp.Close()
	fmt.Println("PASS arbitrary UDP blocked")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := net.DefaultResolver.LookupIP(ctx, "ip6", "example.com"); err == nil {
		panic("unexpected IPv6 answer")
	}
}

func main() {
	defer func() {
		if value := recover(); value != nil {
			fmt.Println("VZM NETWORK SMOKE FAIL:", value)
		}
		time.Sleep(200 * time.Millisecond)
		_ = syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
		select {}
	}()
	check()
	// Let the host publish a byte-counter batch before the VM powers off.
	time.Sleep(1200 * time.Millisecond)
	fmt.Println("VZM NETWORK SMOKE PASS")
}
