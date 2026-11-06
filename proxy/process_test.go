package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Run the real entry point in a subprocess so flag parsing and signal handling
// do not change the test runner's globals.
func TestProxyProcessHelper(t *testing.T) {
	if os.Getenv("VZM_TEST_PROXY_PROCESS") != "1" {
		return
	}
	os.Args = append([]string{os.Args[0]}, os.Args[3:]...)
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	main()
	os.Exit(0)
}

func proxyProcess(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestProxyProcessHelper$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), "VZM_TEST_PROXY_PROCESS=1")
	return cmd
}

func TestProxyRejectsLegacyListenerFlags(t *testing.T) {
	for _, name := range []string{"listen-unix", "listen-tcp", "tcp-listen-unix"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			output, err := proxyProcess(ctx, "--"+name, "unused").CombinedOutput()
			if err == nil || !strings.Contains(string(output), "flag provided but not defined: -"+name) {
				t.Fatalf("legacy flag not rejected: %v\n%s", err, output)
			}
		})
	}
}

func TestProxyProcessLifecycle(t *testing.T) {
	for _, withGit := range []bool{false, true} {
		name := "network-only"
		if withGit {
			name = "network-with-git"
		}
		t.Run(name, func(t *testing.T) {
			// Keep Unix socket paths below Darwin's length limit.
			dir, err := os.MkdirTemp("/tmp", "vzm-proxy-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
			if err != nil {
				t.Fatal(err)
			}
			wire := os.NewFile(uintptr(fds[0]), "proxy-wire")
			peer := os.NewFile(uintptr(fds[1]), "guest-wire")
			defer wire.Close()
			defer peer.Close()

			caPath := filepath.Join(dir, "ca.pem")
			args := []string{"--network-fd", "3", "--ca-cert", caPath}
			readyPaths := []string{caPath}
			if withGit {
				gitPath := filepath.Join(dir, "git.sock")
				args = append(args, "--git-listen-unix", gitPath)
				readyPaths = append(readyPaths, gitPath)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := proxyProcess(ctx, args...)
			cmd.ExtraFiles = []*os.File{wire}
			var output bytes.Buffer
			cmd.Stdout, cmd.Stderr = &output, &output
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			var waitErr error
			go func() { waitErr = cmd.Wait(); close(done) }()
			defer func() { cancel(); <-done }()

			for {
				ready := true
				for _, path := range readyPaths {
					info, err := os.Stat(path)
					if err != nil || (path == caPath && info.Size() == 0) {
						ready = false
						break
					}
				}
				if ready {
					break
				}
				select {
				case <-done:
					t.Fatalf("proxy exited before ready: %v\n%s", waitErr, &output)
				case <-time.After(10 * time.Millisecond):
				}
			}
			pem, err := os.ReadFile(caPath)
			if err != nil || !x509.NewCertPool().AppendCertsFromPEM(pem) {
				t.Fatalf("CA distribution failed: %v", err)
			}
			select {
			case <-done:
				t.Fatalf("proxy exited without legacy listener: %v\n%s", waitErr, &output)
			case <-time.After(100 * time.Millisecond):
			}
			if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			<-done
			if waitErr != nil {
				t.Fatalf("proxy shutdown failed: %v\n%s", waitErr, &output)
			}
		})
	}
}
