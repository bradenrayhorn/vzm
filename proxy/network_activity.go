package main

import (
	"encoding/json"
	"net"
	"sync/atomic"
	"time"
)

// Preserve the menu-bar byte counters without sending per-packet IPC. These
// counters measure guest TCP bytes (including TLS), just as the vsock bridge did.
type networkActivity struct {
	upload   atomic.Int64
	download atomic.Int64
}

type networkActivityMessage struct {
	Type          string `json:"type"`
	UploadBytes   int64  `json:"uploadBytes"`
	DownloadBytes int64  `json:"downloadBytes"`
}

type activityConn struct {
	net.Conn
	activity *networkActivity
}

func (c *activityConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.activity.upload.Add(int64(n))
	return n, err
}

func (c *activityConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.activity.download.Add(int64(n))
	return n, err
}

func (c *activityConn) CloseWrite() error {
	closeWrite(c.Conn)
	return nil
}

func (n *virtualNetwork) reportActivity() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
		}
		message := networkActivityMessage{Type: "NETWORK_ACTIVITY", UploadBytes: n.activity.upload.Swap(0), DownloadBytes: n.activity.download.Swap(0)}
		if message.UploadBytes == 0 && message.DownloadBytes == 0 {
			continue
		}
		conn, err := net.DialTimeout("unix", controlUnixPath, time.Second)
		if err != nil {
			continue
		}
		_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
		_ = json.NewEncoder(conn).Encode(message)
		_ = conn.Close()
	}
}
