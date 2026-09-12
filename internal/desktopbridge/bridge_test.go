package desktopbridge

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

func TestTargetForPortAllowsOnlyFixedGuestLoopbackServices(t *testing.T) {
	cases := map[uint32]Target{
		GuestSSHPort:    {Host: "127.0.0.1", Port: 22},
		GuestHTTPPort:   {Host: "127.0.0.1", Port: 8080},
		GuestHealthPort: {Host: "127.0.0.1", Port: 18481},
	}
	for port, want := range cases {
		got, err := TargetForPort(port)
		if err != nil || got != want {
			t.Fatalf("TargetForPort(%d) = %#v, %v; want %#v", port, got, err, want)
		}
	}
	for _, port := range []uint32{0, 1, 22, 8080, 65535} {
		if _, err := TargetForPort(port); err == nil {
			t.Fatalf("TargetForPort(%d) unexpectedly allowed", port)
		}
	}
}

func TestServeClosesWhenContextIsCancelled(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, listener, GuestHTTPPort) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not close its listener after cancellation")
	}
}

func TestForwardStdioHTTPUsesOnlyFixedLoopbackHTTP(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	go func() {
		buffer := make([]byte, 3)
		_, _ = server.Read(buffer)
		_, _ = server.Write([]byte("ok"))
		_ = server.Close()
	}()
	var got bytes.Buffer
	var network, address string
	err := ForwardStdioHTTP(context.Background(), bytes.NewBufferString("GET"), &got, func(actualNetwork, actualAddress string, _ time.Duration) (net.Conn, error) {
		network, address = actualNetwork, actualAddress
		return client, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if network != "tcp" || address != "127.0.0.1:8080" || got.String() != "ok" {
		t.Fatalf("stdio bridge = %q to %s/%s", got.String(), network, address)
	}
}
