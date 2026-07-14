package main

// This test exercises the full "tcp" tunnel path of the srvus server:
//
//  1. An in-process SSH server (srvus's own server type) is started on a
//     random local port, using an ephemeral, in-memory host key instead of
//     reading key files from disk.
//  2. A real golang.org/x/crypto/ssh client connects to it as user "tcp",
//     which is srvus's convention for requesting a raw TCP tunnel (as
//     opposed to HTTP/HTTPS routing via other usernames).
//  3. The client issues a standard SSH remote port-forward request
//     (tcpip-forward) via client.Listen(...). The server responds by
//     opening a public TCP listener and, for every connection accepted on
//     it, dials back into the client over a "forwarded-tcpip" channel.
//  4. The test plays the role of the srvus client program: for every
//     forwarded connection it receives, it dials a local backend TCP echo
//     server and pipes bytes both ways.
//  5. Finally, the test dials the server's public tunnel port directly (as
//     an external caller would) and verifies that bytes written are echoed
//     back, proving the full path: external client -> srvus server ->
//     SSH tunnel -> test "backend" -> and back again.

import (
	"crypto/ed25519"
	crand "crypto/rand"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// newTestHostKey generates an ephemeral ed25519 SSH host key signer, so the
// test doesn't depend on any host key files on disk.
func newTestHostKey(t *testing.T) ssh.Signer {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatalf("failed to generate host key: %v", err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("failed to create signer from host key: %v", err)
	}
	return signer
}

// startTestSSHServer boots a fresh srvus *server on a random local port
// without touching CLI flags or on-disk host key files, and returns the
// server instance (for assertions) along with its listen address.
func startTestSSHServer(t *testing.T) (*server, string) {
	t.Helper()

	localhost := "127.0.0.1"
	domain = &localhost
	s := newServer()

	sshConfig := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-srvus-test-1.0",
	}
	sshConfig.AddHostKey(newTestHostKey(t))

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for ssh: %v", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// Mirrors server.serveSSH()'s accept loop, minus the
			// disk/flag-based bootstrapping.
			go s.serveSSHConnection(sshConfig, conn)
		}
	}()

	t.Cleanup(func() {
		_ = listener.Close()
	})

	return s, listener.Addr().String()
}

// startEchoServer starts a plain TCP echo server, standing in for the local
// service that a real srvus client would expose through the tunnel.
func startEchoServer(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for echo server: %v", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c) // echo whatever is read straight back
			}(conn)
		}
	}()

	t.Cleanup(func() {
		_ = listener.Close()
	})

	return listener.Addr().String()
}

func TestTCPTunnelEndToEnd(t *testing.T) {
	// 1. Start the srvus SSH server.
	s, sshAddr := startTestSSHServer(t)

	// 2. Start a local backend service that will be exposed through the
	// tunnel, playing the role of "the thing behind the srvus client".
	backendAddr := startEchoServer(t)

	// 3. Connect an SSH client as the "tcp" user to request a raw TCP
	// tunnel. Any credentials are accepted by srvus (it treats every
	// non-public-key auth attempt as an anonymous session).
	clientConfig := &ssh.ClientConfig{
		User:            "tcp",
		Auth:            []ssh.AuthMethod{ssh.Password("anything")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	client, err := ssh.Dial("tcp", sshAddr, clientConfig)
	if err != nil {
		t.Fatalf("failed to dial ssh server: %v", err)
	}
	defer client.Close()

	// 4. Ask the server to open a remote TCP listener (tcpip-forward) and
	// forward incoming connections back to us over the SSH connection.
	// This is exactly what the real srvus client does under the hood.
	remoteListener, err := client.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to request remote tcp forward: %v", err)
	}
	defer remoteListener.Close()

	// Act like the srvus client: for every forwarded connection, dial the
	// local backend and pipe data both ways.
	go func() {
		for {
			forwarded, err := remoteListener.Accept()
			if err != nil {
				return
			}
			go func(fc net.Conn) {
				defer fc.Close()

				backend, err := net.Dial("tcp", backendAddr)
				if err != nil {
					return
				}
				defer backend.Close()

				done := make(chan struct{}, 2)
				go func() {
					_, _ = io.Copy(backend, fc)
					done <- struct{}{}
				}()
				go func() {
					_, _ = io.Copy(fc, backend)
					done <- struct{}{}
				}()
				<-done
			}(forwarded)
		}
	}()

	// 5. Wait until the server has registered the tunnel's public TCP
	// listener (it registers this before replying to tcpip-forward, so in
	// practice this succeeds immediately after client.Listen returns).
	deadline := time.Now().Add(2 * time.Second)
	for {
		s.Lock()
		n := len(s.tcpListeners)
		s.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected 1 registered tcp listener, got %d", n)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Read back the actual public port srvus is listening on for this
	// tunnel (chosen by the OS, since we requested port 0).
	s.Lock()
	publicPort := s.tcpListeners[0].Listener.Addr().(*net.TCPAddr).Port
	s.Unlock()
	publicAddr := fmt.Sprintf("127.0.0.1:%d", publicPort)

	// 6. Simulate an external caller hitting the public tunnel endpoint,
	// the way any internet client would connect to <endpoint>:<port>.
	conn, err := net.Dial("tcp", publicAddr)
	if err != nil {
		t.Fatalf("failed to dial public tunnel address %s: %v", publicAddr, err)
	}
	defer conn.Close()

	payload := []byte("hello through the tunnel")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("failed to write payload: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("failed to read echoed payload: %v", err)
	}

	if string(buf) != string(payload) {
		t.Fatalf("unexpected echo response: got %q, want %q", buf, payload)
	}

	// 7. Sanity-check server-side bookkeeping reflects the active session.
	s.Lock()
	connCount := len(s.conns)
	s.Unlock()
	if connCount != 1 {
		t.Fatalf("expected 1 tracked ssh connection, got %d", connCount)
	}
}
