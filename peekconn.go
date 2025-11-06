package main

import (
	"io"
	"net"
	"sync"
	"time"
)

// CustomConn wraps a bufio.Reader and the original net.Conn
type CustomConn struct {
	io.Reader
	net.Conn // The original connection, used for Write, Close, LocalAddr, etc.
}

// Read implements the net.Conn Read method.
// It reads from the internal bufio.Reader, which will first return
// the data that was peeked, and then read directly from the underlying connection.
func (c CustomConn) Read(b []byte) (int, error) {
	return c.Reader.Read(b)
}

// Close is needed to fulfill the net.Conn interface, using the original conn's method.
func (c CustomConn) Close() error {
	// Note: Closing the underlying conn will affect the reader.
	return c.Conn.Close()
}

// SetReadDeadline, SetWriteDeadline, SetDeadline
// These are also necessary for the full net.Conn implementation.
// We delegate these to the underlying net.Conn.
func (c CustomConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}
func (c CustomConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}
func (c CustomConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

// LocalAddr, RemoteAddr, Write are directly satisfied by embedding net.Conn,
// but let's explicitly implement Write for clarity, though it's not strictly
// necessary if `net.Conn` is the last embedded field or if you explicitly
// call `c.Conn.Write`. Embedding it makes its methods available directly.

// Write implements the net.Conn Write method.
func (c CustomConn) Write(b []byte) (int, error) {
	return c.Conn.Write(b)
}

// NewCustomConn creates the new net.Conn wrapper
func NewCustomConn(conn net.Conn, reader io.Reader) net.Conn {
	return &CustomConn{
		Reader: reader,
		Conn:   conn,
	}
}

// SafeCloser wraps a channel and provides a safe way to close it
type SafeCloser[T any] struct {
	C    chan T
	once sync.Once
}

// NewSafeCloser creates a new SafeCloser for a given channel
func NewSafeCloser[T any](ch chan T) *SafeCloser[T] {
	return &SafeCloser[T]{
		C: ch,
	}
}

// Close closes the channel safely, ensuring it's only closed once
func (sc *SafeCloser[T]) Close() {
	sc.once.Do(func() {
		close(sc.C)
	})
}
