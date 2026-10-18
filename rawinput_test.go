package tls

import (
	"bytes"
	"io"
	"testing"
)

// rawInputPair returns a client and a server Conn with the handshake done.
func rawInputPair(t *testing.T) (*Conn, *Conn) {
	t.Helper()
	c, s := localPipe(t)
	client := Client(c, testConfig.Clone())
	server := Server(s, testConfig.Clone())
	errc := make(chan error, 1)
	go func() { errc <- server.Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close(); server.Close() })
	return client, server
}

func checkIdle(t *testing.T, conn *Conn, when string) {
	t.Helper()
	conn.in.Lock()
	defer conn.in.Unlock()
	if conn.rawInputPooled != nil {
		t.Errorf("%s: a drained conn holds a pooled raw input buffer", when)
	}
	if n := cap(conn.rawInput.Bytes()); n > rawInputSmallSize {
		t.Errorf("%s: a drained conn holds %d bytes of raw input, want at most %d", when, n, rawInputSmallSize)
	}
	if n := conn.hand.Cap(); n != 0 && when == "after the handshake" {
		t.Errorf("%s: the handshake buffer keeps %d bytes", when, n)
	}
}

// TestRawInputIdle: a connection holds no more than a small raw input
// buffer after the handshake and after a transfer of full records, and the
// data arrives intact whatever the record sizes.
func TestRawInputIdle(t *testing.T) {
	client, server := rawInputPair(t)
	checkIdle(t, client, "after the handshake")
	checkIdle(t, server, "after the handshake")

	sizes := []int{1, 100, 900, 2000, 16384, 70000, 5, 300000, 17}
	var want bytes.Buffer
	for i, n := range sizes {
		p := make([]byte, n)
		for j := range p {
			p[j] = byte(i + j)
		}
		want.Write(p)
	}
	go func() {
		for i, n := range sizes {
			p := make([]byte, n)
			for j := range p {
				p[j] = byte(i + j)
			}
			if _, err := client.Write(p); err != nil {
				return
			}
		}
	}()
	got := make([]byte, want.Len())
	// Reads of every size: whole records, parts of records.
	for off, step := 0, 1; off < len(got); step = step*3 + 1 {
		if step > 50000 {
			step = 7
		}
		end := off + step
		if end > len(got) {
			end = len(got)
		}
		n, err := io.ReadFull(server, got[off:end])
		if err != nil {
			t.Fatal(err)
		}
		off += n
	}
	if !bytes.Equal(got, want.Bytes()) {
		t.Fatal("the data was corrupted")
	}
	checkIdle(t, server, "after a transfer")

	// a short message back and forth keeps the small buffer
	go client.Write([]byte("ping"))
	p := make([]byte, 4)
	if _, err := io.ReadFull(server, p); err != nil || string(p) != "ping" {
		t.Fatalf("got %q, %v", p, err)
	}
	checkIdle(t, server, "after a short message")
}

// TestRawInputCloseNotify: the close_notify read ahead with the last data
// still ends the stream with EOF.
func TestRawInputCloseNotify(t *testing.T) {
	client, server := rawInputPair(t)
	go func() {
		client.Write(bytes.Repeat([]byte("x"), 20000))
		client.CloseWrite()
	}()
	got, err := io.ReadAll(server)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 20000 {
		t.Fatalf("read %d bytes, want 20000", len(got))
	}
	checkIdle(t, server, "after close_notify")
}

func BenchmarkRawInputThroughput(b *testing.B) {
	c, s := localPipe(b)
	client := Client(c, testConfig.Clone())
	server := Server(s, testConfig.Clone())
	go server.Handshake()
	if err := client.Handshake(); err != nil {
		b.Fatal(err)
	}
	defer client.Close()
	defer server.Close()
	const chunk = 1 << 20
	go func() {
		p := make([]byte, chunk)
		for {
			if _, err := client.Write(p); err != nil {
				return
			}
		}
	}()
	p := make([]byte, 32<<10)
	b.SetBytes(chunk)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for n := 0; n < chunk; {
			m, err := server.Read(p)
			if err != nil {
				b.Fatal(err)
			}
			n += m
		}
	}
}

// TestWaitRead: WaitRead returns once data can be read, consumes nothing,
// and reports the error Read would.
func TestWaitRead(t *testing.T) {
	client, server := rawInputPair(t)
	go client.Write([]byte("hello"))
	if err := server.WaitRead(); err != nil {
		t.Fatal(err)
	}
	if err := server.WaitRead(); err != nil { // data is waiting: returns at once
		t.Fatal(err)
	}
	p := make([]byte, 5)
	if _, err := io.ReadFull(server, p); err != nil || string(p) != "hello" {
		t.Fatalf("got %q, %v", p, err)
	}
	checkIdle(t, server, "after WaitRead and Read")
	client.Close()
	if err := server.WaitRead(); err != io.EOF {
		t.Fatalf("WaitRead after close_notify: %v, want EOF", err)
	}
	if _, err := server.Read(p); err != io.EOF {
		t.Fatalf("Read after close_notify: %v, want EOF", err)
	}
}
