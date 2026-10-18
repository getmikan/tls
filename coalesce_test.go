package tls

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
)

// writeSizeConn records the size of every write to the connection.
type writeSizeConn struct {
	net.Conn
	mu     sync.Mutex
	writes []int
}

func (c *writeSizeConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, len(b))
	c.mu.Unlock()
	return c.Conn.Write(b)
}

func (c *writeSizeConn) reset() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	w := c.writes
	c.writes = nil
	return w
}

// TestWriteCoalescesRecords checks that the records of one large write go to
// the connection in writes of several records, up to coalesceLimit, and that
// the peer reads the same data, with every cipher kind.
func TestWriteCoalescesRecords(t *testing.T) {
	configs := map[string]func(*Config){
		"TLSv13": func(*Config) {},
		"AEAD": func(c *Config) {
			c.MaxVersion = VersionTLS12
			c.CipherSuites = []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
		},
		"CBC": func(c *Config) {
			c.MaxVersion = VersionTLS12
			c.CipherSuites = []uint16{TLS_RSA_WITH_AES_256_CBC_SHA}
		},
		"Stream": func(c *Config) {
			c.MaxVersion = VersionTLS12
			c.CipherSuites = []uint16{TLS_RSA_WITH_RC4_128_SHA}
		},
	}
	for name, configure := range configs {
		for _, dynamic := range []bool{false, true} {
			config := testConfig.Clone()
			configure(config)
			serverConfig := config.Clone()
			serverConfig.DynamicRecordSizingDisabled = !dynamic
			testWriteCoalescesRecords(t, name, dynamic, config, serverConfig)
		}
	}
}

func testWriteCoalescesRecords(t *testing.T, name string, dynamic bool, clientConfig, serverConfig *Config) {
	clientConn, serverConn := localPipe(t)
	counted := &writeSizeConn{Conn: serverConn}
	server := Server(counted, serverConfig)
	defer server.Close()

	plaintext := make([]byte, 1<<20+123)
	for i := range plaintext {
		plaintext[i] = byte(i * 7)
	}
	got := make(chan []byte, 1)
	go func() {
		client := Client(clientConn, clientConfig)
		defer client.Close()
		data, err := io.ReadAll(io.LimitReader(client, int64(len(plaintext))))
		if err != nil {
			t.Errorf("%s: client read: %v", name, err)
		}
		got <- data
	}()
	if err := server.Handshake(); err != nil {
		t.Fatalf("%s: handshake: %v", name, err)
	}
	counted.reset()
	if n, err := server.Write(plaintext); err != nil || n != len(plaintext) {
		t.Fatalf("%s: write = %d, %v", name, n, err)
	}
	writes := counted.reset()
	if data := <-got; !bytes.Equal(data, plaintext) {
		t.Fatalf("%s: the client read other data (%d bytes)", name, len(data))
	}

	total := 0
	for i, size := range writes {
		total += size
		if size > coalesceLimit {
			t.Errorf("%s: write #%d of %d bytes, over the limit of %d", name, i, size, coalesceLimit)
		}
	}
	fullRecords := len(plaintext)/maxPlaintext + 1
	maxWrites := fullRecords/7 + 1 // about eight records per write
	if dynamic {
		maxWrites += recordSizeBoostThreshold / (8 * 1000) // the small records first
	}
	if len(writes) > maxWrites {
		t.Errorf("%s (dynamic %v): %d writes for %d bytes of records, want at most %d", name, dynamic, len(writes), total, maxWrites)
	}
}

// TestWriteSmallRecordsUnchanged checks that a write of one record is still
// one write of that record.
func TestWriteSmallRecordsUnchanged(t *testing.T) {
	clientConn, serverConn := localPipe(t)
	counted := &writeSizeConn{Conn: serverConn}
	server := Server(counted, testConfig.Clone())
	defer server.Close()
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		client := Client(clientConn, testConfig.Clone())
		defer client.Close()
		buf := make([]byte, 100)
		for i := 0; i < 3; i++ {
			if _, err := io.ReadFull(client, buf[:10]); err != nil {
				t.Errorf("client read: %v", err)
				return
			}
		}
	}()
	if err := server.Handshake(); err != nil {
		t.Fatal(err)
	}
	counted.reset()
	for i := 0; i < 3; i++ {
		if _, err := server.Write(bytes.Repeat([]byte{'a'}, 10)); err != nil {
			t.Fatal(err)
		}
		if writes := counted.reset(); len(writes) != 1 || writes[0] != recordHeaderLen+10+1+16 {
			t.Fatalf("write %d: writes %v, want one record of %d bytes", i, writes, recordHeaderLen+10+1+16)
		}
	}
	<-clientDone // before the connections are closed
}
