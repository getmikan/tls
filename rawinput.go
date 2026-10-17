package tls

import (
	"bytes"
	"sync"
)

// The raw input buffer (Conn.rawInput) is sized by what is moving, not by the
// largest record the connection ever saw.
//
// Upstream grows rawInput with bytes.Buffer.Grow, which doubles it, and keeps
// it for the life of the connection: a connection that once received a full
// record, or only a large ClientHello, holds 16-40 KiB (2-4 KiB after a
// handshake alone) while it waits for its next record. A proxy that keeps
// thousands of mostly idle connections pays that for each of them.
//
// Here a read takes a small buffer of its own while the records are small,
// and a pooled buffer that holds the largest record when one does not fit.
// Once Read has handed out everything that was read (the raw input and the
// plaintext are both drained) and the last record was a short one, a pooled
// buffer goes back to the pool and the small one, which is kept, takes over
// again. A connection that waits for its peer after a short message (an
// answer, an acknowledgement, a keepalive) or right after the handshake
// holds rawInputSmallSize bytes; one that waits after a full record keeps
// the pooled buffer (upstream keeps a larger one); a transfer of full
// records runs on one pooled buffer, with one read per record as before.

// rawInputSmallSize is the largest buffer a Conn allocates for itself: the
// record header and the read-ahead of readFromUntil (bytes.MinRead) with room
// for a short record.
const rawInputSmallSize = 1024

// rawInputPoolSize holds the largest record with its header and the
// read-ahead.
const rawInputPoolSize = recordHeaderLen + maxCiphertext + bytes.MinRead

var rawInputPool = sync.Pool{New: func() any {
	b := make([]byte, rawInputPoolSize)
	return &b
}}

// reserveRawInput makes room for n more bytes after the data in c.rawInput,
// keeping that data.
func (c *Conn) reserveRawInput(n int) {
	data := c.rawInput.Bytes()
	if cap(data)-len(data) >= n {
		return
	}
	m := len(data)
	if c.rawInputBuf != nil && m+n <= len(c.rawInputBuf) {
		// The data was read from the front of the buffer: move it back.
		k := copy(c.rawInputBuf, data)
		c.rawInput = *bytes.NewBuffer(c.rawInputBuf[:k])
		return
	}
	var buf []byte
	switch {
	case m+n <= rawInputSmallSize:
		if c.rawInputSmall == nil {
			c.rawInputSmall = make([]byte, rawInputSmallSize)
		}
		buf = c.rawInputSmall
	case m+n <= rawInputPoolSize:
		c.rawInputPooled = rawInputPool.Get().(*[]byte)
		buf = *c.rawInputPooled
	default:
		// Not reached by readFromUntil, whose records fit the pooled size.
		buf = make([]byte, m+n)
	}
	k := copy(buf, data)
	if c.rawInputPooled != nil && &buf[0] != &(*c.rawInputPooled)[0] {
		c.putRawInput()
	}
	c.rawInput = *bytes.NewBuffer(buf[:k])
	c.rawInputBuf = buf
}

// putRawInput returns a pooled raw input buffer to the pool. The caller
// replaces c.rawInput.
func (c *Conn) putRawInput() {
	if c.rawInputPooled != nil {
		rawInputPool.Put(c.rawInputPooled)
		c.rawInputPooled = nil
	}
	c.rawInputBuf = nil
}

// releaseInput lets go of the input buffers once everything read was handed
// out: a pooled raw input buffer goes back to the pool after a record that
// the small buffer holds, a small one is kept for the next record. c.in must
// be held.
//
// After a large record the pooled buffer stays: a transfer drains the conn
// after every record when its reader keeps up, and reading the next record's
// header into the small buffer would cost a second read per record.
func (c *Conn) releaseInput() {
	if c.input.Len() != 0 || c.rawInput.Len() != 0 {
		return
	}
	// c.input points into c.rawInput.
	c.input.Reset(nil)
	if c.rawInputPooled != nil && c.lastRecordLen+recordHeaderLen+bytes.MinRead <= rawInputSmallSize {
		c.putRawInput()
		// back to the small buffer, if there is one yet
		c.rawInput = *bytes.NewBuffer(c.rawInputSmall[:0])
		c.rawInputBuf = c.rawInputSmall
	} else {
		c.rawInput.Reset()
	}
}

// releaseHandshakeBuffers drops what only the handshake needed once it is
// complete and nothing is left to read: the handshake message buffer and the
// raw input. c.in must be held.
func (c *Conn) releaseHandshakeBuffers() {
	if c.hand.Len() == 0 {
		c.hand = bytes.Buffer{}
	}
	c.releaseInput()
}
