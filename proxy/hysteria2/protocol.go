package hysteria2

import (
	"io"
	"math/rand"

	hyProtocol "github.com/apernet/hysteria/core/v2/international/protocol"
	"github.com/apernet/quic-go/quicvarint"

	"github.com/v2fly/v2ray-core/v5/common/buf"
	"github.com/v2fly/v2ray-core/v5/common/net"
	hyTransport "github.com/v2fly/v2ray-core/v5/transport/internet/hysteria2"
)

const (
	paddingChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

// ConnWriter is TCP Connection Writer Wrapper
type ConnWriter struct {
	io.Writer
	Target        net.Destination
	Account       *MemoryAccount
	TCPHeaderSent bool
}

// Write implements io.Writer
func (c *ConnWriter) Write(p []byte) (n int, err error) {
	if !c.TCPHeaderSent {
		if err := c.writeTCPHeader(); err != nil {
			return 0, newError("failed to write request header").Base(err)
		}
	}

	return c.Writer.Write(p)
}

// WriteMultiBuffer implements buf.Writer
func (c *ConnWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)

	for _, b := range mb {
		if !b.IsEmpty() {
			if _, err := c.Write(b.Bytes()); err != nil {
				return err
			}
		}
	}

	return nil
}

func (c *ConnWriter) WriteTCPHeader() error {
	if !c.TCPHeaderSent {
		if err := c.writeTCPHeader(); err != nil {
			return err
		}
	}
	return nil
}

func (c *ConnWriter) writeTCPHeader() error {
	c.TCPHeaderSent = true

	paddingLen := 64 + rand.Intn(512-64)
	padding := make([]byte, paddingLen)
	for i := range padding {
		padding[i] = paddingChars[rand.Intn(len(paddingChars))]
	}
	addressAndPort := c.Target.NetAddr()
	addressLen := len(addressAndPort)

	if quicvarint.Len(uint64(addressLen))+addressLen > hyProtocol.MaxAddressLength {
		return newError("invalid header length")
	}

	buf := make([]byte, quicvarint.Len(uint64(addressLen))+addressLen+quicvarint.Len(uint64(paddingLen))+paddingLen)
	i := hyProtocol.VarintPut(buf, uint64(addressLen))
	i += copy(buf[i:], addressAndPort)
	i += hyProtocol.VarintPut(buf[i:], uint64(paddingLen))
	copy(buf[i:], padding)

	_, err := c.Writer.Write(buf)
	return err
}

// PacketWriter UDP Connection Writer Wrapper
type PacketWriter struct {
	io.Writer
	HyConn *hyTransport.HyConn
	Target net.Destination
}

// WriteMultiBuffer implements buf.Writer
func (w *PacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for _, b := range mb {
		if b.IsEmpty() {
			continue
		}
		target := &w.Target
		if b.Endpoint != nil {
			target = b.Endpoint
		}
		if _, err := w.writePacket(b.Bytes(), *target); err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
	}

	return nil
}

// WriteMultiBufferWithMetadata writes udp packet with destination specified
func (w *PacketWriter) WriteMultiBufferWithMetadata(mb buf.MultiBuffer, dest net.Destination) error {
	for _, b := range mb {
		if b.IsEmpty() {
			continue
		}
		if _, err := w.writePacket(b.Bytes(), dest); err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
	}

	return nil
}

func (w *PacketWriter) WriteTo(payload []byte, addr net.Addr) (int, error) {
	dest := net.DestinationFromAddr(addr)

	return w.writePacket(payload, dest)
}

func (w *PacketWriter) writePacket(payload []byte, dest net.Destination) (int, error) {
	return w.HyConn.WritePacket(payload, dest)
}

// ConnReader is TCP Connection Reader Wrapper
type ConnReader struct {
	io.Reader
}

// Read implements io.Reader
func (c *ConnReader) Read(p []byte) (int, error) {
	return c.Reader.Read(p)
}

// ReadMultiBuffer implements buf.Reader
func (c *ConnReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b := buf.New()
	_, err := b.ReadFrom(c)
	if err != nil {
		return nil, err
	}
	return buf.MultiBuffer{b}, nil
}

// PacketPayload combines udp payload and destination
type PacketPayload struct {
	Target net.Destination
	Buffer buf.MultiBuffer
}

// PacketReader is UDP Connection Reader Wrapper
type PacketReader struct {
	io.Reader
	HyConn *hyTransport.HyConn
}

// ReadMultiBuffer implements buf.Reader
func (r *PacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	p, err := r.ReadMultiBufferWithMetadata()
	if err != nil {
		return nil, err
	}
	return p.Buffer, nil
}

// ReadMultiBufferWithMetadata reads udp packet with destination
func (r *PacketReader) ReadMultiBufferWithMetadata() (*PacketPayload, error) {
	_, data, dest, err := r.HyConn.ReadPacket()
	if err != nil {
		return nil, err
	}
	b := buf.FromBytes(data)
	b.Endpoint = dest
	return &PacketPayload{Target: *dest, Buffer: buf.MultiBuffer{b}}, nil
}
