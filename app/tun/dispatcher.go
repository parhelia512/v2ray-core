package tun

import (
	"context"
	"io"
	"time"

	"github.com/v2fly/v2ray-core/v4/common"
	"github.com/v2fly/v2ray-core/v4/common/buf"
	"github.com/v2fly/v2ray-core/v4/common/net"
	"github.com/v2fly/v2ray-core/v4/common/protocol/udp"
	"github.com/v2fly/v2ray-core/v4/common/signal"
	"github.com/v2fly/v2ray-core/v4/features/routing"
	"github.com/v2fly/v2ray-core/v4/transport"
)

func dispatchUDP(ctx context.Context, dispatcher routing.Dispatcher, destination net.Destination, timeout time.Duration) (packetConn, error) {
	ctx, cancel := context.WithCancel(ctx)
	link, err := dispatcher.Dispatch(ctx, destination)
	if err != nil {
		cancel()
		return nil, err
	}
	c := &dispatcherConn{
		dest:   destination,
		link:   link,
		ctx:    ctx,
		cancel: cancel,
		cache:  make(chan *udp.Packet, 16),
	}
	c.timer = signal.CancelAfterInactivity(ctx, func() { c.Close() }, timeout)
	go c.handleInput()
	return c, nil
}

type packetConn interface {
	net.PacketConn
	readFrom() (p []byte, addr net.Addr, err error)
}

var _ packetConn = (*dispatcherConn)(nil)

type dispatcherConn struct {
	dest  net.Destination
	link  *transport.Link
	timer *signal.ActivityTimer

	ctx    context.Context
	cancel context.CancelFunc

	cache chan *udp.Packet
}

func (c *dispatcherConn) handleInput() {
	defer c.Close()
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		mb, err := c.link.Reader.ReadMultiBuffer()
		if err != nil {
			buf.ReleaseMulti(mb)
			return
		}
		c.timer.Update()
		for _, buffer := range mb {
			packet := udp.Packet{
				Payload: buffer,
			}
			if buffer.Endpoint == nil {
				packet.Source = c.dest
			} else {
				packet.Source = *buffer.Endpoint
			}
			select {
			case c.cache <- &packet:
				continue
			case <-c.ctx.Done():
			default:
			}
			buffer.Release()
		}
	}
}

func (c *dispatcherConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case <-c.ctx.Done():
		return 0, nil, io.EOF
	case packet := <-c.cache:
		n := copy(p, packet.Payload.Bytes())
		return n, &net.UDPAddr{
			IP:   packet.Source.Address.IP(),
			Port: int(packet.Source.Port),
		}, nil
	}
}

func (c *dispatcherConn) readFrom() (p []byte, addr net.Addr, err error) {
	select {
	case <-c.ctx.Done():
		return nil, nil, io.EOF
	case packet := <-c.cache:
		return packet.Payload.Bytes(), &net.UDPAddr{
			IP:   packet.Source.Address.IP(),
			Port: int(packet.Source.Port),
		}, nil
	}
}

func (c *dispatcherConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	buffer := buf.FromBytes(p)
	endpoint := net.DestinationFromAddr(addr)
	buffer.Endpoint = &endpoint
	err = c.link.Writer.WriteMultiBuffer(buf.MultiBuffer{buffer})
	if err == nil {
		c.timer.Update()
	}
	return
}

func (c *dispatcherConn) LocalAddr() net.Addr {
	return &net.UDPAddr{
		IP:   []byte{0, 0, 0, 0},
		Port: 0,
	}
}

func (c *dispatcherConn) Close() error {
	select {
	case <-c.ctx.Done():
		return nil
	default:
	}

	c.cancel()
	_ = common.Interrupt(c.link.Reader)
	_ = common.Interrupt(c.link.Writer)
	close(c.cache)

	return nil
}

func (c *dispatcherConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *dispatcherConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *dispatcherConn) SetWriteDeadline(t time.Time) error {
	return nil
}
