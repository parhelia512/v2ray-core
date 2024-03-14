package internet

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/database64128/tfo-go/v2"
)

var errInvalid = newError("invalid")

type tfoConn struct {
	dialer      *tfo.Dialer
	ctx         context.Context
	network     string
	destination string
	conn        net.Conn
	create      chan struct{}
	access      sync.Mutex
	err         error
}

func DialTFOContext(dialer *tfo.Dialer, ctx context.Context, network string, destination string) (net.Conn, error) {
	if dialer.DisableTFO {
		return dialer.Dialer.DialContext(ctx, network, destination)
	}
	return &tfoConn{
		dialer:      dialer,
		ctx:         ctx,
		network:     network,
		destination: destination,
		create:      make(chan struct{}),
	}, nil
}

func (c *tfoConn) Read(b []byte) (n int, err error) {
	if c.conn == nil {
		select {
		case <-c.create:
			if c.err != nil {
				return 0, c.err
			}
		case <-c.ctx.Done():
			return 0, c.ctx.Err()
		}
	}
	return c.conn.Read(b)
}

func (c *tfoConn) Write(b []byte) (n int, err error) {
	if c.conn != nil {
		return c.conn.Write(b)
	}
	c.access.Lock()
	defer c.access.Unlock()
	select {
	case <-c.create:
		if c.err != nil {
			return 0, c.err
		}
		return c.conn.Write(b)
	default:
	}
	c.conn, err = c.dialer.DialContext(c.ctx, c.network, c.destination, b)
	if err != nil {
		c.conn = nil
		c.err = err
	}
	n = len(b)
	close(c.create)
	return
}

func (c *tfoConn) Close() error {
	if c.conn == nil {
		return errInvalid
	}
	return c.conn.Close()
}

func (c *tfoConn) LocalAddr() net.Addr {
	if c.conn == nil {
		return nil
	}
	return c.conn.LocalAddr()
}

func (c *tfoConn) RemoteAddr() net.Addr {
	if c.conn == nil {
		return nil
	}
	return c.conn.RemoteAddr()
}

func (c *tfoConn) SetDeadline(t time.Time) error {
	if c.conn == nil {
		return errInvalid
	}
	return c.conn.SetDeadline(t)
}

func (c *tfoConn) SetReadDeadline(t time.Time) error {
	if c.conn == nil {
		return errInvalid
	}
	return c.conn.SetReadDeadline(t)
}

func (c *tfoConn) SetWriteDeadline(t time.Time) error {
	if c.conn == nil {
		return errInvalid
	}
	return c.conn.SetWriteDeadline(t)
}
