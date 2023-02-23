package shadowtls

import (
	"context"
	"io"
	"net"

	"github.com/sagernet/sing/common/bufio"

	"github.com/v2fly/v2ray-core/v5/common/buf"
	"github.com/v2fly/v2ray-core/v5/transport"
)

func copyConn(ctx context.Context, link *transport.Link, serverConn net.Conn) error {
	conn := &pipeConnWrapper{
		W: link.Writer,
	}
	if ir, ok := link.Reader.(io.Reader); ok {
		conn.R = ir
	} else {
		conn.R = &buf.BufferedReader{Reader: link.Reader}
	}
	return returnError(bufio.CopyConn(ctx, conn, serverConn))
}

type pipeConnWrapper struct {
	R io.Reader
	W buf.Writer
	net.Conn
}

func (w *pipeConnWrapper) Close() error {
	return nil
}

func (w *pipeConnWrapper) Read(b []byte) (n int, err error) {
	return w.R.Read(b)
}

func (w *pipeConnWrapper) Write(p []byte) (n int, err error) {
	n = len(p)
	var mb buf.MultiBuffer
	pLen := len(p)
	for pLen > 0 {
		buffer := buf.New()
		if pLen > buf.Size {
			_, err = buffer.Write(p[:buf.Size])
			p = p[buf.Size:]
		} else {
			buffer.Write(p)
		}
		pLen -= int(buffer.Len())
		mb = append(mb, buffer)
	}
	err = w.W.WriteMultiBuffer(mb)
	if err != nil {
		n = 0
		buf.ReleaseMulti(mb)
	}
	return
}
