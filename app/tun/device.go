package tun

import (
	"io"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type Device interface {
	Name() (string, error)
	SetAddress() error
	SetRoute() error
	MTU() (int, error)
	SetMTU(mtu int) error
	io.Reader
	ReadBuffer() (*stack.PacketBuffer, error)
	StopRead()
	io.Writer
	WriteBuffer(buffer *stack.PacketBuffer) error
	WriteBuffers(buffers []*stack.PacketBuffer) (int, error)
	io.Closer
}
