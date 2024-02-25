package internet

import (
	"context"
	"syscall"
	"time"

	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/session"
)

var (
	effectiveSystemDialer    SystemDialer = &DefaultSystemDialer{}
	effectiveSystemDNSDialer SystemDialer = &DefaultSystemDialer{}
)

type SystemDialer interface {
	Dial(ctx context.Context, source net.Address, destination net.Destination, sockopt *SocketConfig) (net.Conn, error)
}

type DefaultSystemDialer struct {
	controllers []controller
}

func resolveSrcAddr(network net.Network, src net.Address) net.Addr {
	if src == nil || src == net.AnyIP {
		return nil
	}

	if network == net.Network_TCP {
		return &net.TCPAddr{
			IP:   src.IP(),
			Port: 0,
		}
	}

	return &net.UDPAddr{
		IP:   src.IP(),
		Port: 0,
	}
}

func hasBindAddr(sockopt *SocketConfig) bool {
	return sockopt != nil && len(sockopt.BindAddress) > 0 && sockopt.BindPort > 0
}

func (d *DefaultSystemDialer) Dial(ctx context.Context, src net.Address, dest net.Destination, sockopt *SocketConfig) (net.Conn, error) {
	if dest.Network == net.Network_UDP && !hasBindAddr(sockopt) {
		srcAddr := resolveSrcAddr(net.Network_UDP, src)
		if srcAddr == nil {
			srcAddr = &net.UDPAddr{
				IP:   []byte{0, 0, 0, 0},
				Port: 0,
			}
		}
		packetConn, err := ListenSystemPacket(ctx, srcAddr, sockopt)
		if err != nil {
			return nil, err
		}
		destAddr, err := net.ResolveUDPAddr("udp", dest.NetAddr())
		if err != nil {
			return nil, err
		}
		if sockopt != nil {
			if rawConn, err := packetConn.(*net.UDPConn).SyscallConn(); err == nil {
				rawConn.Control(func(fd uintptr) {
					if err := applyOutboundSocketOptions("udp", dest.NetAddr(), fd, sockopt); err != nil {
						newError("failed to apply socket options").Base(err).WriteToLog(session.ExportIDToError(ctx))
					}
				})
			}
		}
		return &PacketConnWrapper{
			Conn: packetConn,
			Dest: destAddr,
		}, nil
	}
	goStdKeepAlive := time.Duration(0)
	if sockopt != nil && (sockopt.TcpKeepAliveInterval != 0 || sockopt.TcpKeepAliveIdle != 0) {
		goStdKeepAlive = time.Duration(-1)
	}
	dialer := &net.Dialer{
		Timeout:   time.Second * 16,
		LocalAddr: resolveSrcAddr(dest.Network, src),
		KeepAlive: goStdKeepAlive,
	}

	if sockopt != nil || len(d.controllers) > 0 {
		dialer.Control = func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if sockopt != nil {
					if err := applyOutboundSocketOptions(network, address, fd, sockopt); err != nil {
						newError("failed to apply socket options").Base(err).WriteToLog(session.ExportIDToError(ctx))
					}
					if dest.Network == net.Network_UDP && hasBindAddr(sockopt) {
						if err := bindAddr(fd, sockopt.BindAddress, sockopt.BindPort); err != nil {
							newError("failed to bind source address to ", sockopt.BindAddress).Base(err).WriteToLog(session.ExportIDToError(ctx))
						}
					}
				}

				for _, ctl := range d.controllers {
					if err := ctl(network, address, fd); err != nil {
						newError("failed to apply external controller").Base(err).WriteToLog(session.ExportIDToError(ctx))
					}
				}
			})
		}
	}

	return dialer.DialContext(ctx, dest.Network.SystemString(), dest.NetAddr())
}

func ApplySockopt(sockopt *SocketConfig, dest net.Destination, fd uintptr, ctx context.Context) {
	if err := applyOutboundSocketOptions(dest.Network.String(), dest.Address.String(), fd, sockopt); err != nil {
		newError("failed to apply socket options").Base(err).WriteToLog(session.ExportIDToError(ctx))
	}
	if dest.Network == net.Network_UDP && hasBindAddr(sockopt) {
		if err := bindAddr(fd, sockopt.BindAddress, sockopt.BindPort); err != nil {
			newError("failed to bind source address to ", sockopt.BindAddress).Base(err).WriteToLog(session.ExportIDToError(ctx))
		}
	}
}

type PacketConnWrapper struct {
	Conn net.PacketConn
	Dest net.Addr

	IPEndpoint     net.Addr
	DomainEndpoint *net.Destination
}

func (c *PacketConnWrapper) Close() error {
	return c.Conn.Close()
}

func (c *PacketConnWrapper) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

func (c *PacketConnWrapper) RemoteAddr() net.Addr {
	return c.Dest
}

func (c *PacketConnWrapper) Write(p []byte) (int, error) {
	return c.Conn.WriteTo(p, c.Dest)
}

func (c *PacketConnWrapper) Read(p []byte) (int, error) {
	n, _, err := c.Conn.ReadFrom(p)
	return n, err
}

func (c *PacketConnWrapper) WriteTo(p []byte, d net.Addr) (int, error) {
	return c.Conn.WriteTo(p, d)
}

func (c *PacketConnWrapper) ReadFrom(p []byte) (int, net.Addr, error) {
	return c.Conn.ReadFrom(p)
}

func (c *PacketConnWrapper) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

func (c *PacketConnWrapper) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

func (c *PacketConnWrapper) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

type SystemDialerAdapter interface {
	Dial(network string, address string) (net.Conn, error)
}

type SimpleSystemDialer struct {
	adapter SystemDialerAdapter
}

func WithAdapter(dialer SystemDialerAdapter) SystemDialer {
	return &SimpleSystemDialer{
		adapter: dialer,
	}
}

func (v *SimpleSystemDialer) Dial(ctx context.Context, src net.Address, dest net.Destination, sockopt *SocketConfig) (net.Conn, error) {
	return v.adapter.Dial(dest.Network.SystemString(), dest.NetAddr())
}

// UseAlternativeSystemDialer replaces the current system dialer with a given one.
// Caller must ensure there is no race condition.
//
// v2ray:api:stable
func UseAlternativeSystemDialer(dialer SystemDialer) {
	if dialer == nil {
		dialer = &DefaultSystemDialer{}
	}
	effectiveSystemDialer = dialer
}

// SagerNet private
func UseAlternativeSystemDNSDialer(dialer SystemDialer) {
	if dialer == nil {
		dialer = &DefaultSystemDialer{}
	}
	effectiveSystemDNSDialer = dialer
}

// RegisterDialerController adds a controller to the effective system dialer.
// The controller can be used to operate on file descriptors before they are put into use.
// It only works when effective dialer is the default dialer.
//
// v2ray:api:beta
func RegisterDialerController(ctl func(network, address string, fd uintptr) error) error {
	if ctl == nil {
		return newError("nil listener controller")
	}

	dialer, ok := effectiveSystemDialer.(*DefaultSystemDialer)
	if !ok {
		return newError("RegisterListenerController not supported in custom dialer")
	}

	dialer.controllers = append(dialer.controllers, ctl)
	return nil
}
