//go:build !confonly
// +build !confonly

package grpc

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/session"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
	"github.com/v2fly/v2ray-core/v5/transport/internet/grpc/encoding"
	"github.com/v2fly/v2ray-core/v5/transport/internet/tls"
)

type Listener struct {
	encoding.UnimplementedGunServiceServer
	ctx     context.Context
	handler internet.ConnHandler
	local   net.Addr
	config  *Config

	s *grpc.Server
}

func (l Listener) Tun(server encoding.GunService_TunServer) error {
	tunCtx, cancel := context.WithCancel(l.ctx)
	gunConn := encoding.NewGunConn(server, cancel)
	var remoteAddr net.Addr
	md, ok := metadata.FromIncomingContext(server.Context())
	if ok && l.config.AcceptXForwardFor {
		if addr := ParseXForwardFor(md); addr != nil {
			remoteAddr = addr
		}
	}
	if ok && l.config.AcceptXRealIP {
		if addr := ParseXRealIP(md); addr != nil {
			remoteAddr = addr
		}
	}
	if remoteAddr != nil {
		gunConn.SetRemoteAddr(remoteAddr)
	}
	l.handler(gunConn)
	<-tunCtx.Done()
	return nil
}

func (l Listener) Close() error {
	l.s.Stop()
	return nil
}

func (l Listener) Addr() net.Addr {
	return l.local
}

func Listen(ctx context.Context, address net.Address, port net.Port, settings *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
	grpcSettings := settings.ProtocolSettings.(*Config)
	var listener *Listener
	if port == net.Port(0) { // unix
		listener = &Listener{
			handler: handler,
			local: &net.UnixAddr{
				Name: address.Domain(),
				Net:  "unix",
			},
			config: grpcSettings,
		}
	} else { // tcp
		listener = &Listener{
			handler: handler,
			local: &net.TCPAddr{
				IP:   address.IP(),
				Port: int(port),
			},
			config: grpcSettings,
		}
	}

	listener.ctx = ctx

	config := tls.ConfigFromStreamSettings(settings)

	var s *grpc.Server
	if config == nil {
		s = grpc.NewServer()
	} else {
		// gRPC server may silently ignore TLS errors
		s = grpc.NewServer(grpc.Creds(credentials.NewTLS(config.GetTLSConfig(tls.WithNextProto("h2")))))
	}
	listener.s = s

	if settings.SocketSettings != nil && settings.SocketSettings.AcceptProxyProtocol {
		newError("accepting PROXY protocol").AtWarning().WriteToLog(session.ExportIDToError(ctx))
	}

	go func() {
		var streamListener net.Listener
		var err error
		if port == net.Port(0) { // unix
			streamListener, err = internet.ListenSystem(ctx, &net.UnixAddr{
				Name: address.Domain(),
				Net:  "unix",
			}, settings.SocketSettings)
			if err != nil {
				newError("failed to listen on ", address).Base(err).AtError().WriteToLog(session.ExportIDToError(ctx))
				return
			}
		} else { // tcp
			streamListener, err = internet.ListenSystem(ctx, &net.TCPAddr{
				IP:   address.IP(),
				Port: int(port),
			}, settings.SocketSettings)
			if err != nil {
				newError("failed to listen on ", address, ":", port).Base(err).AtError().WriteToLog(session.ExportIDToError(ctx))
				return
			}
		}

		encoding.RegisterGunServiceServerX(s, listener, grpcSettings.ServiceName)

		if err = s.Serve(streamListener); err != nil {
			newError("Listener for grpc ended").Base(err).WriteToLog()
		}
	}()

	return listener, nil
}

func ParseXRealIP(md metadata.MD) net.Addr {
	xri := md.Get("X-Real-IP")
	if len(xri) == 0 {
		return nil
	}
	if addr := net.ParseAddress(xri[0]); addr.Family().IsIP() {
		return &net.TCPAddr{
			IP:   addr.IP(),
			Port: int(0),
		}
	}
	return nil
}

func ParseXForwardFor(md metadata.MD) net.Addr {
	xff := md.Get("X-Forwarded-For")
	if len(xff) == 0 {
		return nil
	}
	list := strings.Split(xff[0], ",")
	if len(list) == 0 {
		return nil
	}
	if addr := net.ParseAddress(list[len(list)-1]); addr.Family().IsIP() {
		return &net.TCPAddr{
			IP:   addr.IP(),
			Port: int(0),
		}
	}
	return nil
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, Listen))
}
