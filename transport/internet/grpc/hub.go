//go:build !confonly
// +build !confonly

package grpc

import (
	"context"

	goreality "github.com/xtls/reality"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/session"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
	"github.com/v2fly/v2ray-core/v5/transport/internet/grpc/encoding"
	"github.com/v2fly/v2ray-core/v5/transport/internet/reality"
	"github.com/v2fly/v2ray-core/v5/transport/internet/tls"
)

var _ encoding.GunServiceServer = (*Listener)(nil)

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
	l.handler(encoding.NewGunConn(server, cancel))
	<-tunCtx.Done()
	return nil
}

func (l Listener) TunMulti(server encoding.GunService_TunMultiServer) error {
	conn, done := encoding.NewMultiConn(server)
	l.handler(conn)
	<-done
	return nil
}

func (l Listener) HandleConn(connection internet.Connection) {
	l.handler(connection)
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
	realityConfig := reality.ConfigFromStreamSettings(settings)

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

		if realityConfig != nil {
			streamListener = goreality.NewListener(streamListener, realityConfig.GetREALITYConfig())
		}

		if err = s.Serve(streamListener); err != nil {
			newError("Listener for grpc ended").Base(err).WriteToLog()
		}
	}()

	return listener, nil
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, Listen))
}
