package tls

import (
	"context"

	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/transport/internet/security"
)

type Engine struct {
	ctx    context.Context
	config *Config
}

func (e *Engine) Client(conn net.Conn, opts ...security.Option) (security.Conn, error) {
	var options []Option
	for _, v := range opts {
		switch s := v.(type) {
		case security.OptionWithALPN:
			options = append(options, WithNextProto(s.ALPNs...))
		case security.OptionWithDestination:
			options = append(options, WithDestination(s.Dest))
		default:
			return nil, newError("unknown option")
		}
	}
	var tlsConn net.Conn
	customClient, loaded := CustomClientFromContext(e.ctx)
	if loaded {
		tlsConn = customClient(conn, e.config.GetTLSConfig(options...))
	} else {
		tlsConn = Client(conn, e.config.GetTLSConfig(options...))
	}
	return tlsConn, nil
}

func NewTLSSecurityEngineFromConfig(ctx context.Context, config *Config) (security.Engine, error) {
	return &Engine{ctx: ctx, config: config}, nil
}
