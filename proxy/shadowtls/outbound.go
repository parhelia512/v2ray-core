package shadowtls

import (
	"context"
	"crypto/tls"

	shadowtls "github.com/sagernet/sing-shadowtls"

	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/session"
	"github.com/v2fly/v2ray-core/v5/transport"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
)

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}

type Outbound struct {
	ctx          context.Context
	clientConfig shadowtls.ClientConfig
}

func NewClient(ctx context.Context, config *ClientConfig) (*Outbound, error) {
	return &Outbound{
		ctx: ctx,
		clientConfig: shadowtls.ClientConfig{
			Version:  int(config.Version),
			Password: config.Password,
			Server: toSocksaddr(net.Destination{
				Address: config.Address.AsAddress(),
				Port:    net.Port(config.Port),
			}),
			Logger: newLogger(newError),
		},
	}, nil
}

func (o *Outbound) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbound := session.OutboundFromContext(ctx)
	if outbound == nil || !outbound.Target.IsValid() {
		return newError("target not specified")
	}
	destination := outbound.Target

	if destination.Network != net.Network_TCP {
		return newError("only TCP is supported")
	}

	newError("tunneling request to ", destination, " via ", o.clientConfig.Server).WriteToLog(session.ExportIDToError(ctx))

	var client *shadowtls.Client
	clientConfig := o.clientConfig
	clientConfig.Dialer = newTLSDialer(dialer, func(conn net.Conn, config *tls.Config) net.Conn {
		client.SetHandshakeFunc(shadowtls.DefaultTLSHandshakeFunc(clientConfig.Password, config))
		return conn
	})
	var err error
	client, err = shadowtls.NewClient(clientConfig)
	if err != nil {
		return newError("failed to create client").Base(err)
	}

	conn, err := client.DialContext(ctx)
	if err != nil {
		return newError("failed to connect to server").Base(err)
	}

	return copyConn(ctx, link, conn)
}
