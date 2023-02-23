package shadowtls

import (
	"context"
	gotls "crypto/tls"
	"os"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
	"github.com/v2fly/v2ray-core/v5/transport/internet/tls"
)

type v2rayTLSDialer struct {
	dialer     internet.Dialer
	clientFunc tls.CustomClientFunc
}

func newTLSDialer(dialer internet.Dialer, clientFunc tls.CustomClientFunc) *v2rayTLSDialer {
	return &v2rayTLSDialer{dialer, clientFunc}
}

func (d *v2rayTLSDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	var tlsConfig *gotls.Config
	conn, err := d.dialer.Dial(tls.ContextWithCustomClient(ctx, func(conn net.Conn, config *gotls.Config) net.Conn {
		tlsConfig = config
		return conn
	}), toDestination(destination, toNetwork(network)))
	if err != nil {
		return nil, err
	}
	if tlsConfig == nil {
		return nil, E.New("missing TLS config")
	}
	return d.clientFunc(conn, tlsConfig), nil
}

func (d *v2rayTLSDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}
