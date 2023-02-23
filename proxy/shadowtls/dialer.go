package shadowtls

import (
	"context"
	"os"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
)

var _ N.Dialer = (*v2rayDialer)(nil)

type v2rayDialer struct {
	dialer internet.Dialer
}

func newDialer(dialer internet.Dialer) *v2rayDialer {
	return &v2rayDialer{dialer}
}

func (d *v2rayDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.dialer.Dial(ctx, toDestination(destination, toNetwork(network)))
}

func (d *v2rayDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}
