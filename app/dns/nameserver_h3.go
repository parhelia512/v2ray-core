package dns

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/net/cnc"
	"github.com/v2fly/v2ray-core/v5/common/uuid"
	"github.com/v2fly/v2ray-core/v5/features/routing"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
)

// NewH3NameServer creates DOH server object for remote resolving.
func NewH3NameServer(url *url.URL, dispatcher routing.Dispatcher) (*DoHNameServer, error) {
	url.Scheme = "https"
	s := baseDOHNameServer(url, "H3", "quic")
	tr := &http3.RoundTripper{
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			dest, err := net.ParseDestination("udp:" + addr)
			if err != nil {
				return nil, err
			}
			link, err := dispatcher.Dispatch(ctx, dest)
			if err != nil {
				return nil, err
			}
			conn := cnc.NewConnection(
				cnc.ConnectionInputMulti(link.Writer),
				cnc.ConnectionOutputMultiUDP(link.Reader),
			)
			netAddr := &netAddrWrapper{network: "udp", dest: addr}
			tr := quic.Transport{
				Conn: &packetConnWrapper{conn, netAddr},
			}
			return tr.DialEarly(ctx, conn.RemoteAddr(), tlsCfg, cfg)
		},
	}
	dispatchedClient := &http.Client{
		Transport: tr,
		Timeout:   180 * time.Second,
	}

	s.httpClient = dispatchedClient
	newError("DNS: created Remote H3 client for ", url.String()).AtInfo().WriteToLog()
	return s, nil
}

// NewH3LocalNameServer creates H3 client object for local resolving
func NewH3LocalNameServer(url *url.URL) *DoHNameServer {
	url.Scheme = "https"
	s := baseDOHNameServer(url, "H3L", "quic")
	tr := &http3.RoundTripper{
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			dest, err := net.ParseDestination("udp:" + addr)
			if err != nil {
				return nil, err
			}
			conn, err := internet.DialSystem(ctx, dest, nil)
			if err != nil {
				return nil, err
			}
			tr := quic.Transport{
				Conn: conn.(*internet.PacketConnWrapper).Conn.(*net.UDPConn),
			}
			return tr.DialEarly(ctx, conn.RemoteAddr(), tlsCfg, cfg)
		},
	}
	s.httpClient = &http.Client{
		Timeout:   time.Second * 180,
		Transport: tr,
	}
	newError("DNS: created Local H3 client for ", url.String()).AtInfo().WriteToLog()
	return s
}

type netAddrWrapper struct {
	network string
	dest    string
}

func (a *netAddrWrapper) Network() string {
	return a.network
}

func (a *netAddrWrapper) String() string {
	return a.dest
}

type packetConnWrapper struct {
	net.Conn
	addr net.Addr
}

func (c *packetConnWrapper) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = c.Read(p)
	if err == nil {
		addr = c.addr
	}
	return
}

func (c *packetConnWrapper) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	return c.Write(p)
}

func (c *packetConnWrapper) LocalAddr() net.Addr {
	// https://github.com/quic-go/quic-go/commit/8189e75be6121fdc31dc1d6085f17015e9154667#diff-4c6aaadced390f3ce9bec0a9c9bb5203d5fa85df79023e3e0eec423dc9baa946R48-R62
	// quic-go says that it will remove this check one year later https://github.com/quic-go/quic-go/pull/4079 (September 11th, 2023)
	uuid := uuid.New()
	return &net.UnixAddr{Name: uuid.String()}
}
