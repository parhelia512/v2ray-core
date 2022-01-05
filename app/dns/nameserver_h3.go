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
			var destAddr *net.UDPAddr
			if dest.Address.Family().IsIP() {
				destAddr = &net.UDPAddr{
					IP:   dest.Address.IP(),
					Port: int(dest.Port),
				}
			} else {
				addr, err := net.ResolveUDPAddr("udp", dest.NetAddr())
				if err != nil {
					return nil, err
				}
				destAddr = addr
			}
			tr := quic.Transport{
				Conn: &connWrapper{conn, destAddr},
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
			conn, err := internet.DialSystemDNS(ctx, dest, nil)
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

type connWrapper struct {
	net.Conn
	addr net.Addr
}

func (c *connWrapper) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = c.Read(p)
	if err == nil {
		addr = c.addr
	}
	return
}

func (c *connWrapper) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	return c.Write(p)
}

func (c *connWrapper) LocalAddr() net.Addr {
	// https://github.com/quic-go/quic-go/commit/8189e75be6121fdc31dc1d6085f17015e9154667#diff-4c6aaadced390f3ce9bec0a9c9bb5203d5fa85df79023e3e0eec423dc9baa946R48-R62
	uuid := uuid.New()
	return &net.UnixAddr{Name: uuid.String()}
}
