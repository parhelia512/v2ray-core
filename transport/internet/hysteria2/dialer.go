package hysteria2

import (
	"context"

	hy_client "github.com/apernet/hysteria/core/client"
	hyProtocol "github.com/apernet/hysteria/core/international/protocol"
	"github.com/apernet/quic-go/quicvarint"

	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/session"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
	"github.com/v2fly/v2ray-core/v5/transport/internet/tls"
)

const (
	FrameTypeTCPRequest = 0x401
)

var RunningClient map[net.Destination](hy_client.Client)

func initTLSConfig(streamSettings *internet.MemoryStreamConfig) *hy_client.TLSConfig {
	tlsSetting := checkTLSConfig(streamSettings, true)
	if tlsSetting == nil {
		tlsSetting = &tls.Config{
			ServerName:    internalDomain,
			AllowInsecure: true,
		}
	}
	res := &hy_client.TLSConfig{
		ServerName:         tlsSetting.ServerName,
		InsecureSkipVerify: tlsSetting.AllowInsecure,
	}
	return res
}

func initAddress(dest net.Destination) (net.Addr, error) {
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
	return destAddr, nil
}

type connFactory struct {
	NewFunc    func(addr net.Addr) (net.PacketConn, error)
	Obfuscator Obfuscator
}

func (f *connFactory) New(addr net.Addr) (net.PacketConn, error) {
	return f.NewFunc(addr)
}

func NewHyClient(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (hy_client.Client, error) {
	tlsConfig := initTLSConfig(streamSettings)

	serverAddr, err := initAddress(dest)
	if err != nil {
		return nil, err
	}

	config := streamSettings.ProtocolSettings.(*Config)
	hyConfig := &hy_client.Config{
		TLSConfig:  *tlsConfig,
		Auth:       config.GetPassword(),
		ServerAddr: serverAddr,
	}

	connFactory := &connFactory{
		NewFunc: func(addr net.Addr) (net.PacketConn, error) {
			rawConn, err := internet.DialSystem(ctx, net.DestinationFromAddr(addr), streamSettings.SocketSettings)
			if err != nil {
				return nil, newError("failed to dial to dest: ", err).AtWarning().Base(err)
			}
			var udpConn *net.UDPConn
			switch conn := rawConn.(type) {
			case *net.UDPConn:
				udpConn = conn
			case *internet.PacketConnWrapper:
				udpConn = conn.Conn.(*net.UDPConn)
			default:
				rawConn.Close()
				return nil, newError("QUIC with sockopt is unsupported").AtWarning()
			}
			return udpConn, nil
		},
	}
	if config.Obfs != nil && config.Obfs.Type == "salamander" {
		ob, err := NewSalamanderObfuscator([]byte(config.Obfs.Password))
		if err != nil {
			return nil, err
		}
		connFactory.Obfuscator = ob
	}
	hyConfig.ConnFactory = connFactory

	client, _, err := hy_client.NewClient(hyConfig)
	if err != nil {
		return nil, err
	}

	RunningClient[dest] = client
	return client, nil
}

func CloseHyClient(dest net.Destination) error {
	client, found := RunningClient[dest]
	if found {
		delete(RunningClient, dest)
		return client.Close()
	}
	return nil
}

func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (internet.Connection, error) {
	config := streamSettings.ProtocolSettings.(*Config)

	var client hy_client.Client
	var err error
	client, found := RunningClient[dest]
	if !found {
		// TODO: Clean idle connections
		client, err = NewHyClient(ctx, dest, streamSettings)
		if err != nil {
			return nil, err
		}
	}

	quicConn := client.GetQuicConn()
	conn := &HyConn{
		local:  quicConn.LocalAddr(),
		remote: quicConn.RemoteAddr(),
	}

	outbound := session.OutboundFromContext(ctx)
	network := net.Network_TCP
	if outbound != nil {
		network = outbound.Target.Network
		conn.Target = outbound.Target
	}

	if network == net.Network_UDP && config.GetUseUdpExtension() { // only hysteria2 can use udpExtension
		conn.IsUDPExtension = true
		conn.IsServer = false
		conn.ClientUDPSession, err = client.UDP()
		if err != nil {
			CloseHyClient(dest)
			return nil, err
		}
		return conn, nil
	}

	conn.stream, err = client.OpenStream()
	if err != nil {
		CloseHyClient(dest)
		return nil, err
	}

	// write TCP frame type
	frameSize := int(quicvarint.Len(FrameTypeTCPRequest))
	buf := make([]byte, frameSize)
	hyProtocol.VarintPut(buf, FrameTypeTCPRequest)
	conn.stream.Write(buf)
	return conn, nil
}

func init() {
	RunningClient = make(map[net.Destination]hy_client.Client)
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}
