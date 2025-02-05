package quic

import (
	"context"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/task"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
	"github.com/v2fly/v2ray-core/v5/transport/internet/tls"
)

type connectionContext struct {
	rawConn *sysConn
	conn    quic.EarlyConnection
}

var errConnectionClosed = newError("connection closed")

func (c *connectionContext) openStream(destAddr net.Addr) (*interConn, error) {
	if !isActive(c.conn) {
		return nil, errConnectionClosed
	}

	stream, err := c.conn.OpenStream()
	if err != nil {
		return nil, err
	}

	conn := &interConn{
		stream: stream,
		local:  c.conn.LocalAddr(),
		remote: destAddr,
	}

	return conn, nil
}

type dialerConf struct {
	net.Destination
	*internet.MemoryStreamConfig
}

type clientConnections struct {
	access  sync.Mutex
	conns   map[dialerConf][]*connectionContext
	cleanup *task.Periodic
}

func isActive(s quic.EarlyConnection) bool {
	select {
	case <-s.Context().Done():
		return false
	default:
		return true
	}
}

func removeInactiveConnections(conns []*connectionContext) []*connectionContext {
	activeConnections := make([]*connectionContext, 0, len(conns))
	for _, s := range conns {
		if isActive(s.conn) {
			activeConnections = append(activeConnections, s)
			continue
		}
		if err := s.conn.CloseWithError(0, ""); err != nil {
			newError("failed to close connection").Base(err).WriteToLog()
		}
		if err := s.rawConn.Close(); err != nil {
			newError("failed to close raw connection").Base(err).WriteToLog()
		}
	}

	if len(activeConnections) < len(conns) {
		return activeConnections
	}

	return conns
}

func openStream(conns []*connectionContext, destAddr net.Addr) *interConn {
	for _, s := range conns {
		if !isActive(s.conn) {
			continue
		}

		conn, err := s.openStream(destAddr)
		if err != nil {
			continue
		}

		return conn
	}

	return nil
}

func (s *clientConnections) cleanConnections() error {
	s.access.Lock()
	defer s.access.Unlock()

	if len(s.conns) == 0 {
		return nil
	}

	newConnMap := make(map[dialerConf][]*connectionContext)

	for dialerConf, conns := range s.conns {
		conns = removeInactiveConnections(conns)
		if len(conns) > 0 {
			newConnMap[dialerConf] = conns
		}
	}

	s.conns = newConnMap
	return nil
}

func (s *clientConnections) openConnection(ctx context.Context, destAddr net.Addr, streamSettings *internet.MemoryStreamConfig) (internet.Connection, error) {
	s.access.Lock()
	defer s.access.Unlock()

	if s.conns == nil {
		s.conns = make(map[dialerConf][]*connectionContext)
	}

	dest := net.DestinationFromAddr(destAddr)

	var conns []*connectionContext
	if s, found := s.conns[dialerConf{dest, streamSettings}]; found {
		conns = s
	}

	{
		conn := openStream(conns, destAddr)
		if conn != nil {
			return conn, nil
		}
	}

	conns = removeInactiveConnections(conns)

	newError("dialing QUIC to ", dest).WriteToLog()

	rawConn, err := internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
	if err != nil {
		return nil, newError("failed to dial to dest: ", err).AtWarning().Base(err)
	}

	quicConfig := &quic.Config{
		HandshakeIdleTimeout: time.Second * 8,
		MaxIdleTimeout:       time.Second * 30,
		KeepAlivePeriod:      time.Second * 15,
	}

	var packetConn net.PacketConn
	switch conn := rawConn.(type) {
	case *net.UDPConn:
		packetConn = conn
	case *internet.PacketConnWrapper:
		if c, ok := conn.Conn.(*net.UDPConn); ok {
			packetConn = c
		} else {
			packetConn = conn.Conn
		}
	case net.PacketConn:
		packetConn = conn
	default:
		rawConn.Close()
		return nil, newError("neither a *net.UDPConn nor a net.PacketConn").AtWarning()
	}

	sysConn, err := wrapSysConn(packetConn, streamSettings.ProtocolSettings.(*Config))
	if err != nil {
		rawConn.Close()
		return nil, err
	}

	tr := quic.Transport{
		ConnectionIDLength: 12,
	}

	if _, ok := packetConn.(*net.UDPConn); ok {
		tr.Conn = wrapSysUDPConn(sysConn)
	} else {
		tr.Conn = sysConn
	}

	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			ServerName:    internalDomain,
			AllowInsecure: true,
		}
	}

	conn, err := tr.DialEarly(context.Background(), destAddr, tlsConfig.GetTLSConfig(tls.WithDestination(dest)), quicConfig)
	if err != nil {
		sysConn.Close()
		return nil, err
	}

	context := &connectionContext{
		conn:    conn,
		rawConn: sysConn,
	}

	s.conns[dialerConf{dest, streamSettings}] = append(conns, context)
	return context.openStream(destAddr)
}

var client clientConnections

func init() {
	client.conns = make(map[dialerConf][]*connectionContext)
	client.cleanup = &task.Periodic{
		Interval: time.Minute,
		Execute:  client.cleanConnections,
	}
	common.Must(client.cleanup.Start())
}

func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (internet.Connection, error) {
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

	return client.openConnection(ctx, destAddr, streamSettings)
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}
