package internet

import (
	"context"

	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/session"
	"github.com/v2fly/v2ray-core/v5/transport/internet/tagged"
)

// Dialer is the interface for dialing outbound connections.
type Dialer interface {
	// Dial dials a system connection to the given destination.
	Dial(ctx context.Context, destination net.Destination) (Connection, error)

	// Address returns the address used by this Dialer. Maybe nil if not known.
	Address() net.Address
}

// dialFunc is an interface to dial network connection to a specific destination.
type dialFunc func(ctx context.Context, dest net.Destination, streamSettings *MemoryStreamConfig) (Connection, error)

var transportDialerCache = make(map[string]dialFunc)

// RegisterTransportDialer registers a Dialer with given name.
func RegisterTransportDialer(protocol string, dialer dialFunc) error {
	if _, found := transportDialerCache[protocol]; found {
		return newError(protocol, " dialer already registered").AtError()
	}
	transportDialerCache[protocol] = dialer
	return nil
}

// Dial dials a internet connection towards the given destination.
func Dial(ctx context.Context, dest net.Destination, streamSettings *MemoryStreamConfig) (Connection, error) {
	if dest.Network == net.Network_TCP {
		if streamSettings == nil {
			s, err := ToMemoryStreamConfig(nil)
			if err != nil {
				return nil, newError("failed to create default stream settings").Base(err)
			}
			streamSettings = s
		}

		protocol := streamSettings.ProtocolName

		if originalProtocolName := getOriginalMessageName(streamSettings); originalProtocolName != "" {
			protocol = originalProtocolName
		}

		dialer := transportDialerCache[protocol]
		if dialer == nil {
			return nil, newError(protocol, " dialer not registered").AtError()
		}
		return dialer(ctx, dest, streamSettings)
	}

	if dest.Network == net.Network_UDP {
		udpDialer := transportDialerCache["udp"]
		if udpDialer == nil {
			return nil, newError("UDP dialer not registered").AtError()
		}
		return udpDialer(ctx, dest, streamSettings)
	}

	return nil, newError("unknown network ", dest.Network)
}

// DialSystem calls system dialer to create a network connection.
func DialSystem(ctx context.Context, dest net.Destination, sockopt *SocketConfig) (net.Conn, error) {
	outbound := session.OutboundFromContext(ctx)

	var src net.Address
	if outbound != nil {
		src = outbound.Gateway
	}

	if transportLayerOutgoingTag := session.GetTransportLayerProxyTagFromContext(ctx); transportLayerOutgoingTag != "" {
		return DialTaggedOutbound(ctx, dest, transportLayerOutgoingTag)
	}

	originalAddr := dest.Address
	if outbound != nil && outbound.Resolver != nil && dest.Address.Family().IsDomain() {
		if addr := outbound.Resolver(ctx, dest.Address.Domain()); addr != nil {
			dest.Address = addr
		}
	}

	switch {
	case src != nil && dest.Address != originalAddr:
		newError("dialing to ", dest, " resolved from ", originalAddr, " via ", src).WriteToLog(session.ExportIDToError(ctx))
	case src != nil:
		newError("dialing to ", dest, " via ", src).WriteToLog(session.ExportIDToError(ctx))
	case dest.Address != originalAddr:
		newError("dialing to ", dest, " resolved from ", originalAddr).WriteToLog(session.ExportIDToError(ctx))
	}

	conn, err := effectiveSystemDialer.Dial(ctx, src, dest, sockopt)
	if err == nil && conn != nil {
		if dest.Network == net.Network_TCP && sockopt != nil && sockopt.Fragment != nil {
			return NewFragmentConn(conn, sockopt.Fragment.Packets, sockopt.Fragment.Length, sockopt.Fragment.Interval)
		}
		if dest.Network == net.Network_UDP && sockopt != nil && sockopt.Noise != nil {
			switch c := conn.(type) {
			case *PacketConnWrapper:
				noisePacketConn, err := NewNoisePacketConn(c.Conn, sockopt.Noise.Packet, sockopt.Noise.Delay)
				if err != nil {
					return nil, err
				}
				c.Conn = noisePacketConn
				return c, nil
			case net.PacketConn:
				noisePacketConn, err := NewNoisePacketConn(c, sockopt.Noise.Packet, sockopt.Noise.Delay)
				if err != nil {
					return nil, err
				}
				return &PacketConnWrapper{
					Conn: noisePacketConn,
					Dest: conn.RemoteAddr(),
				}, nil
			default:
				return NewNoiseConn(conn, sockopt.Noise.Packet, sockopt.Noise.Delay)
			}
		}
	}
	return conn, err
}

func DialTaggedOutbound(ctx context.Context, dest net.Destination, tag string) (net.Conn, error) {
	if tagged.Dialer == nil {
		return nil, newError("tagged dial not enabled")
	}
	return tagged.Dialer(ctx, dest, tag)
}
