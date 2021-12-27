package internet

import (
	"context"
	"time"

	"github.com/v2fly/v2ray-core/v4/common/net"
	"github.com/v2fly/v2ray-core/v4/common/session"
	"github.com/v2fly/v2ray-core/v4/features/dns"
	"github.com/v2fly/v2ray-core/v4/transport/internet/tagged"
)

// Dialer is the interface for dialing outbound connections.
type Dialer interface {
	// Dial dials a system connection to the given destination.
	Dial(ctx context.Context, destination net.Destination) (Connection, error)

	// Addresses returns the address used by this Dialer. Maybe nil if not known.
	Addresses() (net.Address, net.Address)
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
	var la4, la6 net.Address
	var domainStrategy int32
	var fallbackDelay time.Duration

	if outbound := session.OutboundFromContext(ctx); outbound != nil {
		la4 = outbound.Bind4
		la6 = outbound.Bind6
		domainStrategy = outbound.DomainStrategy
		fallbackDelay = time.Duration(outbound.FallbackDelayMs) * time.Millisecond
	}

	if defaultInterfaceName != "" {
		if domainStrategy == 0 {
			domainStrategy = 1
		}
		if la4 == nil && defaultBind4 != nil {
			la4 = net.IPAddress(defaultBind4)
		} else if la6 == nil && defaultBind6 != nil {
			la6 = net.IPAddress(defaultBind6)
		}
		if sockopt == nil {
			sockopt = &SocketConfig{}
		}
		if sockopt.BindInterfaceName == "" {
			sockopt.BindInterfaceName = defaultInterfaceName
		}
		if sockopt.BindInterfaceIndex == 0 {
			sockopt.BindInterfaceIndex = uint32(defaultInterfaceIndex)
		}
		if sockopt.BindInterfaceIp4 == nil {
			sockopt.BindInterfaceIp4 = la4.IP()
		}
		if sockopt.BindInterfaceIp6 == nil {
			sockopt.BindInterfaceIp6 = la4.IP()
		}
	}

	if transportLayerOutgoingTag := session.GetTransportLayerProxyTagFromContext(ctx); transportLayerOutgoingTag != "" {
		return DialTaggedOutbound(ctx, dest, transportLayerOutgoingTag)
	}

	effectiveSystemDialer.SetFallbackDelay(fallbackDelay)
	if fallbackDelay > 0 {
		newError("Set fallback delay to ", fallbackDelay).AtDebug().WriteToLog()
	}

	// If the outbound is bound to an interface, we have to make sure the destination address
	// is resolved to an IP. The AsIs domain strategy is overridden by BindInterfaceIndex.
	if domainStrategy == 0 && la4 == nil && la6 == nil && !sockopt.HasBindInterface() {
		return effectiveSystemDialer.Dial(ctx, nil, dest, sockopt)
	}

	ips4, ips6 := resolveIP(ctx, domainStrategy, dest.Address, la4, la6)
	var dests4, dests6 []net.Destination

	for _, ip4 := range ips4 {
		dests4 = append(dests4, net.Destination{
			Address: net.IPAddress(ip4),
			Port:    dest.Port,
			Network: dest.Network,
		})
	}

	for _, ip6 := range ips6 {
		dests6 = append(dests6, net.Destination{
			Address: net.IPAddress(ip6),
			Port:    dest.Port,
			Network: dest.Network,
		})
	}

	if len(dests4) == 0 && len(dests6) == 0 {
		return nil, newError("unknown destination from ", dest)
	}

	return effectiveSystemDialer.DialIPs(ctx, la4, dests4, la6, dests6, sockopt)
}

// SagerNet: private
func DialSystemDNS(ctx context.Context, dest net.Destination, sockopt *SocketConfig) (net.Conn, error) {
	var la4, la6 net.Address
	var domainStrategy int32
	var fallbackDelay time.Duration

	if outbound := session.OutboundFromContext(ctx); outbound != nil {
		la4 = outbound.Bind4
		la6 = outbound.Bind6
		domainStrategy = outbound.DomainStrategy
		fallbackDelay = time.Duration(outbound.FallbackDelayMs) * time.Millisecond
	}
	if domainStrategy == 0 {
		domainStrategy = 1
		if defaultBind4 != nil {
			la4 = net.IPAddress(defaultBind4)
		} else if defaultBind6 != nil {
			la6 = net.IPAddress(defaultBind6)
		} else {
			domainStrategy = 0
		}
	}

	if transportLayerOutgoingTag := session.GetTransportLayerProxyTagFromContext(ctx); transportLayerOutgoingTag != "" {
		return DialTaggedOutbound(ctx, dest, transportLayerOutgoingTag)
	}

	effectiveSystemDNSDialer.SetFallbackDelay(fallbackDelay)

	if domainStrategy == 0 && la4 == nil && la6 == nil {
		return effectiveSystemDialer.Dial(ctx, nil, dest, sockopt)
	}

	ips4, ips6 := resolveIP(ctx, domainStrategy, dest.Address, la4, la6)
	var dests4, dests6 []net.Destination

	for _, ip4 := range ips4 {
		dests4 = append(dests4, net.Destination{
			Address: net.IPAddress(ip4),
			Port:    dest.Port,
			Network: dest.Network,
		})
	}

	for _, ip6 := range ips6 {
		dests6 = append(dests6, net.Destination{
			Address: net.IPAddress(ip6),
			Port:    dest.Port,
			Network: dest.Network,
		})
	}

	return effectiveSystemDNSDialer.DialIPs(ctx, la4, dests4, la6, dests6, sockopt)
}

func DialTaggedOutbound(ctx context.Context, dest net.Destination, tag string) (net.Conn, error) {
	if tagged.Dialer == nil {
		return nil, newError("tagged dial not enabled")
	}
	return tagged.Dialer(ctx, dest, tag)
}

func resolveIP(ctx context.Context, domainStrategy int32, address net.Address, la4 net.Address, la6 net.Address) (ips4, ips6 []net.IP) {
	if address.Family().IsIP() {
		ip := address.IP()
		if ip.To4() == nil {
			ips6 = append(ips6, ip)
		} else {
			ips4 = append(ips4, ip)
		}
		return
	}

	domain := address.Domain()

	dialerDnsClient := session.DNSClientFromContext(ctx)
	if dialerDnsClient == nil {
		newError("DNS client is nil").WriteToLog()
		return
	}

	if c, ok := dialerDnsClient.(dns.ClientWithIPOption); ok {
		c.SetFakeDNSOption(false) // Skip FakeDNS
	} else {
		newError("DNS client doesn't implement ClientWithIPOption")
	}

	var err error
	switch domainStrategy {
	case 0, 1:
		var ips []net.IP
		ips, err = dialerDnsClient.LookupIP(domain)
		for _, ip := range ips {
			if ip.To4() == nil {
				ips6 = append(ips6, ip)
			} else {
				ips4 = append(ips4, ip)
			}
		}
	case 2:
		ips4, err = dialerDnsClient.(dns.IPv4Lookup).LookupIPv4(domain)
	case 3:
		ips6, err = dialerDnsClient.(dns.IPv6Lookup).LookupIPv6(domain)
	}

	if err != nil {
		newError("failed to get IP address for domain ", domain).Base(err).WriteToLog(session.ExportIDToError(ctx))
	}

	return
}
