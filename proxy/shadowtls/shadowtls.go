package shadowtls

import (
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/v2fly/v2ray-core/v5/common/net"
)

//go:generate go run github.com/v2fly/v2ray-core/v5/common/errors/errorgen

func toNetwork(network string) net.Network {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		return net.Network_TCP
	case N.NetworkUDP:
		return net.Network_UDP
	default:
		return net.Network_Unknown
	}
}

func toDestination(socksaddr M.Socksaddr, network net.Network) net.Destination {
	if socksaddr.IsFqdn() {
		return net.Destination{
			Network: network,
			Address: net.DomainAddress(socksaddr.Fqdn),
			Port:    net.Port(socksaddr.Port),
		}
	} else {
		return net.Destination{
			Network: network,
			Address: net.IPAddress(socksaddr.Addr.AsSlice()),
			Port:    net.Port(socksaddr.Port),
		}
	}
}

func toSocksaddr(destination net.Destination) M.Socksaddr {
	var addr M.Socksaddr
	switch destination.Address.Family() {
	case net.AddressFamilyDomain:
		addr.Fqdn = destination.Address.Domain()
	default:
		addr.Addr = M.AddrFromIP(destination.Address.IP())
	}
	addr.Port = uint16(destination.Port)
	return addr
}

func returnError(err error) error {
	if E.IsClosed(err) {
		return nil
	}
	return err
}
