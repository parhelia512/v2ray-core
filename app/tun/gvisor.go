package tun

import (
	"context"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/v2fly/v2ray-core/v4/features/tun"
)

var (
	_ tun.Tun                      = (*GVisorTun)(nil)
	_ stack.InjectableLinkEndpoint = (*GVisorTun)(nil)
)

const defaultNIC tcpip.NICID = 0x01

type GVisorTun struct {
	*baseTun

	ctx               context.Context
	nic               tcpip.NICID
	stack             *stack.Stack
	networkDispatcher stack.NetworkDispatcher
	wg                sync.WaitGroup
	udpTable          sync.Map
	lockTable         sync.Map
}

func newGVisor(ctx context.Context, base *baseTun) (*GVisorTun, error) {
	return &GVisorTun{
		ctx:     ctx,
		baseTun: base,
		nic:     defaultNIC,
	}, nil
}

func (t *GVisorTun) InjectInbound(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	go t.networkDispatcher.DeliverNetworkPacket("", "", protocol, pkt)
}

func (t *GVisorTun) InjectOutbound(_ tcpip.Address, packet []byte) tcpip.Error {
	_, err := t.device.Write(packet)
	if err != nil {
		return &tcpip.ErrAborted{}
	}
	return nil
}

func (t *GVisorTun) Type() interface{} {
	return tun.TunType()
}

func (t *GVisorTun) Start() error {
	var has4, has6 bool
	for _, prefix := range t.ranges {
		if prefix.Addr().Is4() {
			has4 = true
		} else {
			has6 = true
		}
	}
	options := stack.Options{}
	if has4 && !has6 {
		options.NetworkProtocols = []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
		}
		options.TransportProtocols = []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
		}
	} else if !has4 && has6 {
		options.NetworkProtocols = []stack.NetworkProtocolFactory{
			ipv6.NewProtocol,
		}
		options.TransportProtocols = []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol6,
		}
	} else {
		options.NetworkProtocols = []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		}
		options.TransportProtocols = []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		}
	}
	t.stack = stack.New(options)
	err := t.stack.CreateNIC(t.nic, t)
	if err != nil {
		return newError("failed to create nic").Base(tcpipErr(err))
	}
	t.setupForwarders()
	for _, prefix := range t.ranges {
		var address tcpip.Address
		var protocol tcpip.NetworkProtocolNumber
		if prefix.Addr().Is4() {
			addrBytes := prefix.Addr().As4()
			address = tcpip.Address(addrBytes[:])
			protocol = header.IPv4ProtocolNumber
		} else {
			addrBytes := prefix.Addr().As16()
			address = tcpip.Address(addrBytes[:])
			protocol = header.IPv6ProtocolNumber
		}
		err := t.stack.AddProtocolAddress(t.nic, tcpip.ProtocolAddress{
			Protocol: protocol,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   address,
				PrefixLen: prefix.Bits(),
			},
		}, stack.AddressProperties{})
		if err != nil {
			return newError("failed to add addr ", prefix.String(), " to nic").Base(tcpipErr(err))
		}
	}
	if has4 {
		t.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: t.nic})
	}
	if has6 {
		t.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: t.nic})
	}
	t.stack.SetSpoofing(t.nic, true)
	t.stack.SetPromiscuousMode(t.nic, true)
	return nil
}

func (t *GVisorTun) Close() error {
	return t.device.Close()
}

func (t *GVisorTun) MTU() uint32 {
	mtu, _ := t.device.MTU()
	return uint32(mtu)
}

func (t *GVisorTun) MaxHeaderLength() uint16 {
	return 0
}

func (t *GVisorTun) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (t *GVisorTun) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityNone
}

func (t *GVisorTun) Attach(dispatcher stack.NetworkDispatcher) {
	if dispatcher == nil && t.networkDispatcher != nil {
		t.device.StopRead()
		t.Wait()
		t.networkDispatcher = nil
		return
	}
	if dispatcher != nil && t.networkDispatcher == nil {
		t.networkDispatcher = dispatcher
		t.wg.Add(1)
		go func() {
			t.dispatchLoop()
			t.wg.Done()
		}()
	}
}

func (t *GVisorTun) IsAttached() bool {
	return t.networkDispatcher != nil
}

func (t *GVisorTun) Wait() {
	t.wg.Wait()
}

func (t *GVisorTun) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (t *GVisorTun) AddHeader(tcpip.LinkAddress, tcpip.LinkAddress, tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {
}

func (t *GVisorTun) WritePacket(_ stack.RouteInfo, _ tcpip.NetworkProtocolNumber, buffer *stack.PacketBuffer) tcpip.Error {
	err := t.device.WriteBuffer(buffer)
	if err != nil {
		return &tcpip.ErrAborted{}
	}
	return nil
}

func (t *GVisorTun) WritePackets(_ stack.RouteInfo, pkts stack.PacketBufferList, _ tcpip.NetworkProtocolNumber) (int, tcpip.Error) {
	const batchSz = 47
	batch := make([]*stack.PacketBuffer, 0, batchSz)
	for pkt := pkts.Front(); pkt != nil; pkt = pkt.Next() {
		batch = append(batch, pkt)
	}
	n, err := t.device.WriteBuffers(batch)
	if err != nil {
		return 0, &tcpip.ErrAborted{}
	}
	return n, nil
}

func (t *GVisorTun) WriteRawPacket(buffer *stack.PacketBuffer) tcpip.Error {
	err := t.device.WriteBuffer(buffer)
	if err != nil {
		return &tcpip.ErrAborted{}
	}
	return nil
}

func (t *GVisorTun) dispatchLoop() {
	if name, err := t.device.Name(); err == nil {
		newError("listening packets on ", name).AtInfo().WriteToLog()
	}
	for {
		pkt, err := t.device.ReadBuffer()
		if err != nil {
			newError("failed to read packet").Base(err).WriteToLog()
			break
		}

		t.dispatch(pkt)
	}
}

func (t *GVisorTun) dispatch(pkt *stack.PacketBuffer) {
	h, ok := pkt.Data().PullUp(1)
	if !ok {
		return
	}

	var (
		p             tcpip.NetworkProtocolNumber
		remote, local tcpip.LinkAddress
	)

	switch header.IPVersion(h) {
	case header.IPv4Version:
		p = header.IPv4ProtocolNumber
	case header.IPv6Version:
		p = header.IPv6ProtocolNumber
	default:
		return
	}

	t.networkDispatcher.DeliverNetworkPacket(remote, local, p, pkt)
}
