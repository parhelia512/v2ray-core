package tun

import (
	"fmt"
	"strconv"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	core "github.com/v2fly/v2ray-core/v4"
	"github.com/v2fly/v2ray-core/v4/common"
	"github.com/v2fly/v2ray-core/v4/common/buf"
	"github.com/v2fly/v2ray-core/v4/common/net"
	"github.com/v2fly/v2ray-core/v4/common/protocol"
	"github.com/v2fly/v2ray-core/v4/common/session"
	"github.com/v2fly/v2ray-core/v4/common/task"
)

func (t *GVisorTun) setupForwarders() {
	tcpForwarder := tcp.NewForwarder(t.stack, 0, 2<<10, func(request *tcp.ForwarderRequest) {
		id := request.ID()
		waitQueue := new(waiter.Queue)
		endpoint, errT := request.CreateEndpoint(waitQueue)
		if errT != nil {
			newError("failed to create TCP connection").Base(tcpipErr(errT)).WriteToLog()
			// prevent potential half-open TCP connection leak.
			request.Complete(true)
			return
		}
		request.Complete(false)
		srcAddr := net.JoinHostPort(id.RemoteAddress.String(), strconv.Itoa(int(id.RemotePort)))
		src, err := net.ParseDestination(fmt.Sprint("tcp:", srcAddr))
		if err != nil {
			newError("parse tcp source address ", srcAddr, " failed: ", err).AtWarning().WriteToLog()
			return
		}
		dstAddr := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
		dst, err := net.ParseDestination(fmt.Sprint("tcp:", dstAddr))
		if err != nil {
			newError("parse tcp destination address ", dstAddr, " failed: ", err).AtWarning().WriteToLog()
			return
		}

		newError("tcp: ", src.NetAddr(), " => ", dst.NetAddr()).AtDebug().WriteToLog()

		go func() {
			ctx := core.ToBackgroundDetachedContext(t.ctx)
			ctx = session.ContextWithInbound(ctx, &session.Inbound{
				Source: src,
				Tag:    t.config.Tag,
				User: &protocol.MemoryUser{
					Level: t.config.UserLevel,
				},
			})
			if t.content != nil {
				c := *t.content
				ctx = session.ContextWithContent(ctx, &c)
			}

			conn := gonet.NewTCPConn(waitQueue, endpoint)
			link, err := t.dispatcher.Dispatch(ctx, dst)
			if err != nil {
				newError("failed to dispatch tcp conn").Base(err).WriteToLog()
				return
			}

			task.Run(ctx, func() error {
				return buf.Copy(buf.NewReader(conn), link.Writer)
			}, func() error {
				return buf.Copy(link.Reader, buf.NewWriter(conn))
			})

			common.Close(conn)
			common.Close(link.Reader)
			common.Close(link.Writer)
		}()
	})

	t.stack.SetTransportProtocolHandler(header.TCPProtocolNumber, tcpForwarder.HandlePacket)

	udpForwarder := func(id stack.TransportEndpointID, buffer *stack.PacketBuffer) bool {
		// Ref: gVisor pkg/tcpip/transport/udp/endpoint.go HandlePacket
		udpHdr := header.UDP(buffer.TransportHeader().View())
		if int(udpHdr.Length()) > buffer.Data().Size()+header.UDPMinimumSize {
			// Malformed packet.
			return true
		}

		srcAddr := net.JoinHostPort(id.RemoteAddress.String(), strconv.Itoa(int(id.RemotePort)))
		source, err := net.ParseDestination(fmt.Sprint("udp:", srcAddr))
		if err != nil {
			newError("parse udp source address ", srcAddr, " failed: ", err).AtWarning().WriteToLog()
			return true
		}
		dstAddr := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
		destination, err := net.ParseDestination(fmt.Sprint("udp:", dstAddr))
		if err != nil {
			newError("parse udp destination address ", dstAddr, " failed: ", err).AtWarning().WriteToLog()
			return true
		}

		go func() {
			data := buffer.Data().ExtractVV()
			packet := &gUdpPacket{
				s:        t.stack,
				id:       &id,
				nicID:    buffer.NICID,
				netHdr:   buffer.Network(),
				netProto: buffer.NetworkProtocolNumber,
			}
			destUdpAddr := &net.UDPAddr{
				IP:   destination.Address.IP(),
				Port: int(destination.Port),
			}

			natKey := source.NetAddr()

			sendTo := func() bool {
				iConn, ok := t.udpTable.Load(natKey)
				if !ok {
					return false
				}
				conn := iConn.(net.PacketConn)
				_, err := conn.WriteTo(data.ToView(), &net.UDPAddr{
					IP:   destination.Address.IP(),
					Port: int(destination.Port),
				})
				if err != nil {
					_ = conn.Close()
				}
				return true
			}

			var cond *sync.Cond

			if sendTo() {
				return
			} else {
				iCond, loaded := t.lockTable.LoadOrStore(natKey, sync.NewCond(&sync.Mutex{}))
				cond = iCond.(*sync.Cond)
				if loaded {
					cond.L.Lock()
					cond.Wait()
					sendTo()
					cond.L.Unlock()
					return
				}
			}

			newError("udp: ", source.NetAddr(), " => ", destination.NetAddr()).AtDebug().WriteToLog()

			ctx := core.ToBackgroundDetachedContext(t.ctx)
			ctx = session.ContextWithInbound(ctx, &session.Inbound{
				Source: source,
				Tag:    t.config.Tag,
				User: &protocol.MemoryUser{
					Level: t.config.UserLevel,
				},
			})
			if t.content != nil {
				c := *t.content
				ctx = session.ContextWithContent(ctx, &c)
			}

			conn, err := dispatchUDP(ctx, t.dispatcher, destination, t.timeouts.ConnectionIdle)
			if err != nil {
				newError("failed to dispatch udp conn").Base(err).WriteToLog()
			}

			t.udpTable.Store(natKey, conn)

			go sendTo()

			t.lockTable.Delete(natKey)
			cond.Broadcast()

			for {
				data, addr, err := conn.readFrom()
				if err != nil {
					break
				}
				if addr, ok := addr.(*net.UDPAddr); ok {
					_, err = packet.WriteBack(data, addr)
				} else {
					_, err = packet.WriteBack(data, destUdpAddr)
				}
				if err != nil {
					break
				}
			}

			t.udpTable.Delete(natKey)
		}()

		return true
	}

	t.stack.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder)
}

type gUdpPacket struct {
	s        *stack.Stack
	id       *stack.TransportEndpointID
	nicID    tcpip.NICID
	netHdr   header.Network
	netProto tcpip.NetworkProtocolNumber
}

func (p *gUdpPacket) WriteBack(b []byte, addr *net.UDPAddr) (int, error) {
	v := buffer.View(b)
	if len(v) > header.UDPMaximumPacketSize {
		// Payload can't possibly fit in a packet.
		return 0, fmt.Errorf("%s", &tcpip.ErrMessageTooLong{})
	}

	var (
		localAddress tcpip.Address
		localPort    uint16
	)

	if addr == nil {
		localAddress = p.netHdr.DestinationAddress()
		localPort = p.id.LocalPort
	} else {
		localAddress = tcpip.Address(addr.IP)
		localPort = uint16(addr.Port)
	}

	route, err := p.s.FindRoute(p.nicID, localAddress, p.netHdr.SourceAddress(), p.netProto, false /* multicastLoop */)
	if err != nil {
		return 0, fmt.Errorf("%#v find route: %s", p.id, err)
	}
	defer route.Release()

	data := v.ToVectorisedView()
	if err = gSendUDP(route, data, localPort, p.id.RemotePort); err != nil {
		return 0, fmt.Errorf("%v", err)
	}
	return data.Size(), nil
}

// gSendUDP sends a UDP segment via the provided network endpoint and under the
// provided identity.
func gSendUDP(r *stack.Route, data buffer.VectorisedView, localPort, remotePort uint16) tcpip.Error {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.UDPMinimumSize + int(r.MaxHeaderLength()),
		Data:               data,
	})
	defer pkt.DecRef()

	// Initialize the UDP header.
	udpHdr := header.UDP(pkt.TransportHeader().Push(header.UDPMinimumSize))
	pkt.TransportProtocolNumber = udp.ProtocolNumber

	length := uint16(pkt.Size())
	udpHdr.Encode(&header.UDPFields{
		SrcPort: localPort,
		DstPort: remotePort,
		Length:  length,
	})

	// Set the checksum field unless TX checksum offload is enabled.
	// On IPv4, UDP checksum is optional, and a zero value indicates the
	// transmitter skipped the checksum generation (RFC768).
	// On IPv6, UDP checksum is not optional (RFC2460 Section 8.1).
	if r.RequiresTXTransportChecksum() && r.NetProto() == header.IPv6ProtocolNumber {
		xsum := r.PseudoHeaderChecksum(udp.ProtocolNumber, length)
		for _, v := range data.Views() {
			xsum = header.Checksum(v, xsum)
		}
		udpHdr.SetChecksum(^udpHdr.CalculateChecksum(xsum))
	}

	ttl := r.DefaultTTL()

	if err := r.WritePacket(stack.NetworkHeaderParams{
		Protocol: udp.ProtocolNumber,
		TTL:      ttl,
		TOS:      0, /* default */
	}, pkt); err != nil {
		r.Stats().UDP.PacketSendErrors.Increment()
		return err
	}

	// Track count of packets sent.
	r.Stats().UDP.PacketsSent.Increment()
	return nil
}
