package internet

import (
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/v2fly/v2ray-core/v4/common/net"
)

func newUDPConnWrapper(conn *net.UDPConn, src net.Address, destAddr *net.UDPAddr, addressFamily net.AddressFamily, sockopt *SocketConfig) (*PacketConnWrapper, error) {
	if !sockopt.HasBindInterface() || !sockopt.LinuxBindInterfaceUdpUsePktinfo {
		return &PacketConnWrapper{
			Conn: conn,
			Dest: destAddr,
		}, nil
	}

	var b []byte

	switch addressFamily {
	case net.AddressFamilyIPv4:
		ip4 := (*[4]byte)([]byte(sockopt.BindInterfaceIp4))
		pktinfo := &unix.Inet4Pktinfo{
			Ifindex:  int32(sockopt.BindInterfaceIndex),
			Spec_dst: *ip4,
		}

		b = make([]byte, unix.CmsgSpace(unix.SizeofInet4Pktinfo))
		h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
		h.Level = unix.IPPROTO_IP
		h.Type = unix.IP_PKTINFO
		h.SetLen(unix.SizeofCmsghdr + unix.SizeofInet4Pktinfo)
		*(*unix.Inet4Pktinfo)(unsafe.Pointer(uintptr(unsafe.Pointer(h)) + uintptr(unix.SizeofCmsghdr))) = *pktinfo

	case net.AddressFamilyIPv6:
		ip6 := (*[16]byte)([]byte(sockopt.BindInterfaceIp6))
		pktinfo := &unix.Inet6Pktinfo{
			Addr:    *ip6,
			Ifindex: sockopt.BindInterfaceIndex,
		}

		b = make([]byte, unix.CmsgSpace(unix.SizeofInet6Pktinfo))
		h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
		h.Level = unix.IPPROTO_IPV6
		h.Type = unix.IPV6_PKTINFO
		h.SetLen(unix.SizeofCmsghdr + unix.SizeofInet6Pktinfo)
		*(*unix.Inet6Pktinfo)(unsafe.Pointer(uintptr(unsafe.Pointer(h)) + uintptr(unix.SizeofCmsghdr))) = *pktinfo

	default:
		return nil, newError("newUdpConnWrapper requires addressFamily to be either IPv4 or IPv6")
	}

	return &PacketConnWrapper{
		Conn: conn,
		Oob:  b,
		Dest: destAddr,
	}, nil
}

func (sockopt *SocketConfig) getBindInterfaceIP46() (bindInterfaceIP4, bindInterfaceIP6 []byte) {
	if sockopt.HasBindInterface() && sockopt.LinuxBindInterfaceUdpUsePktinfo {
		bindInterfaceIP4 = sockopt.BindInterfaceIp4
		bindInterfaceIP6 = sockopt.BindInterfaceIp6
	} else {
		bindInterfaceIP4 = make([]byte, 4)
		bindInterfaceIP6 = make([]byte, 16)
	}
	return
}
