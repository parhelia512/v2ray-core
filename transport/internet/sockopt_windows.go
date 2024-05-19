package internet

import (
	"encoding/binary"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	v2net "github.com/v2fly/v2ray-core/v5/common/net"
)

const (
	IP_UNICAST_IF   = 31 // nolint: revive,stylecheck
	IPV6_UNICAST_IF = 31 // nolint: revive,stylecheck
)

func applyOutboundSocketOptions(network string, address string, fd uintptr, config *SocketConfig) error {
	if isTCPSocket(network) {
		if config.TcpKeepAliveIdle > 0 {
			if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1); err != nil {
				return newError("failed to set SO_KEEPALIVE", err)
			}
		}
	}

	if config.BindToDevice != "" {
		iface, err := net.InterfaceByName(config.BindToDevice)
		if err != nil {
			return newError("failed to get interface ", config.BindToDevice).Base(err)
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		switch v2net.ParseAddress(host).Family() {
		case v2net.AddressFamilyIPv4:
			var bytes [4]byte
			binary.BigEndian.PutUint32(bytes[:], uint32(iface.Index))
			index := *(*uint32)(unsafe.Pointer(&bytes[0]))
			// DWORD in network byte order
			if err := windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, IP_UNICAST_IF, int(index)); err != nil {
				return newError("failed to set IP_UNICAST_IF", err)
			}
		case v2net.AddressFamilyIPv6:
			// DWORD in host byte order
			if err := windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, IPV6_UNICAST_IF, iface.Index); err != nil {
				return newError("failed to set IPV6_UNICAST_IF", err)
			}
		}
	}

	if config.TxBufSize != 0 {
		if err := windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_SNDBUF, int(config.TxBufSize)); err != nil {
			return newError("failed to set SO_SNDBUF").Base(err)
		}
	}

	if config.RxBufSize != 0 {
		if err := windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_RCVBUF, int(config.TxBufSize)); err != nil {
			return newError("failed to set SO_RCVBUF").Base(err)
		}
	}

	return nil
}

func applyInboundSocketOptions(network string, address string, fd uintptr, config *SocketConfig) error {
	if isTCPSocket(network) {
		if config.TcpKeepAliveIdle > 0 {
			if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1); err != nil {
				return newError("failed to set SO_KEEPALIVE", err)
			}
		}
	}

	if config.BindToDevice != "" {
		iface, err := net.InterfaceByName(config.BindToDevice)
		if err != nil {
			return newError("failed to get interface ", config.BindToDevice).Base(err)
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		addr := v2net.ParseAddress(host)
		switch {
		case addr.Family().IsIP() && addr.IP().IsUnspecified(), addr.Family().IsIPv6():
			// DWORD in host byte order
			if err := windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, IPV6_UNICAST_IF, iface.Index); err != nil {
				return newError("failed to set IPV6_UNICAST_IF", err)
			}
		case addr.Family().IsIPv4():
			var bytes [4]byte
			binary.BigEndian.PutUint32(bytes[:], uint32(iface.Index))
			index := *(*uint32)(unsafe.Pointer(&bytes[0]))
			// DWORD in network byte order
			if err := windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, IP_UNICAST_IF, int(index)); err != nil {
				return newError("failed to set IP_UNICAST_IF", err)
			}
		}
	}

	if config.TxBufSize != 0 {
		if err := windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_SNDBUF, int(config.TxBufSize)); err != nil {
			return newError("failed to set SO_SNDBUF").Base(err)
		}
	}

	if config.RxBufSize != 0 {
		if err := windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_RCVBUF, int(config.TxBufSize)); err != nil {
			return newError("failed to set SO_RCVBUF").Base(err)
		}
	}

	return nil
}

func bindAddr(_ uintptr, _ []byte, _ uint32) error {
	return nil
}

func setReuseAddr(_ uintptr) error {
	return nil
}

func setReusePort(_ uintptr) error {
	return nil
}
