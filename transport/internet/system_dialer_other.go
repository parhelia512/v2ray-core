//go:build !linux
// +build !linux

package internet

import "github.com/v2fly/v2ray-core/v4/common/net"

func newUDPConnWrapper(conn *net.UDPConn, src net.Address, destAddr *net.UDPAddr, addressFamily net.AddressFamily, sockopt *SocketConfig) (*PacketConnWrapper, error) {
	return &PacketConnWrapper{
		Conn: conn,
		Dest: destAddr,
	}, nil
}

func (sockopt *SocketConfig) getBindInterfaceIP46() (bindInterfaceIP4, bindInterfaceIP6 []byte) {
	bindInterfaceIP4 = make([]byte, 4)
	bindInterfaceIP6 = make([]byte, 16)
	return
}
