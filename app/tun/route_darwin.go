package tun

import (
	"context"
	"net"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/go118/netip"

	"github.com/v2fly/v2ray-core/v4/transport/internet"
)

func (t *DarwinDevice) SetRoute() error {
	iif, err := getUpstreamInterface()
	if err != nil {
		return err
	}
	addrs, _ := iif.Addrs()
	var bind4, bind6 net.IP
	for _, addr := range addrs {
		ip := addr.(*net.IPNet).IP
		if ip.To4() != nil {
			bind4 = ip
		} else {
			bind6 = ip
		}
	}
	internet.UseDefaultInterface(bind4, bind6, iif.Name, iif.Index)

	var gw4, gw6 netip.Addr
	for _, prefix := range t.ranges {
		if prefix.Addr().Is4() {
			gw4 = prefix.Addr()
		} else {
			gw6 = prefix.Addr()
		}
	}

	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var seq int

	if gw4.IsValid() {
		for _, prefix := range ip4nets {
			seq++
			mask, _ := netip.AddrFromSlice(net.CIDRMask(prefix.Bits(), 32))
			rtmsg := route.RouteMessage{
				Type:    unix.RTM_ADD,
				Flags:   unix.RTF_UP | unix.RTF_STATIC | unix.RTF_GATEWAY,
				Version: unix.RTM_VERSION,
				Seq:     seq,
				Addrs: []route.Addr{
					syscall.RTAX_DST:     &route.Inet4Addr{IP: prefix.Addr().As4()},
					syscall.RTAX_GATEWAY: &route.Inet4Addr{IP: gw4.As4()},
					syscall.RTAX_NETMASK: &route.Inet4Addr{IP: mask.As4()},
				},
			}

			buf, err := rtmsg.Marshal()
			if err != nil {
				return err
			}
			_, err = syscall.Write(fd, buf)
			if err != nil {
				return newError("failed to set route to ", prefix.String()).Base(err)
			}
		}
	}

	if gw6.IsValid() {
		for _, prefix := range ip6nets {
			seq++
			mask, _ := netip.AddrFromSlice(net.CIDRMask(prefix.Bits(), 128))
			rtmsg := route.RouteMessage{
				Type:    unix.RTM_ADD,
				Flags:   unix.RTF_UP | unix.RTF_STATIC | unix.RTF_GATEWAY,
				Version: unix.RTM_VERSION,
				Seq:     seq,
				Addrs: []route.Addr{
					syscall.RTAX_DST:     &route.Inet6Addr{IP: prefix.Addr().As16()},
					syscall.RTAX_GATEWAY: &route.Inet6Addr{IP: gw6.As16()},
					syscall.RTAX_NETMASK: &route.Inet6Addr{IP: mask.As16()},
				},
			}

			buf, err := rtmsg.Marshal()
			if err != nil {
				return err
			}
			_, err = syscall.Write(fd, buf)
			if err != nil {
				return newError("failed to set route to ", prefix.String()).Base(err)
			}
		}
	}

	return nil
}

func getUpstreamInterface() (*net.Interface, error) {
	ipRoute, err := exec.Command("route", "get", "default").CombinedOutput()
	if err == nil {
		for _, line := range strings.Split(string(ipRoute), "\n") {
			if strings.Contains(line, "interface") {
				dev := strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
				iif, err := net.InterfaceByName(dev)
				if err != nil {
					newError("failed to get upstream interface from route get default, line: ", line, ", dev: ", dev).Base(err).AtWarning().WriteToLog()
				} else {
					return iif, nil
				}
			}
		}
	}
	var dialer net.Dialer
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	conn, err := dialer.DialContext(ctx, "tcp", "1.0.0.1:443")
	cancel()
	if err != nil {
		return nil, newError("failed to get default bind address")
	}
	upsteamIp := conn.LocalAddr().(*net.TCPAddr).IP
	conn.Close()
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, newError("failed to get all interfaces").Base(err)
	}
	for _, iif := range interfaces {
		addrs, err := iif.Addrs()
		if err == nil {
			for _, addr := range addrs {
				if upsteamIp.Equal(addr.(*net.IPNet).IP) {
					return &iif, nil
				}
			}
		}
	}
	return nil, newError("failed to get upstream network")
}
