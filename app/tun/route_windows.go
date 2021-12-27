package tun

import (
	"context"
	"net"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/go118/netip"

	"github.com/v2fly/v2ray-core/v4/app/tun/winipcfg"
	"github.com/v2fly/v2ray-core/v4/transport/internet"
)

func (t *WindowsDevice) SetRoute() error {
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
	luid := winipcfg.LUID(t.adapter.LUID())
	if t.has4 {
		for _, prefix := range ip4nets {
			err = luid.AddRoute(prefix, prefix.Addr(), 0)
			if err != nil {
				return newError("failed to set ipv4 route for wintun: ", prefix).Base(err)
			}
		}
	}
	if t.has6 {
		for _, prefix := range ip6nets {
			err = luid.AddRoute(prefix, prefix.Addr(), 0)
			if err != nil {
				return newError("failed to set ipv6 route for wintun: ", prefix).Base(err)
			}
		}
	}
	if t.has4 {
		ipif, err := luid.IPInterface(windows.AF_INET)
		if err != nil {
			return newError("failed to get ipv4 interface for wintun").Base(err)
		}
		ipif.UseAutomaticMetric = false
		ipif.Metric = 0
		err = ipif.Set()
		if err != nil {
			return newError("failed to disable ipv4 automatic metric for wintun").Base(err)
		}
	}
	if t.has6 {
		ipif, err := luid.IPInterface(windows.AF_INET6)
		if err != nil {
			return newError("failed to get ipv6 interface for wintun").Base(err)
		}
		ipif.UseAutomaticMetric = false
		ipif.Metric = 0
		err = ipif.Set()
		if err != nil {
			return newError("failed to disable ipv6 automatic metric for wintun").Base(err)
		}
	}
	if t.has4 {
		err = luid.SetDNS(windows.AF_INET, []netip.Addr{netip.MustParseAddr("1.0.0.1")}, []string{})
	}

	if t.has6 && err == nil {
		err = luid.SetDNS(windows.AF_INET6, []netip.Addr{netip.MustParseAddr("2606:4700:4700::1001")}, []string{})
	}

	if err != nil {
		return newError("failed to set dns for wintun").Base(err)
	}

	return nil
}

func getUpstreamInterface() (*net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, newError("failed to get all interfaces").Base(err)
	}
	ipRoute, err := exec.Command("netsh", "interface", "ip", "show", "route").CombinedOutput()
	if err == nil {
		for _, line := range strings.Split(string(ipRoute), "\n") {
			if strings.Contains(line, "0.0.0.0/0") {
				line = strings.Trim(line, " \r\n")
				dev := line[strings.LastIndex(line, " ")+1:]
				iip := net.ParseIP(dev)
				for _, iif := range interfaces {
					if iif.Name == dev {
						return &iif, nil
					}
					addrs, err := iif.Addrs()
					if err == nil {
						for _, addr := range addrs {
							inet := addr.(*net.IPNet)
							if inet.IP.Equal(iip) || inet.Contains(iip) {
								return &iif, nil
							}
						}
					}
				}
				newError("failed to get upstream interface from netsh, line: ", line, ", dev: ", dev).Base(err).AtWarning().WriteToLog()
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
