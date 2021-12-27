package tun

import (
	"context"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/v2fly/v2ray-core/v4/transport/internet"
)

func (t *LinuxDevice) SetRoute() error {
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

	name, err := t.Name()
	if err != nil {
		return err
	}
	_, ipRoute2NotFound := exec.LookPath("ip")
	if ipRoute2NotFound == nil {
		if t.has4 {
			for _, prefix := range ip4nets {
				err = execShell("ip", "route", "add", prefix.String(), "dev", name)
				if err != nil {
					return err
				}
			}
		}
		if t.has6 {
			for _, prefix := range ip6nets {
				err = execShell("ip", "route", "add", prefix.String(), "dev", name)
				if err != nil {
					return err
				}
			}
		}
		err = execShell("ip", "route", "flush", "cache")
	} else {
		if t.has4 {
			for _, prefix := range ip4nets {
				err = execShell("route", "add", "-A", "inet", prefix.String(), "dev", name)
				if err != nil {
					return err
				}
			}
		}
		if t.has6 {
			for _, prefix := range ip6nets {
				err = execShell("route", "add", "-A", "inet6", prefix.String(), "dev", name)
				if err != nil {
					return err
				}
			}
		}
	}
	return err
}

func getUpstreamInterface() (*net.Interface, error) {
	ipRoute, err := exec.Command("ip", "route").CombinedOutput()
	if err == nil {
		for _, line := range strings.Split(string(ipRoute), "\n") {
			if strings.Contains(line, "default via") {
				dev := strings.SplitN(line, "dev", 2)[1]
				dev = strings.TrimSpace(dev)
				dev = strings.SplitN(dev, " ", 2)[0]
				iif, err := net.InterfaceByName(dev)
				if err != nil {
					newError("failed to get upstream interface from ip route, line: ", line, ", dev: ", dev).Base(err).AtWarning().WriteToLog()
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
