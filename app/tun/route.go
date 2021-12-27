package tun

import (
	"bytes"
	"os/exec"
	"strings"

	"golang.zx2c4.com/go118/netip"
)

var (
	ip4nets = []netip.Prefix{
		netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 0, 0, 0}), 8),
		netip.PrefixFrom(netip.AddrFrom4([4]byte{2, 0, 0, 0}), 7),
		netip.PrefixFrom(netip.AddrFrom4([4]byte{4, 0, 0, 0}), 6),
		netip.PrefixFrom(netip.AddrFrom4([4]byte{8, 0, 0, 0}), 5),
		netip.PrefixFrom(netip.AddrFrom4([4]byte{16, 0, 0, 0}), 4),
		netip.PrefixFrom(netip.AddrFrom4([4]byte{32, 0, 0, 0}), 3),
		netip.PrefixFrom(netip.AddrFrom4([4]byte{64, 0, 0, 0}), 2),
		netip.PrefixFrom(netip.AddrFrom4([4]byte{128, 0, 0, 0}), 1),
	}
	ip6nets = []netip.Prefix{
		netip.MustParsePrefix("2000::/3"),
	}
)

func execShell(name string, arg ...string) error {
	shell := strings.Join([]string{name, strings.Join(arg, " ")}, " ")
	c := exec.Command(name, arg...)
	var b bytes.Buffer
	c.Stdout = &b
	c.Stderr = &b
	err := c.Run()
	if err != nil {
		return newError("failed to exec ", shell, ": exit status ", c.ProcessState.ExitCode(), ": \n", b.String())
	}
	return nil
}
