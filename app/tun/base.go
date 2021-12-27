package tun

import (
	"golang.zx2c4.com/go118/netip"
	"gvisor.dev/gvisor/pkg/tcpip"

	"github.com/v2fly/v2ray-core/v4/common/errors"
	"github.com/v2fly/v2ray-core/v4/common/session"
	"github.com/v2fly/v2ray-core/v4/features/policy"
	"github.com/v2fly/v2ray-core/v4/features/routing"
)

type baseDevice struct {
	ranges     []netip.Prefix
	has4, has6 bool
	config     *Config
}

type baseTun struct {
	*baseDevice
	device     Device
	timeouts   policy.Timeout
	dispatcher routing.Dispatcher
	content    *session.Content
}

func tcpipErr(err tcpip.Error) error {
	return errors.New(err.String())
}
