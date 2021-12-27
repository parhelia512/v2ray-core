package tun

import (
	"context"
	"runtime"

	"golang.zx2c4.com/go118/netip"

	core "github.com/v2fly/v2ray-core/v4"
	"github.com/v2fly/v2ray-core/v4/common"
	"github.com/v2fly/v2ray-core/v4/common/session"
	"github.com/v2fly/v2ray-core/v4/features/policy"
	"github.com/v2fly/v2ray-core/v4/features/routing"
)

//go:generate go run github.com/v2fly/v2ray-core/v4/common/errors/errorgen

func New(ctx context.Context, config *Config) (interface{}, error) {
	tunName := config.Name
	if tunName == "" {
		switch runtime.GOOS {
		case "darwin":
			tunName = "utun"
		case "windows":
			tunName = "Transproxy"
		default:
			tunName = "tun0"
		}
	}
	mtu := config.Mtu
	if mtu == 0 {
		mtu = 1500
	}

	addresses := config.Address
	if len(addresses) == 0 {
		addresses = []string{
			"192.16.0.1/32",
			"fdfe:dcba:9876::1/128",
		}
	}

	var ranges []netip.Prefix
	var has4, has6 bool
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address)
		if err != nil {
			return nil, newError("failed to parse tun address ", address).Base(err)
		}
		ranges = append(ranges, prefix)
		if prefix.Addr().Is4() {
			if has4 {
				return nil, newError("only one ipv4 address is allowed")
			}
			has4 = true
		} else {
			has6 = true
		}
	}
	base := baseDevice{ranges, has4, has6, config}
	device, err := createDevice(&base, tunName, int(mtu))
	if err != nil {
		return nil, newError("failed to create tun device").Base(err)
	}
	err = device.SetAddress()
	if err != nil {
		return nil, newError("failed to set device address").Base(err)
	}
	if config.AutoRoute {
		err = device.SetRoute()
		if err != nil {
			return nil, newError("failed to set route automatically").Base(err)
		}
	}

	baseTun := baseTun{baseDevice: &base, device: device}
	if err := core.RequireFeatures(ctx, func(dispatcher routing.Dispatcher, policyManager policy.Manager) {
		baseTun.dispatcher = dispatcher
		baseTun.timeouts = policyManager.ForLevel(config.UserLevel).Timeouts
	}); err != nil {
		return nil, newError("failed to get default dispatcher").Base(err).AtError()
	}

	if config.Sniffing != nil {
		baseTun.content = &session.Content{SniffingRequest: session.SniffingRequest{
			Enabled:                        config.Sniffing.Enabled,
			OverrideDestinationForProtocol: config.Sniffing.DestinationOverride,
			MetadataOnly:                   config.Sniffing.MetadataOnly,
			RouteOnly:                      config.Sniffing.RouteOnly,
		}}
	}

	switch config.Stack {
	case "gvisor", "":
		return newGVisor(ctx, &baseTun)
	default:
		return nil, newError("unknown device stack type: ", config.Stack)
	}
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		c, err := New(ctx, config.(*Config))
		if err != nil {
			return nil, newError("failed to create tun").Base(err)
		}
		return c, nil
	}))
}
