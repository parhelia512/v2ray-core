package v4

import (
	"github.com/v2fly/v2ray-core/v4/app/tun"
	"github.com/v2fly/v2ray-core/v4/infra/conf/cfgcommon"
	"github.com/v2fly/v2ray-core/v4/infra/conf/cfgcommon/sniffer"
)

type TunConfig struct {
	Name           string                  `json:"name"`
	MTU            uint32                  `json:"MTU"`
	Address        *cfgcommon.StringList   `json:"address"`
	AutoRoute      bool                    `json:"autoRoute"`
	Stack          string                  `json:"stack"`
	Tag            string                  `json:"tag"`
	UserLevel      uint32                  `json:"userLevel"`
	SniffingConfig *sniffer.SniffingConfig `json:"sniffing"`
}

func (c *TunConfig) Build() (*tun.Config, error) {
	config := &tun.Config{
		Name:      c.Name,
		Mtu:       c.MTU,
		AutoRoute: c.AutoRoute,
		Stack:     c.Stack,
		UserLevel: c.UserLevel,
		Tag:       c.Tag,
	}
	if c.Address != nil && c.Address.Len() > 0 {
		config.Address = *c.Address
	}
	if c.SniffingConfig != nil {
		sniffingConfig, err := c.SniffingConfig.Build()
		if err != nil {
			return nil, newError("failed to build sniffing config").Base(err)
		}
		config.Sniffing = sniffingConfig
	}
	return config, nil
}
