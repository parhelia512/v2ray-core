package v4

import (
	"github.com/golang/protobuf/proto"

	"github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"github.com/v2fly/v2ray-core/v5/app/tun"
	"github.com/v2fly/v2ray-core/v5/infra/conf/cfgcommon"
	"github.com/v2fly/v2ray-core/v5/infra/conf/cfgcommon/socketcfg"
	"github.com/v2fly/v2ray-core/v5/infra/conf/rule"
)

type TUNConfig struct {
	Name                  string                   `json:"name"`
	MTU                   uint32                   `json:"mtu"`
	Level                 uint32                   `json:"level"`
	PacketEncoding        cfgcommon.PacketAddrType `json:"packetEncoding"`
	Tag                   string                   `json:"tag"`
	IPs                   cfgcommon.StringList     `json:"ips"`
	Routes                cfgcommon.StringList     `json:"routes"`
	EnablePromiscuousMode bool                     `json:"enablePromiscuousMode"`
	EnableSpoofing        bool                     `json:"enableSpoofing"`
	SocketSettings        *socketcfg.SocketConfig  `json:"sockopt"`
}

func (t *TUNConfig) Build() (proto.Message, error) {
	config := new(tun.Config)
	var ips []*routercommon.CIDR
	for _, ip := range t.IPs {
		parsedIP, err := rule.ParseIP(ip)
		if err != nil {
			return nil, newError("invalid IP: ", ip).Base(err)
		}
		ips = append(ips, parsedIP)
	}
	if len(ips) > 0 {
		config.Ips = ips
	}
	var routes []*routercommon.CIDR
	for _, route := range t.Routes {
		parsedRoute, err := rule.ParseIP(route)
		if err != nil {
			return nil, newError("invalid route: ", route).Base(err)
		}
		routes = append(routes, parsedRoute)
	}
	if len(routes) > 0 {
		config.Routes = routes
	}
	if t.SocketSettings != nil {
		ss, err := t.SocketSettings.Build()
		if err != nil {
			return nil, newError("Failed to build sockopt.").Base(err)
		}
		config.SocketSettings = ss
	}
	config.Name = t.Name
	config.Mtu = t.MTU
	config.UserLevel = t.Level
	config.PacketEncoding = t.PacketEncoding.Build()
	config.Tag = t.Tag
	config.EnablePromiscuousMode = t.EnablePromiscuousMode
	config.EnableSpoofing = t.EnableSpoofing
	return config, nil
}
