package tun

import "github.com/v2fly/v2ray-core/v4/features"

type Tun interface {
	features.Feature
}

func TunType() interface{} {
	return (*Tun)(nil)
}
