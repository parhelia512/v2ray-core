package conf

import (
	"github.com/golang/protobuf/proto"

	"github.com/v2fly/v2ray-core/v4/infra/conf/cfgcommon"
	shadowsocks2022 "github.com/v2fly/v2ray-core/v4/proxy/shadowsocks2022"
)

type Shadowsocks2022Config struct {
	Method  string             `json:"method"`
	PSK     []byte             `json:"psk"`
	IPSK    [][]byte           `json:"iPSK"`
	Address *cfgcommon.Address `json:"address"`
	Port    uint16             `json:"port"`
}

func (c *Shadowsocks2022Config) Build() (proto.Message, error) {
	config := new(shadowsocks2022.ClientConfig)
	config.Method = c.Method
	config.Psk = c.PSK
	config.Ipsk = c.IPSK
	config.Address = c.Address.Build()
	config.Port = uint32(c.Port)
	return config, nil
}
