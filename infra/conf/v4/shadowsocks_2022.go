package v4

import (
	"github.com/golang/protobuf/proto"

	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/infra/conf/cfgcommon"
	shadowsocks_2022 "github.com/v2fly/v2ray-core/v5/proxy/shadowsocks_2022"
)

type Shadowsocks2022ServerConfig struct {
	Method  string                       `json:"method"`
	Key     string                       `json:"key"`
	Level   byte                         `json:"level"`
	Email   string                       `json:"email"`
	Network *cfgcommon.NetworkList       `json:"network"`
	Users   []*Shadowsocks2022UserConfig `json:"users"`
}

func (v *Shadowsocks2022ServerConfig) Build() (proto.Message, error) {
	var network []net.Network
	if v.Network != nil {
		network = v.Network.Build()
	}
	return &shadowsocks_2022.ServerConfig{
		Method:  v.Method,
		Key:     v.Key,
		Level:   int32(v.Level),
		Email:   v.Email,
		Network: network,
	}, nil
}

type Shadowsocks2022MultiUserServerConfig struct {
	Method  string                       `json:"method"`
	Key     string                       `json:"key"`
	Network *cfgcommon.NetworkList       `json:"network"`
	Users   []*Shadowsocks2022UserConfig `json:"users"`
}

type Shadowsocks2022UserConfig struct {
	Key   string `json:"key"`
	Level byte   `json:"level"`
	Email string `json:"email"`
}

func (v *Shadowsocks2022MultiUserServerConfig) Build() (proto.Message, error) {
	var network []net.Network
	if v.Network != nil {
		network = v.Network.Build()
	}
	var users []*shadowsocks_2022.User
	for _, user := range v.Users {
		users = append(users, &shadowsocks_2022.User{
			Key:   user.Key,
			Level: int32(user.Level),
			Email: user.Email,
		})
	}
	return &shadowsocks_2022.MultiUserServerConfig{
		Method:  v.Method,
		Key:     v.Key,
		Network: network,
		Users:   users,
	}, nil
}

type Shadowsocks2022ClientConfig struct {
	Address *cfgcommon.Address `json:"address"`
	Port    uint16             `json:"port"`
	Method  string             `json:"method"`
	Key     string             `json:"key"`
}

func (v *Shadowsocks2022ClientConfig) Build() (proto.Message, error) {
	if v.Address == nil {
		return nil, newError("shadowsocks 2022: missing server address")
	}
	return &shadowsocks_2022.ClientConfig{
		Address: v.Address.Build(),
		Port:    uint32(v.Port),
		Method:  v.Method,
		Key:     v.Key,
	}, nil
}
