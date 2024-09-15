package conf

import (
	"strings"

	"github.com/golang/protobuf/proto"

	"github.com/v2fly/v2ray-core/v4/common/net/packetaddr"
	"github.com/v2fly/v2ray-core/v4/common/protocol"
	"github.com/v2fly/v2ray-core/v4/common/serial"
	"github.com/v2fly/v2ray-core/v4/infra/conf/cfgcommon"
	"github.com/v2fly/v2ray-core/v4/proxy/shadowsocks"
)

func cipherFromString(c string) shadowsocks.CipherType {
	switch strings.ToLower(c) {
	case "aes-128-gcm", "aead_aes_128_gcm":
		return shadowsocks.CipherType_AES_128_GCM
	case "aes-192-gcm", "aead_aes_192_gcm":
		return shadowsocks.CipherType_AES_192_GCM
	case "aes-256-gcm", "aead_aes_256_gcm":
		return shadowsocks.CipherType_AES_256_GCM
	case "chacha20-poly1305", "aead_chacha20_poly1305", "chacha20-ietf-poly1305":
		return shadowsocks.CipherType_CHACHA20_POLY1305
	case "xchacha20-poly1305", "aead_xchacha20_poly1305", "xchacha20-ietf-poly1305":
		return shadowsocks.CipherType_XCHACHA20_POLY1305
	case "none", "plain":
		return shadowsocks.CipherType_NONE
	default:
		return shadowsocks.CipherType_UNKNOWN
	}
}

type ShadowsocksServerConfig struct {
	Cipher         string                 `json:"method"`
	Password       string                 `json:"password"`
	UDP            bool                   `json:"udp"`
	Level          byte                   `json:"level"`
	Email          string                 `json:"email"`
	NetworkList    *cfgcommon.NetworkList `json:"network"`
	IVCheck        bool                   `json:"ivCheck"`
	PacketEncoding string                 `json:"packetEncoding"`
}

func (v *ShadowsocksServerConfig) Build() (proto.Message, error) {
	config := new(shadowsocks.ServerConfig)
	config.UdpEnabled = v.UDP
	config.Network = v.NetworkList.Build()

	if v.Password == "" {
		return nil, newError("Shadowsocks password is not specified.")
	}
	account := &shadowsocks.Account{
		Password: v.Password,
		IvCheck:  v.IVCheck,
	}
	account.CipherType = cipherFromString(v.Cipher)
	if account.CipherType == shadowsocks.CipherType_UNKNOWN {
		return nil, newError("unknown cipher method: ", v.Cipher)
	}

	config.User = &protocol.User{
		Email:   v.Email,
		Level:   uint32(v.Level),
		Account: serial.ToTypedMessage(account),
	}

	switch strings.ToLower(v.PacketEncoding) {
	case "packet":
		config.PacketEncoding = packetaddr.PacketAddrType_Packet
	case "", "none":
		config.PacketEncoding = packetaddr.PacketAddrType_None
	}

	return config, nil
}

type ShadowsocksServerTarget struct {
	Address                        *cfgcommon.Address `json:"address"`
	Port                           uint16             `json:"port"`
	Cipher                         string             `json:"method"`
	Password                       string             `json:"password"`
	Email                          string             `json:"email"`
	Ota                            bool               `json:"ota"`
	Level                          byte               `json:"level"`
	IVCheck                        bool               `json:"ivCheck"`
	ExperimentReducedIvHeadEntropy bool               `json:"experimentReducedIvHeadEntropy"`
}

type ShadowsocksClientConfig struct {
	Servers []*ShadowsocksServerTarget `json:"servers"`
}

func (v *ShadowsocksClientConfig) Build() (proto.Message, error) {
	config := new(shadowsocks.ClientConfig)

	if len(v.Servers) == 0 {
		return nil, newError("0 Shadowsocks server configured.")
	}

	serverSpecs := make([]*protocol.ServerEndpoint, len(v.Servers))
	for idx, server := range v.Servers {
		if server.Address == nil {
			return nil, newError("Shadowsocks server address is not set.")
		}
		if server.Port == 0 {
			return nil, newError("Invalid Shadowsocks port.")
		}
		if server.Password == "" {
			return nil, newError("Shadowsocks password is not specified.")
		}
		account := &shadowsocks.Account{
			Password: server.Password,
		}
		account.CipherType = cipherFromString(server.Cipher)
		if account.CipherType == shadowsocks.CipherType_UNKNOWN {
			return nil, newError("unknown cipher method: ", server.Cipher)
		}

		account.IvCheck = server.IVCheck
		account.ExperimentReducedIvHeadEntropy = server.ExperimentReducedIvHeadEntropy

		ss := &protocol.ServerEndpoint{
			Address: server.Address.Build(),
			Port:    uint32(server.Port),
			User: []*protocol.User{
				{
					Level:   uint32(server.Level),
					Email:   server.Email,
					Account: serial.ToTypedMessage(account),
				},
			},
		}

		serverSpecs[idx] = ss
	}

	config.Server = serverSpecs

	return config, nil
}
