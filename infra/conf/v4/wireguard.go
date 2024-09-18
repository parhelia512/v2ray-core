package v4

import (
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/golang/protobuf/proto"

	"github.com/v2fly/v2ray-core/v5/proxy/wireguard"
)

type WireGuardPeerConfig struct {
	PublicKey    string   `json:"publicKey"`
	PreSharedKey string   `json:"preSharedKey"`
	Endpoint     string   `json:"endpoint"`
	KeepAlive    uint32   `json:"keepAlive"`
	AllowedIPs   []string `json:"allowedIPs,omitempty"`
}

func (c *WireGuardPeerConfig) Build() (proto.Message, error) {
	var err error
	config := new(wireguard.PeerConfig)

	if c.PublicKey != "" {
		config.PublicKey, err = parseWireGuardKey(c.PublicKey)
		if err != nil {
			return nil, err
		}
	}

	if c.PreSharedKey != "" {
		config.PreSharedKey, err = parseWireGuardKey(c.PreSharedKey)
		if err != nil {
			return nil, err
		}
	}

	config.Endpoint = c.Endpoint
	// default 0
	config.KeepAlive = uint32(c.KeepAlive)
	if c.AllowedIPs == nil {
		config.AllowedIps = []string{"0.0.0.0/0", "::0/0"}
	} else {
		config.AllowedIps = c.AllowedIPs
	}

	return config, nil
}

type WireGuardClientConfig struct {
	SecretKey      string                 `json:"secretKey"`
	Address        []string               `json:"address"`
	Peers          []*WireGuardPeerConfig `json:"peers"`
	MTU            int32                  `json:"mtu"`
	NumWorkers     int32                  `json:"workers"`
	Reserved       []byte                 `json:"reserved"`
	DomainStrategy string                 `json:"domainStrategy"`
}

func (c *WireGuardClientConfig) Build() (proto.Message, error) {
	config := new(wireguard.DeviceConfig)

	var err error
	config.SecretKey, err = parseWireGuardKey(c.SecretKey)
	if err != nil {
		return nil, err
	}

	if c.Address == nil {
		// bogon ips
		config.Endpoint = []string{"10.0.0.1", "fd59:7153:2388:b5fd:0000:0000:0000:0001"}
	} else {
		config.Endpoint = c.Address
	}

	if c.Peers != nil {
		config.Peers = make([]*wireguard.PeerConfig, len(c.Peers))
		for i, p := range c.Peers {
			msg, err := p.Build()
			if err != nil {
				return nil, err
			}
			config.Peers[i] = msg.(*wireguard.PeerConfig)
		}
	}

	if c.MTU == 0 {
		config.Mtu = 1420
	} else {
		config.Mtu = c.MTU
	}
	// these a fallback code in wireguard-go code,
	// we don't need to process fallback manually
	config.NumWorkers = c.NumWorkers

	if len(c.Reserved) != 0 && len(c.Reserved) != 3 {
		return nil, newError(`"reserved" should be empty or 3 bytes`)
	}
	config.Reserved = c.Reserved

	switch strings.ToLower(c.DomainStrategy) {
	case "useip", "":
		config.DomainStrategy = wireguard.DeviceConfig_USE_IP
	case "useipv4":
		config.DomainStrategy = wireguard.DeviceConfig_USE_IP4
	case "useipv6":
		config.DomainStrategy = wireguard.DeviceConfig_USE_IP6
	case "preferipv4":
		config.DomainStrategy = wireguard.DeviceConfig_PREFER_IP4
	case "preferipv6":
		config.DomainStrategy = wireguard.DeviceConfig_PREFER_IP6
	default:
		return nil, newError("unsupported domain strategy: ", c.DomainStrategy)
	}

	return config, nil
}

func parseWireGuardKey(str string) (string, error) {
	var err error
	if len(str)%2 == 0 {
		_, err = hex.DecodeString(str)
		if err == nil {
			return str, nil
		}
	}
	var dat []byte
	str = strings.TrimSuffix(str, "=")
	if strings.ContainsRune(str, '+') || strings.ContainsRune(str, '/') {
		dat, err = base64.RawStdEncoding.DecodeString(str)
	} else {
		dat, err = base64.RawURLEncoding.DecodeString(str)
	}
	if err == nil {
		return hex.EncodeToString(dat), nil
	}
	return "", newError("failed to deserialize key").Base(err)
}
