package v4

import (
	"github.com/v2fly/v2ray-core/v5/common/serial"
	"github.com/v2fly/v2ray-core/v5/transport/global"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
)

type TransportConfig struct {
	TCPConfig         *TCPConfig          `json:"tcpSettings"`
	KCPConfig         *KCPConfig          `json:"kcpSettings"`
	WSConfig          *WebSocketConfig    `json:"wsSettings"`
	HTTPConfig        *HTTPConfig         `json:"httpSettings"`
	DSConfig          *DomainSocketConfig `json:"dsSettings"`
	QUICConfig        *QUICConfig         `json:"quicSettings"`
	GunConfig         *GunConfig          `json:"gunSettings"`
	GRPCConfig        *GunConfig          `json:"grpcSettings"`
	MeekConfig        *MeekConfig         `json:"meekSettings"`
	HTTPUpgradeConfig *HTTPUpgradeConfig  `json:"httpupgradeSettings"`
	Hysteria2Config   *Hysteria2Config    `json:"hysteria2Settings"`
}

// Build implements Buildable.
func (c *TransportConfig) Build() (*global.Config, error) {
	config := new(global.Config)

	if c.TCPConfig != nil {
		ts, err := c.TCPConfig.Build()
		if err != nil {
			return nil, newError("failed to build TCP config").Base(err).AtError()
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "tcp",
			Settings:     serial.ToTypedMessage(ts),
		})
	}

	if c.KCPConfig != nil {
		ts, err := c.KCPConfig.Build()
		if err != nil {
			return nil, newError("failed to build mKCP config").Base(err).AtError()
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "mkcp",
			Settings:     serial.ToTypedMessage(ts),
		})
	}

	if c.WSConfig != nil {
		ts, err := c.WSConfig.Build()
		if err != nil {
			return nil, newError("failed to build WebSocket config").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "websocket",
			Settings:     serial.ToTypedMessage(ts),
		})
	}

	if c.HTTPConfig != nil {
		ts, err := c.HTTPConfig.Build()
		if err != nil {
			return nil, newError("Failed to build HTTP config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "http",
			Settings:     serial.ToTypedMessage(ts),
		})
	}

	if c.DSConfig != nil {
		ds, err := c.DSConfig.Build()
		if err != nil {
			return nil, newError("Failed to build DomainSocket config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "domainsocket",
			Settings:     serial.ToTypedMessage(ds),
		})
	}

	if c.QUICConfig != nil {
		qs, err := c.QUICConfig.Build()
		if err != nil {
			return nil, newError("Failed to build QUIC config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "quic",
			Settings:     serial.ToTypedMessage(qs),
		})
	}

	if c.GunConfig == nil {
		c.GunConfig = c.GRPCConfig
	}
	if c.GunConfig != nil {
		gs, err := c.GunConfig.Build()
		if err != nil {
			return nil, newError("Failed to build Gun config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "gun",
			Settings:     serial.ToTypedMessage(gs),
		})
	}

	if c.MeekConfig != nil {
		ms, err := c.MeekConfig.Build()
		if err != nil {
			return nil, newError("Failed to build Meek config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "meek",
			Settings:     serial.ToTypedMessage(ms),
		})
	}

	if c.HTTPUpgradeConfig != nil {
		hs, err := c.HTTPUpgradeConfig.Build()
		if err != nil {
			return nil, newError("Failed to build HTTPUpgrade config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "httpupgrade",
			Settings:     serial.ToTypedMessage(hs),
		})
	}

	if c.Hysteria2Config != nil {
		hs, err := c.Hysteria2Config.Build()
		if err != nil {
			return nil, newError("Failed to build Hysteria2 config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "hysteria2",
			Settings:     serial.ToTypedMessage(hs),
		})
	}

	return config, nil
}
