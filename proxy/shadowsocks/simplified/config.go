package simplified

import (
	"context"
	"encoding/json"

	"github.com/golang/protobuf/jsonpb"

	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/protocol"
	"github.com/v2fly/v2ray-core/v5/common/serial"
	"github.com/v2fly/v2ray-core/v5/proxy/shadowsocks"
)

func (c *CipherTypeWrapper) UnmarshalJSONPB(unmarshaler *jsonpb.Unmarshaler, bytes []byte) error {
	var method string

	if err := json.Unmarshal(bytes, &method); err != nil {
		return err
	}

	if c.Value = shadowsocks.CipherFromString(method); c.Value == shadowsocks.CipherType_UNKNOWN {
		return newError("unknown cipher method: ", method)
	}

	return nil
}

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		simplifiedServer := config.(*ServerConfig)
		fullServer := &shadowsocks.ServerConfig{
			User: &protocol.User{
				Account: serial.ToTypedMessage(&shadowsocks.Account{
					Password:   simplifiedServer.Password,
					CipherType: simplifiedServer.Method.Value,
				}),
			},
			Network:        simplifiedServer.Networks.GetNetwork(),
			PacketEncoding: simplifiedServer.PacketEncoding,
			Plugin:         simplifiedServer.Plugin,
			PluginOpts:     simplifiedServer.PluginOpts,
			PluginArgs:     simplifiedServer.PluginArgs,
		}

		return common.CreateObject(ctx, fullServer)
	}))

	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		simplifiedClient := config.(*ClientConfig)
		fullClient := &shadowsocks.ClientConfig{
			Server: []*protocol.ServerEndpoint{
				{
					Address: simplifiedClient.Address,
					Port:    simplifiedClient.Port,
					User: []*protocol.User{
						{
							Account: serial.ToTypedMessage(&shadowsocks.Account{
								Password:                       simplifiedClient.Password,
								CipherType:                     simplifiedClient.Method.Value,
								ExperimentReducedIvHeadEntropy: simplifiedClient.ExperimentReducedIvHeadEntropy,
							}),
						},
					},
				},
			},
			Plugin:     simplifiedClient.Plugin,
			PluginOpts: simplifiedClient.PluginOpts,
			PluginArgs: simplifiedClient.PluginArgs,
		}

		return common.CreateObject(ctx, fullClient)
	}))
}
