package v4

import (
	"google.golang.org/protobuf/proto"

	"github.com/v2fly/v2ray-core/v5/transport/internet/grpc"
)

type GunConfig struct {
	ServiceName       string `json:"serviceName"`
	AcceptXRealIP     bool   `json:"acceptXRealIP"`
	AcceptXForwardFor bool   `json:"acceptXForwardFor"`
}

func (g GunConfig) Build() (proto.Message, error) {
	return &grpc.Config{
		ServiceName:       g.ServiceName,
		AcceptXRealIP:     g.AcceptXRealIP,
		AcceptXForwardFor: g.AcceptXForwardFor,
	}, nil
}
