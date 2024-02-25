package v4

import (
	"google.golang.org/protobuf/proto"

	"github.com/v2fly/v2ray-core/v5/transport/internet/grpc"
)

type GunConfig struct {
	ServiceName         string `json:"serviceName"`
	Mode                string `json:"mode"`
	IdleTimeout         int32  `json:"idle_timeout"`
	HealthCheckTimeout  int32  `json:"health_check_timeout"`
	PermitWithoutStream bool   `json:"permit_without_stream"`
	InitialWindowsSize  int32  `json:"initial_windows_size"`
	AcceptXRealIP       bool   `json:"acceptXRealIP"`
	AcceptXForwardFor   bool   `json:"acceptXForwardFor"`
}

func (g GunConfig) Build() (proto.Message, error) {
	var mode grpc.Mode
	switch g.Mode {
	case "", "gun":
		mode = grpc.Mode_Gun
	case "multi":
		mode = grpc.Mode_Multi
	default:
		return nil, newError("undefined grpc mode: ", g.Mode)
	}

	if g.IdleTimeout <= 0 {
		g.IdleTimeout = 0
	}
	if g.HealthCheckTimeout <= 0 {
		g.HealthCheckTimeout = 0
	}
	if g.InitialWindowsSize < 0 {
		g.InitialWindowsSize = 0
	}
	return &grpc.Config{
		ServiceName:         g.ServiceName,
		Mode:                mode,
		IdleTimeout:         g.IdleTimeout,
		HealthCheckTimeout:  g.HealthCheckTimeout,
		PermitWithoutStream: g.PermitWithoutStream,
		InitialWindowsSize:  g.InitialWindowsSize,
		AcceptXRealIP:       g.AcceptXRealIP,
		AcceptXForwardFor:   g.AcceptXForwardFor,
	}, nil
}
