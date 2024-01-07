package v4

import (
	"google.golang.org/protobuf/proto"

	"github.com/v2fly/v2ray-core/v5/app/restfulapi"
)

type RestfulAPIConfig struct {
	ListenAddr string `json:"listenAddr"`
	ListenPort int32  `json:"listenPort"`
	AuthToken  string `json:"authToken"`
}

func (r *RestfulAPIConfig) Build() (proto.Message, error) {
	return &restfulapi.Config{
		ListenAddr: r.ListenAddr,
		ListenPort: r.ListenPort,
		AuthToken:  r.AuthToken,
	}, nil
}
