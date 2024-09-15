//go:build !tun || !linux || !(amd64 || arm64)

package conf

import (
	"github.com/golang/protobuf/proto"
)

type TUNConfig struct{}

func (t *TUNConfig) Build() (proto.Message, error) { // nolint:staticcheck
	return nil, newError("TUN unsupported")
}
