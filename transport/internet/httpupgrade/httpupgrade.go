//go:build !confonly
// +build !confonly

package httpupgrade

import (
	"context"

	"github.com/v2fly/v2ray-core/v4/common"
)

//go:generate go run github.com/v2fly/v2ray-core/v4/common/errors/errorgen

const protocolName = "httpupgrade"

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return nil, newError("httpupgrade is a transport protocol.")
	}))
}
