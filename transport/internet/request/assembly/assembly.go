//go:build !confonly
// +build !confonly

package assembly

import (
	"context"

	"github.com/v2fly/v2ray-core/v4/common"
)

//go:generate go run github.com/v2fly/v2ray-core/v4/common/errors/errorgen

const protocolName = "request"

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return nil, newError("request is a transport protocol.")
	}))
}
