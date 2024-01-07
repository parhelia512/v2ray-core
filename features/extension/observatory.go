package extension

import (
	"context"

	"google.golang.org/protobuf/proto"

	"github.com/v2fly/v2ray-core/v5/features"
)

type Observatory interface {
	features.Feature
	GetObservation(ctx context.Context) (proto.Message, error)
}

func ObservatoryType() interface{} {
	return (*Observatory)(nil)
}
