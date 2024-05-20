package inbound

import (
	"context"

	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/features"
	"github.com/v2fly/v2ray-core/v5/proxy"
)

// Handler is the interface for handlers that process inbound connections.
//
// v2ray:api:stable
type Handler interface {
	common.Runnable
	// The tag of this handler.
	Tag() string

	// Deprecated: Do not use in new code.
	GetRandomInboundProxy() (interface{}, net.Port, int)
}

type AddUDPWorker interface {
	AddUDPWorker(port net.Port) error
}

type Initializer interface {
	Initialize(self Handler)
}

// Manager is a feature that manages InboundHandlers.
//
// v2ray:api:stable
type Manager interface {
	features.Feature
	// GetHandlers returns an InboundHandler for the given tag.
	GetHandler(ctx context.Context, tag string) (Handler, error)
	// AddHandler adds the given handler into this Manager.
	AddHandler(ctx context.Context, handler Handler) error

	// RemoveHandler removes a handler from Manager.
	RemoveHandler(ctx context.Context, tag string) error
}

type GetHandlerByInbound interface {
	GetHandlerByInbound(inbound proxy.Inbound) (Handler, error)
}

// ManagerType returns the type of Manager interface. Can be used for implementing common.HasType.
//
// v2ray:api:stable
func ManagerType() interface{} {
	return (*Manager)(nil)
}
