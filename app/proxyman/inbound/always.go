package inbound

import (
	"context"

	core "github.com/v2fly/v2ray-core/v5"
	"github.com/v2fly/v2ray-core/v5/app/proxyman"
	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/dice"
	"github.com/v2fly/v2ray-core/v5/common/errors"
	"github.com/v2fly/v2ray-core/v5/common/mux"
	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/features/inbound"
	"github.com/v2fly/v2ray-core/v5/features/policy"
	"github.com/v2fly/v2ray-core/v5/features/stats"
	"github.com/v2fly/v2ray-core/v5/proxy"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
)

func getStatCounter(v *core.Instance, tag string) (stats.Counter, stats.Counter) {
	var uplinkCounter stats.Counter
	var downlinkCounter stats.Counter

	policy := v.GetFeature(policy.ManagerType()).(policy.Manager)
	if len(tag) > 0 && policy.ForSystem().Stats.InboundUplink {
		statsManager := v.GetFeature(stats.ManagerType()).(stats.Manager)
		name := "inbound>>>" + tag + ">>>traffic>>>uplink"
		c, _ := stats.GetOrRegisterCounter(statsManager, name)
		if c != nil {
			uplinkCounter = c
		}
	}
	if len(tag) > 0 && policy.ForSystem().Stats.InboundDownlink {
		statsManager := v.GetFeature(stats.ManagerType()).(stats.Manager)
		name := "inbound>>>" + tag + ">>>traffic>>>downlink"
		c, _ := stats.GetOrRegisterCounter(statsManager, name)
		if c != nil {
			downlinkCounter = c
		}
	}

	return uplinkCounter, downlinkCounter
}

type AlwaysOnInboundHandler struct {
	ctx            context.Context
	proxy          proxy.Inbound
	workers        []worker
	mux            *mux.Server
	tag            string
	receiverConfig *proxyman.ReceiverConfig
}

func NewAlwaysOnInboundHandler(ctx context.Context, tag string, receiverConfig *proxyman.ReceiverConfig, proxyConfig interface{}) (*AlwaysOnInboundHandler, error) {
	rawProxy, err := common.CreateObject(ctx, proxyConfig)
	if err != nil {
		return nil, err
	}
	p, ok := rawProxy.(proxy.Inbound)
	if !ok {
		return nil, newError("not an inbound proxy.")
	}
	return NewAlwaysOnInboundHandlerWithProxy(ctx, tag, receiverConfig, p, false)
}

func NewAlwaysOnInboundHandlerWithProxy(ctx context.Context, tag string, receiverConfig *proxyman.ReceiverConfig, p proxy.Inbound, inject bool) (*AlwaysOnInboundHandler, error) {
	h := &AlwaysOnInboundHandler{
		ctx:            ctx,
		proxy:          p,
		mux:            mux.NewServer(ctx),
		tag:            tag,
		receiverConfig: receiverConfig,
	}

	uplinkCounter, downlinkCounter := getStatCounter(core.MustFromContext(ctx), tag)

	nl := p.Network()
	pr := receiverConfig.PortRange
	address := receiverConfig.Listen.AsAddress()
	if address == nil {
		address = net.AnyIP
	}

	listeningAddrs := make(map[net.Address]bool)
	if address != net.AnyIP && address != net.AnyIPv6 {
		listeningAddrs[address] = true
	} else {
		interfaceAddrs, err := net.InterfaceAddrs()
		if err != nil {
			listeningAddrs[address] = true
		}
		for _, addr := range interfaceAddrs {
			listeningAddrs[net.IPAddress(addr.(*net.IPNet).IP)] = true
		}
	}

	mss, err := internet.ToMemoryStreamConfig(receiverConfig.StreamSettings)
	if err != nil {
		return nil, newError("failed to parse stream config").Base(err).AtWarning()
	}

	if pr == nil {
		if net.HasNetwork(nl, net.Network_UNIX) {
			newError("creating unix domain socket worker on ", address).AtDebug().WriteToLog()

			worker := &dsWorker{
				address:         address,
				proxy:           p,
				stream:          mss,
				tag:             tag,
				dispatcher:      h.mux,
				sniffingConfig:  receiverConfig.GetEffectiveSniffingSettings(),
				uplinkCounter:   uplinkCounter,
				downlinkCounter: downlinkCounter,
				ctx:             ctx,
			}
			h.workers = append(h.workers, worker)
		}
	}
	if pr != nil {
		for port := pr.From; port <= pr.To; port++ {
			if net.HasNetwork(nl, net.Network_TCP) {
				newError("creating stream worker on ", address, ":", port).AtDebug().WriteToLog()

				worker := &tcpWorker{
					address:         address,
					port:            net.Port(port),
					proxy:           p,
					stream:          mss,
					recvOrigDest:    receiverConfig.ReceiveOriginalDestination,
					tag:             tag,
					dispatcher:      h.mux,
					sniffingConfig:  receiverConfig.GetEffectiveSniffingSettings(),
					uplinkCounter:   uplinkCounter,
					downlinkCounter: downlinkCounter,
					ctx:             ctx,
					listeningAddrs:  listeningAddrs,
				}
				h.workers = append(h.workers, worker)
			}

			if net.HasNetwork(nl, net.Network_UDP) {
				worker := &udpWorker{
					ctx:             ctx,
					tag:             tag,
					proxy:           p,
					address:         address,
					port:            net.Port(port),
					dispatcher:      h.mux,
					sniffingConfig:  receiverConfig.GetEffectiveSniffingSettings(),
					uplinkCounter:   uplinkCounter,
					downlinkCounter: downlinkCounter,
					stream:          mss,
					listeningAddrs:  listeningAddrs,
				}
				h.workers = append(h.workers, worker)
			}
		}
	}

	if !inject {
		if i, ok := p.(inbound.Initializer); ok {
			i.Initialize(h)
		}
	}

	return h, nil
}

// Start implements common.Runnable.
func (h *AlwaysOnInboundHandler) Start() error {
	for _, worker := range h.workers {
		if err := worker.Start(); err != nil {
			return err
		}
	}
	return nil
}

// Close implements common.Closable.
func (h *AlwaysOnInboundHandler) Close() error {
	var errs []error
	for _, worker := range h.workers {
		errs = append(errs, worker.Close())
	}
	errs = append(errs, h.mux.Close())
	if err := errors.Combine(errs...); err != nil {
		return newError("failed to close all resources").Base(err)
	}
	return nil
}

func (h *AlwaysOnInboundHandler) GetRandomInboundProxy() (interface{}, net.Port, int) {
	if len(h.workers) == 0 {
		return nil, 0, 0
	}
	w := h.workers[dice.Roll(len(h.workers))]
	return w.Proxy(), w.Port(), 9999
}

func (h *AlwaysOnInboundHandler) AddUDPWorker(port net.Port) error {
	uplinkCounter, downlinkCounter := getStatCounter(core.MustFromContext(h.ctx), h.tag)
	address := h.receiverConfig.Listen.AsAddress()
	if address == nil {
		address = net.AnyIP
	}
	listeningAddrs := make(map[net.Address]bool)
	if address != net.AnyIP && address != net.AnyIPv6 {
		listeningAddrs[address] = true
	} else {
		interfaceAddrs, err := net.InterfaceAddrs()
		if err != nil {
			listeningAddrs[address] = true
		}
		for _, addr := range interfaceAddrs {
			listeningAddrs[net.IPAddress(addr.(*net.IPNet).IP)] = true
		}
	}
	mss, err := internet.ToMemoryStreamConfig(h.receiverConfig.StreamSettings)
	if err != nil {
		return newError("failed to parse stream config").Base(err).AtWarning()
	}
	worker := &udpWorker{
		ctx:             h.ctx,
		tag:             h.tag,
		proxy:           h.proxy,
		address:         address,
		port:            port,
		dispatcher:      h.mux,
		sniffingConfig:  h.receiverConfig.GetEffectiveSniffingSettings(),
		uplinkCounter:   uplinkCounter,
		downlinkCounter: downlinkCounter,
		stream:          mss,
		listeningAddrs:  listeningAddrs,
	}
	err = worker.Start()
	if err != nil {
		return newError("failed to parse stream config").Base(err).AtWarning()
	}
	h.workers = append(h.workers, worker)
	return nil
}

func (h *AlwaysOnInboundHandler) Tag() string {
	return h.tag
}

func (h *AlwaysOnInboundHandler) GetInbound() proxy.Inbound {
	return h.proxy
}
