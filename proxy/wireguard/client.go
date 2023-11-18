package wireguard

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"

	core "github.com/v2fly/v2ray-core/v5"
	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/buf"
	"github.com/v2fly/v2ray-core/v5/common/log"
	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/protocol"
	"github.com/v2fly/v2ray-core/v5/common/session"
	"github.com/v2fly/v2ray-core/v5/common/signal"
	"github.com/v2fly/v2ray-core/v5/common/task"
	"github.com/v2fly/v2ray-core/v5/features/dns"
	"github.com/v2fly/v2ray-core/v5/features/policy"
	"github.com/v2fly/v2ray-core/v5/transport"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
)

// Handler is an outbound connection that silently swallow the entire payload.
type Handler struct {
	conf          *DeviceConfig
	net           Tunnel
	bind          *netBindClient
	policyManager policy.Manager
	dns           dns.Client
	// cached configuration
	ipc              string
	endpoints        []netip.Addr
	hasIPv4, hasIPv6 bool
	wgLock           sync.Mutex
}

// New creates a new wireguard handler.
func New(ctx context.Context, conf *DeviceConfig) (*Handler, error) {
	v := core.MustFromContext(ctx)

	endpoints, hasIPv4, hasIPv6, err := parseEndpoints(conf)
	if err != nil {
		return nil, err
	}

	d := v.GetFeature(dns.ClientType()).(dns.Client)
	return &Handler{
		conf:          conf,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		dns:           d,
		ipc:           createIPCRequest(conf),
		endpoints:     endpoints,
		hasIPv4:       hasIPv4,
		hasIPv6:       hasIPv6,
	}, nil
}

func (h *Handler) processWireGuard(dialer internet.Dialer) (err error) {
	h.wgLock.Lock()
	defer h.wgLock.Unlock()

	if h.bind != nil && h.bind.dialer == dialer && h.net != nil {
		return nil
	}

	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  "switching dialer",
	})

	if h.net != nil {
		_ = h.net.Close()
		h.net = nil
	}
	if h.bind != nil {
		_ = h.bind.Close()
		h.bind = nil
	}

	// bind := conn.NewStdNetBind() // TODO: conn.Bind wrapper for dialer
	bind := &netBindClient{
		netBind: netBind{
			dns: h.dns,
			dnsOption: dns.IPOption{
				IPv4Enable: h.hasIPv4,
				IPv6Enable: h.hasIPv6,
			},
			workers: int(h.conf.NumWorkers),
		},
		dialer:   dialer,
		reserved: h.conf.Reserved,
	}
	defer func() {
		if err != nil {
			_ = bind.Close()
		}
	}()

	h.net, err = h.makeVirtualTun(bind)
	if err != nil {
		return newError("failed to create virtual tun interface").Base(err)
	}
	h.bind = bind
	return nil
}

// Process implements OutboundHandler.Dispatch().
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbound := session.OutboundFromContext(ctx)
	if outbound == nil || !outbound.Target.IsValid() {
		return newError("target not specified")
	}

	if err := h.processWireGuard(dialer); err != nil {
		return err
	}

	// Destination of the inner request.
	destination := outbound.Target
	command := protocol.RequestCommandTCP
	if destination.Network == net.Network_UDP {
		command = protocol.RequestCommandUDP
	}

	// resolve dns
	addr := destination.Address
	if addr.Family().IsDomain() {
		ips, err := dns.LookupIPWithOption(h.dns, addr.Domain(), dns.IPOption{
			IPv4Enable: h.hasIPv4 && h.conf.DomainStrategy != DeviceConfig_USE_IP6,
			IPv6Enable: h.hasIPv6 && h.conf.DomainStrategy != DeviceConfig_USE_IP4,
		})
		if err != nil {
			return newError("failed to lookup DNS").Base(err)
		}
		if len(ips) == 0 {
			return dns.ErrEmptyResponse
		}
		if h.conf.DomainStrategy == DeviceConfig_PREFER_IP4 || h.conf.DomainStrategy == DeviceConfig_PREFER_IP6 {
			for _, ip := range ips {
				if ip.To4() != nil == (h.conf.DomainStrategy == DeviceConfig_PREFER_IP4) {
					addr = net.IPAddress(ip)
				}
			}
		} else {
			addr = net.IPAddress(ips[0])
		}
	}

	p := h.policyManager.ForLevel(0)

	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, p.Timeouts.ConnectionIdle)
	addrPort := netip.AddrPortFrom(toNetIpAddr(addr), destination.Port.Value())

	var requestFunc func() error
	var responseFunc func() error

	if command == protocol.RequestCommandTCP {
		conn, err := h.net.DialContextTCPAddrPort(ctx, addrPort)
		if err != nil {
			return newError("failed to create TCP connection").Base(err)
		}
		defer conn.Close()

		requestFunc = func() error {
			defer timer.SetTimeout(p.Timeouts.DownlinkOnly)
			return buf.Copy(link.Reader, buf.NewWriter(conn), buf.UpdateActivity(timer))
		}
		responseFunc = func() error {
			defer timer.SetTimeout(p.Timeouts.UplinkOnly)
			return buf.Copy(buf.NewReader(conn), link.Writer, buf.UpdateActivity(timer))
		}
	} else if command == protocol.RequestCommandUDP {
		conn, err := h.net.DialUDPAddrPort(netip.AddrPort{}, addrPort)
		if err != nil {
			return newError("failed to create UDP connection").Base(err)
		}
		defer conn.Close()

		requestFunc = func() error {
			defer timer.SetTimeout(p.Timeouts.DownlinkOnly)
			return buf.Copy(link.Reader, buf.NewWriter(conn), buf.UpdateActivity(timer))
		}
		responseFunc = func() error {
			defer timer.SetTimeout(p.Timeouts.UplinkOnly)
			return buf.Copy(buf.NewReader(conn), link.Writer, buf.UpdateActivity(timer))
		}
	}

	responseDonePost := task.OnSuccess(responseFunc, task.Close(link.Writer))
	if err := task.Run(ctx, requestFunc, responseDonePost); err != nil {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		return newError("connection ends").Base(err)
	}

	return nil
}

// creates a tun interface on netstack given a configuration
func (h *Handler) makeVirtualTun(bind *netBindClient) (Tunnel, error) {
	t, err := CreateTun(h.endpoints, int(h.conf.Mtu))
	if err != nil {
		return nil, err
	}

	bind.dnsOption.IPv4Enable = h.hasIPv4
	bind.dnsOption.IPv6Enable = h.hasIPv6

	if err = t.BuildDevice(h.ipc, bind); err != nil {
		_ = t.Close()
		return nil, err
	}
	return t, nil
}

// convert endpoint string to netip.Addr
func parseEndpoints(conf *DeviceConfig) ([]netip.Addr, bool, bool, error) {
	var hasIPv4, hasIPv6 bool

	endpoints := make([]netip.Addr, len(conf.Endpoint))
	for i, str := range conf.Endpoint {
		var addr netip.Addr
		if strings.Contains(str, "/") {
			prefix, err := netip.ParsePrefix(str)
			if err != nil {
				return nil, false, false, err
			}
			addr = prefix.Addr()
		} else {
			var err error
			addr, err = netip.ParseAddr(str)
			if err != nil {
				return nil, false, false, err
			}
		}
		endpoints[i] = addr

		if addr.Is4() {
			hasIPv4 = true
		} else if addr.Is6() {
			hasIPv6 = true
		}
	}

	return endpoints, hasIPv4, hasIPv6, nil
}

// serialize the config into an IPC request
func createIPCRequest(conf *DeviceConfig) string {
	var request strings.Builder

	request.WriteString(fmt.Sprintf("private_key=%s\n", conf.SecretKey))

	for _, peer := range conf.Peers {
		if peer.PublicKey != "" {
			request.WriteString(fmt.Sprintf("public_key=%s\n", peer.PublicKey))
		}

		if peer.PreSharedKey != "" {
			request.WriteString(fmt.Sprintf("preshared_key=%s\n", peer.PreSharedKey))
		}

		if peer.Endpoint != "" {
			request.WriteString(fmt.Sprintf("endpoint=%s\n", peer.Endpoint))
		}

		for _, ip := range peer.AllowedIps {
			request.WriteString(fmt.Sprintf("allowed_ip=%s\n", ip))
		}

		if peer.KeepAlive != 0 {
			request.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", peer.KeepAlive))
		}
	}

	return request.String()[:request.Len()]
}

func init() {
	common.Must(common.RegisterConfig((*DeviceConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*DeviceConfig))
	}))
}
