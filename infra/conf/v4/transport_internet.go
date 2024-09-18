package v4

import (
	"encoding/json"
	"strings"

	"github.com/golang/protobuf/proto"

	"github.com/v2fly/v2ray-core/v5/common/protocol"
	"github.com/v2fly/v2ray-core/v5/common/serial"
	"github.com/v2fly/v2ray-core/v5/infra/conf/cfgcommon"
	"github.com/v2fly/v2ray-core/v5/infra/conf/cfgcommon/loader"
	"github.com/v2fly/v2ray-core/v5/infra/conf/cfgcommon/socketcfg"
	"github.com/v2fly/v2ray-core/v5/infra/conf/cfgcommon/tlscfg"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
	"github.com/v2fly/v2ray-core/v5/transport/internet/domainsocket"
	"github.com/v2fly/v2ray-core/v5/transport/internet/dtls"
	httpheader "github.com/v2fly/v2ray-core/v5/transport/internet/headers/http"
	"github.com/v2fly/v2ray-core/v5/transport/internet/http"
	"github.com/v2fly/v2ray-core/v5/transport/internet/httpupgrade"
	"github.com/v2fly/v2ray-core/v5/transport/internet/hysteria2"
	"github.com/v2fly/v2ray-core/v5/transport/internet/kcp"
	"github.com/v2fly/v2ray-core/v5/transport/internet/quic"
	"github.com/v2fly/v2ray-core/v5/transport/internet/request/stereotype/meek"
	"github.com/v2fly/v2ray-core/v5/transport/internet/splithttp"
	"github.com/v2fly/v2ray-core/v5/transport/internet/tcp"
	"github.com/v2fly/v2ray-core/v5/transport/internet/websocket"
)

var (
	kcpHeaderLoader = loader.NewJSONConfigLoader(loader.ConfigCreatorCache{
		"none":         func() interface{} { return new(NoOpAuthenticator) },
		"srtp":         func() interface{} { return new(SRTPAuthenticator) },
		"utp":          func() interface{} { return new(UTPAuthenticator) },
		"wechat-video": func() interface{} { return new(WechatVideoAuthenticator) },
		"dtls":         func() interface{} { return new(DTLSAuthenticator) },
		"wireguard":    func() interface{} { return new(WireguardAuthenticator) },
	}, "type", "")

	tcpHeaderLoader = loader.NewJSONConfigLoader(loader.ConfigCreatorCache{
		"none": func() interface{} { return new(NoOpConnectionAuthenticator) },
		"http": func() interface{} { return new(Authenticator) },
	}, "type", "")
)

type KCPConfig struct {
	Mtu             *uint32         `json:"mtu"`
	Tti             *uint32         `json:"tti"`
	UpCap           *uint32         `json:"uplinkCapacity"`
	DownCap         *uint32         `json:"downlinkCapacity"`
	Congestion      *bool           `json:"congestion"`
	ReadBufferSize  *uint32         `json:"readBufferSize"`
	WriteBufferSize *uint32         `json:"writeBufferSize"`
	HeaderConfig    json.RawMessage `json:"header"`
	Seed            *string         `json:"seed"`
}

// Build implements Buildable.
func (c *KCPConfig) Build() (proto.Message, error) {
	config := new(kcp.Config)

	if c.Mtu != nil {
		mtu := *c.Mtu
		if mtu < 576 || mtu > 1460 {
			return nil, newError("invalid mKCP MTU size: ", mtu).AtError()
		}
		config.Mtu = &kcp.MTU{Value: mtu}
	}
	if c.Tti != nil {
		tti := *c.Tti
		if tti < 10 || tti > 100 {
			return nil, newError("invalid mKCP TTI: ", tti).AtError()
		}
		config.Tti = &kcp.TTI{Value: tti}
	}
	if c.UpCap != nil {
		config.UplinkCapacity = &kcp.UplinkCapacity{Value: *c.UpCap}
	}
	if c.DownCap != nil {
		config.DownlinkCapacity = &kcp.DownlinkCapacity{Value: *c.DownCap}
	}
	if c.Congestion != nil {
		config.Congestion = *c.Congestion
	}
	if c.ReadBufferSize != nil {
		size := *c.ReadBufferSize
		if size > 0 {
			config.ReadBuffer = &kcp.ReadBuffer{Size: size * 1024 * 1024}
		} else {
			config.ReadBuffer = &kcp.ReadBuffer{Size: 512 * 1024}
		}
	}
	if c.WriteBufferSize != nil {
		size := *c.WriteBufferSize
		if size > 0 {
			config.WriteBuffer = &kcp.WriteBuffer{Size: size * 1024 * 1024}
		} else {
			config.WriteBuffer = &kcp.WriteBuffer{Size: 512 * 1024}
		}
	}
	if len(c.HeaderConfig) > 0 {
		headerConfig, _, err := kcpHeaderLoader.Load(c.HeaderConfig)
		if err != nil {
			return nil, newError("invalid mKCP header config.").Base(err).AtError()
		}
		ts, err := headerConfig.(cfgcommon.Buildable).Build()
		if err != nil {
			return nil, newError("invalid mKCP header config").Base(err).AtError()
		}
		config.HeaderConfig = serial.ToTypedMessage(ts)
	}

	if c.Seed != nil {
		config.Seed = &kcp.EncryptionSeed{Seed: *c.Seed}
	}

	return config, nil
}

type TCPConfig struct {
	HeaderConfig        json.RawMessage `json:"header"`
	AcceptProxyProtocol bool            `json:"acceptProxyProtocol"`
}

// Build implements Buildable.
func (c *TCPConfig) Build() (proto.Message, error) {
	config := new(tcp.Config)
	if len(c.HeaderConfig) > 0 {
		headerConfig, _, err := tcpHeaderLoader.Load(c.HeaderConfig)
		if err != nil {
			return nil, newError("invalid TCP header config").Base(err).AtError()
		}
		ts, err := headerConfig.(cfgcommon.Buildable).Build()
		if err != nil {
			return nil, newError("invalid TCP header config").Base(err).AtError()
		}
		config.HeaderSettings = serial.ToTypedMessage(ts)
	}
	if c.AcceptProxyProtocol {
		config.AcceptProxyProtocol = c.AcceptProxyProtocol
	}
	return config, nil
}

type Hy2ConfigCongestion struct {
	Type     string `json:"type"`
	UpMbps   uint64 `json:"up_mbps"`
	DownMbps uint64 `json:"down_mbps"`
}

type Hyteria2ConfigOBFS struct {
	Type     string `json:"type"`
	Password string `json:"password"`
}

type Hy2Config struct {
	Password              string              `json:"password"`
	Congestion            Hy2ConfigCongestion `json:"congestion"`
	UseUdpExtension       bool                `json:"use_udp_extension"`
	IgnoreClientBandwidth bool                `json:"ignore_client_bandwidth"`
	OBFS                  Hyteria2ConfigOBFS  `json:"obfs"`
}

// Build implements Buildable.
func (c *Hy2Config) Build() (proto.Message, error) {
	return &hysteria2.Config{Password: c.Password,
		Congestion: &hysteria2.Congestion{
			Type:     c.Congestion.Type,
			DownMbps: c.Congestion.DownMbps,
			UpMbps:   c.Congestion.UpMbps,
		},
		UseUdpExtension:       c.UseUdpExtension,
		IgnoreClientBandwidth: c.IgnoreClientBandwidth,
		Obfs: &hysteria2.OBFS{
			Type:     c.OBFS.Type,
			Password: c.OBFS.Password,
		},
	}, nil
}

type WebSocketConfig struct {
	Path                 string            `json:"path"`
	Headers              map[string]string `json:"headers"`
	AcceptProxyProtocol  bool              `json:"acceptProxyProtocol"`
	MaxEarlyData         int32             `json:"maxEarlyData"`
	UseBrowserForwarding bool              `json:"useBrowserForwarding"`
	EarlyDataHeaderName  string            `json:"earlyDataHeaderName"`
}

// Build implements Buildable.
func (c *WebSocketConfig) Build() (proto.Message, error) {
	path := c.Path
	header := make([]*websocket.Header, 0, 32)
	for key, value := range c.Headers {
		header = append(header, &websocket.Header{
			Key:   key,
			Value: value,
		})
	}
	config := &websocket.Config{
		Path:                 path,
		Header:               header,
		MaxEarlyData:         c.MaxEarlyData,
		UseBrowserForwarding: c.UseBrowserForwarding,
		EarlyDataHeaderName:  c.EarlyDataHeaderName,
	}
	if c.AcceptProxyProtocol {
		config.AcceptProxyProtocol = c.AcceptProxyProtocol
	}
	return config, nil
}

type HTTPConfig struct {
	Host    *cfgcommon.StringList            `json:"host"`
	Path    string                           `json:"path"`
	Method  string                           `json:"method"`
	Headers map[string]*cfgcommon.StringList `json:"headers"`
}

// Build implements Buildable.
func (c *HTTPConfig) Build() (proto.Message, error) {
	config := &http.Config{
		Path: c.Path,
	}
	if c.Host != nil {
		config.Host = []string(*c.Host)
	}
	if c.Method != "" {
		config.Method = c.Method
	}
	if len(c.Headers) > 0 {
		config.Header = make([]*httpheader.Header, 0, len(c.Headers))
		headerNames := sortMapKeys(c.Headers)
		for _, key := range headerNames {
			value := c.Headers[key]
			if value == nil {
				return nil, newError("empty HTTP header value: " + key).AtError()
			}
			config.Header = append(config.Header, &httpheader.Header{
				Name:  key,
				Value: append([]string(nil), (*value)...),
			})
		}
	}
	return config, nil
}

type HTTPUpgradeConfig struct {
	Host    string            `json:"host"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
}

// Build implements Buildable.
func (c *HTTPUpgradeConfig) Build() (proto.Message, error) {
	return &httpupgrade.Config{
		Host:    c.Host,
		Path:    c.Path,
		Headers: c.Headers,
	}, nil
}

type QUICConfig struct {
	Header   json.RawMessage `json:"header"`
	Security string          `json:"security"`
	Key      string          `json:"key"`
}

// Build implements Buildable.
func (c *QUICConfig) Build() (proto.Message, error) {
	config := &quic.Config{
		Key: c.Key,
	}

	if len(c.Header) > 0 {
		headerConfig, _, err := kcpHeaderLoader.Load(c.Header)
		if err != nil {
			return nil, newError("invalid QUIC header config.").Base(err).AtError()
		}
		ts, err := headerConfig.(cfgcommon.Buildable).Build()
		if err != nil {
			return nil, newError("invalid QUIC header config").Base(err).AtError()
		}
		config.Header = serial.ToTypedMessage(ts)
	}

	var st protocol.SecurityType
	switch strings.ToLower(c.Security) {
	case "aes-128-gcm":
		st = protocol.SecurityType_AES128_GCM
	case "chacha20-poly1305":
		st = protocol.SecurityType_CHACHA20_POLY1305
	default:
		st = protocol.SecurityType_NONE
	}

	config.Security = &protocol.SecurityConfig{
		Type: st,
	}

	return config, nil
}

type DomainSocketConfig struct {
	Path     string `json:"path"`
	Abstract bool   `json:"abstract"`
	Padding  bool   `json:"padding"`
}

// Build implements Buildable.
func (c *DomainSocketConfig) Build() (proto.Message, error) {
	return &domainsocket.Config{
		Path:     c.Path,
		Abstract: c.Abstract,
		Padding:  c.Padding,
	}, nil
}

type MeekConfig struct {
	URL string `json:"url"`
}

// Build implements Buildable.
func (c *MeekConfig) Build() (proto.Message, error) {
	return &meek.Config{Url: c.URL}, nil
}

type DTLSConfig struct {
	Mode                   string `json:"mode"`
	PSK                    []byte `json:"psk"`
	MTU                    uint32 `json:"mtu"`
	ReplayProtectionWindow uint32 `json:"replayProtectionWindow"`
}

// Build implements Buildable.
func (c *DTLSConfig) Build() (proto.Message, error) {
	config := &dtls.Config{
		Psk:                    c.PSK,
		Mtu:                    c.MTU,
		ReplayProtectionWindow: c.ReplayProtectionWindow,
	}
	switch strings.ToLower(c.Mode) {
	case "psk":
		config.Mode = dtls.DTLSMode_PSK
	default:
		return nil, newError("invalid mode: ", c.Mode)
	}
	return config, nil
}

type SplitHTTPConfig struct {
	Host        string            `json:"host"`
	Path        string            `json:"path"`
	Headers     map[string]string `json:"headers"`
	NoSSEHeader bool              `json:"noSSEHeader"`
}

// Build implements Buildable.
func (c *SplitHTTPConfig) Build() (proto.Message, error) {
	// If http host is not set in the Host field, but in headers field, we add it to Host Field here.
	// If we don't do that, http host will be overwritten as address.
	// Host priority: Host field > headers field > address.
	if c.Host == "" && c.Headers["host"] != "" {
		c.Host = c.Headers["host"]
	} else if c.Host == "" && c.Headers["Host"] != "" {
		c.Host = c.Headers["Host"]
	}
	return &splithttp.Config{
		Path:        c.Path,
		Host:        c.Host,
		Header:      c.Headers,
		NoSSEHeader: c.NoSSEHeader,
	}, nil
}

type TransportProtocol string

// Build implements Buildable.
func (p TransportProtocol) Build() (string, error) {
	switch strings.ToLower(string(p)) {
	case "tcp":
		return "tcp", nil
	case "kcp", "mkcp":
		return "mkcp", nil
	case "ws", "websocket":
		return "websocket", nil
	case "h2", "http":
		return "http", nil
	case "ds", "domainsocket":
		return "domainsocket", nil
	case "quic":
		return "quic", nil
	case "gun", "grpc":
		return "gun", nil
	case "hy2", "hysteria2":
		return "hysteria2", nil
	case "meek":
		return "meek", nil
	case "httpupgrade":
		return "httpupgrade", nil
	case "dtls":
		return "dtls", nil
	case "request":
		return "request", nil
	case "splithttp":
		return "splithttp", nil
	default:
		return "", newError("Config: unknown transport protocol: ", p)
	}
}

type StreamConfig struct {
	Network             *TransportProtocol      `json:"network"`
	Security            string                  `json:"security"`
	TLSSettings         *tlscfg.TLSConfig       `json:"tlsSettings"`
	UTLSSettings        *tlscfg.UTLSConfig      `json:"utlsSettings"`
	REALITYSettings     *tlscfg.REALITYConfig   `json:"realitySettings"`
	TCPSettings         *TCPConfig              `json:"tcpSettings"`
	KCPSettings         *KCPConfig              `json:"kcpSettings"`
	WSSettings          *WebSocketConfig        `json:"wsSettings"`
	HTTPSettings        *HTTPConfig             `json:"httpSettings"`
	DSSettings          *DomainSocketConfig     `json:"dsSettings"`
	QUICSettings        *QUICConfig             `json:"quicSettings"`
	GunSettings         *GunConfig              `json:"gunSettings"`
	GRPCSettings        *GunConfig              `json:"grpcSettings"`
	Hy2Settings         *Hy2Config              `json:"hy2Settings"`
	MeekSettings        *MeekConfig             `json:"meekSettings"`
	HTTPUpgradeSettings *HTTPUpgradeConfig      `json:"httpupgradeSettings"`
	DTLSSettings        *DTLSConfig             `json:"dtlsSettings"`
	RequestSettings     *RequestConfig          `json:"requestSettings"`
	SplitHTTPSettings   *SplitHTTPConfig        `json:"splithttpSettings"`
	SocketSettings      *socketcfg.SocketConfig `json:"sockopt"`
}

// Build implements Buildable.
func (c *StreamConfig) Build() (*internet.StreamConfig, error) {
	config := &internet.StreamConfig{
		ProtocolName: "tcp",
	}
	if c.Network != nil {
		protocol, err := c.Network.Build()
		if err != nil {
			return nil, err
		}
		config.ProtocolName = protocol
	}
	if strings.EqualFold(c.Security, "tls") {
		tlsSettings := c.TLSSettings
		if tlsSettings == nil {
			tlsSettings = &tlscfg.TLSConfig{}
		}
		if tlsSettings.Fingerprint != "" {
			imitate := strings.ToLower(tlsSettings.Fingerprint)
			imitate = strings.TrimPrefix(imitate, "hello")
			switch imitate {
			case "chrome", "firefox", "safari", "ios", "edge", "360", "qq":
				imitate += "_auto"
			}
			utlsSettings := &tlscfg.UTLSConfig{
				TLSConfig: tlsSettings,
				Imitate:   imitate,
			}
			us, err := utlsSettings.Build()
			if err != nil {
				return nil, newError("Failed to build UTLS config.").Base(err)
			}
			tm := serial.ToTypedMessage(us)
			config.SecuritySettings = append(config.SecuritySettings, tm)
			config.SecurityType = serial.V2Type(tm)
		} else {
			ts, err := tlsSettings.Build()
			if err != nil {
				return nil, newError("Failed to build TLS config.").Base(err)
			}
			tm := serial.ToTypedMessage(ts)
			config.SecuritySettings = append(config.SecuritySettings, tm)
			config.SecurityType = serial.V2Type(tm)
		}
	} else if strings.EqualFold(c.Security, "utls") {
		utlsSettings := c.UTLSSettings
		if utlsSettings == nil {
			utlsSettings = &tlscfg.UTLSConfig{}
		}
		us, err := utlsSettings.Build()
		if err != nil {
			return nil, newError("Failed to build UTLS config.").Base(err)
		}
		tm := serial.ToTypedMessage(us)
		config.SecuritySettings = append(config.SecuritySettings, tm)
		config.SecurityType = serial.V2Type(tm)
	}
	if strings.EqualFold(c.Security, "reality") {
		if config.ProtocolName != "tcp" && config.ProtocolName != "http" && config.ProtocolName != "gun" && config.ProtocolName != "domainsocket" {
			return nil, newError("REALITY only supports TCP, H2, gRPC and DomainSocket for now.")
		}
		if c.REALITYSettings == nil {
			return nil, newError(`REALITY: Empty "realitySettings".`)
		}
		rs, err := c.REALITYSettings.Build()
		if err != nil {
			return nil, newError("Failed to build REALITY config.").Base(err)
		}
		tm := serial.ToTypedMessage(rs)
		config.SecuritySettings = append(config.SecuritySettings, tm)
		config.SecurityType = serial.V2Type(tm)
	}
	if c.TCPSettings != nil {
		ts, err := c.TCPSettings.Build()
		if err != nil {
			return nil, newError("Failed to build TCP config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "tcp",
			Settings:     serial.ToTypedMessage(ts),
		})
	}
	if c.KCPSettings != nil {
		ts, err := c.KCPSettings.Build()
		if err != nil {
			return nil, newError("Failed to build mKCP config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "mkcp",
			Settings:     serial.ToTypedMessage(ts),
		})
	}
	if c.WSSettings != nil {
		ts, err := c.WSSettings.Build()
		if err != nil {
			return nil, newError("Failed to build WebSocket config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "websocket",
			Settings:     serial.ToTypedMessage(ts),
		})
	}
	if c.HTTPSettings != nil {
		ts, err := c.HTTPSettings.Build()
		if err != nil {
			return nil, newError("Failed to build HTTP config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "http",
			Settings:     serial.ToTypedMessage(ts),
		})
	}
	if c.DSSettings != nil {
		ds, err := c.DSSettings.Build()
		if err != nil {
			return nil, newError("Failed to build DomainSocket config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "domainsocket",
			Settings:     serial.ToTypedMessage(ds),
		})
	}
	if c.QUICSettings != nil {
		qs, err := c.QUICSettings.Build()
		if err != nil {
			return nil, newError("Failed to build QUIC config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "quic",
			Settings:     serial.ToTypedMessage(qs),
		})
	}
	if c.GunSettings == nil {
		c.GunSettings = c.GRPCSettings
	}
	if c.GunSettings != nil {
		gs, err := c.GunSettings.Build()
		if err != nil {
			return nil, newError("Failed to build Gun config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "gun",
			Settings:     serial.ToTypedMessage(gs),
		})
	}
	if c.Hy2Settings != nil {
		hy2, err := c.Hy2Settings.Build()
		if err != nil {
			return nil, newError("Failed to build hy2 config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "hysteria2",
			Settings:     serial.ToTypedMessage(hy2),
		})
	}
	if c.MeekSettings != nil {
		ms, err := c.MeekSettings.Build()
		if err != nil {
			return nil, newError("Failed to build Meek config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "meek",
			Settings:     serial.ToTypedMessage(ms),
		})
	}
	if c.HTTPUpgradeSettings != nil {
		hs, err := c.HTTPUpgradeSettings.Build()
		if err != nil {
			return nil, newError("Failed to build HTTPUpgrade config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "httpupgrade",
			Settings:     serial.ToTypedMessage(hs),
		})
	}
	if c.SocketSettings != nil {
		ss, err := c.SocketSettings.Build()
		if err != nil {
			return nil, newError("Failed to build sockopt.").Base(err)
		}
		config.SocketSettings = ss
	}
	if c.DTLSSettings != nil {
		ds, err := c.DTLSSettings.Build()
		if err != nil {
			return nil, newError("Failed to build DTLS config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "dtls",
			Settings:     serial.ToTypedMessage(ds),
		})
	}
	if c.RequestSettings != nil {
		rs, err := c.RequestSettings.Build()
		if err != nil {
			return nil, newError("Failed to build Request config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "request",
			Settings:     serial.ToTypedMessage(rs),
		})
	}
	if c.SplitHTTPSettings != nil {
		hs, err := c.SplitHTTPSettings.Build()
		if err != nil {
			return nil, newError("Failed to build SplitHTTP config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "splithttp",
			Settings:     serial.ToTypedMessage(hs),
		})
	}
	if c.SocketSettings != nil {
		ss, err := c.SocketSettings.Build()
		if err != nil {
			return nil, newError("Failed to build sockopt.").Base(err)
		}
		config.SocketSettings = ss
	}
	return config, nil
}
