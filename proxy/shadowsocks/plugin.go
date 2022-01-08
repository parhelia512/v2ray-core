package shadowsocks

import (
	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/buf"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
)

var (
	PluginLoader func(plugin string) SIP003Plugin
	Plugins      map[string]func() SIP003Plugin
)

func init() {
	Plugins = make(map[string]func() SIP003Plugin)
}

func SetPluginLoader(creator func(plugin string) SIP003Plugin) {
	PluginLoader = creator
}

func RegisterPlugin(name string, creator func() SIP003Plugin) {
	Plugins[name] = creator
}

type SIP003Plugin interface {
	Init(localHost string, localPort string, remoteHost string, remotePort string, pluginOpts string, pluginArgs []string, account *MemoryAccount) error
	common.Closable
}

// SagerNet private
type StreamPlugin interface {
	StreamConn(conn internet.Connection) internet.Connection
}

type ProtocolConn struct {
	buf.Reader
	buf.Writer
	ProtocolReader buf.Reader
	ProtocolWriter buf.Writer
}

// SagerNet private
type ProtocolPlugin interface {
	ProtocolConn(conn *ProtocolConn, iv []byte)
	EncodePacket(buffer *buf.Buffer, ivLen int32) (*buf.Buffer, error)
	DecodePacket(buffer *buf.Buffer) (*buf.Buffer, error)
}
