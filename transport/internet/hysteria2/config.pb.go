package hysteria2

import (
	protocol "github.com/v2fly/v2ray-core/v4/common/protocol"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Congestion struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type     string `protobuf:"bytes,1,opt,name=type,proto3" json:"type,omitempty"`
	UpMbps   uint64 `protobuf:"varint,2,opt,name=up_mbps,json=upMbps,proto3" json:"up_mbps,omitempty"`
	DownMbps uint64 `protobuf:"varint,3,opt,name=down_mbps,json=downMbps,proto3" json:"down_mbps,omitempty"`
}

func (x *Congestion) Reset() {
	*x = Congestion{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transport_internet_hysteria2_config_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Congestion) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Congestion) ProtoMessage() {}

func (x *Congestion) ProtoReflect() protoreflect.Message {
	mi := &file_transport_internet_hysteria2_config_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Congestion.ProtoReflect.Descriptor instead.
func (*Congestion) Descriptor() ([]byte, []int) {
	return file_transport_internet_hysteria2_config_proto_rawDescGZIP(), []int{0}
}

func (x *Congestion) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *Congestion) GetUpMbps() uint64 {
	if x != nil {
		return x.UpMbps
	}
	return 0
}

func (x *Congestion) GetDownMbps() uint64 {
	if x != nil {
		return x.DownMbps
	}
	return 0
}

type Config struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Key                   string                   `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	Security              *protocol.SecurityConfig `protobuf:"bytes,2,opt,name=security,proto3" json:"security,omitempty"`
	Password              string                   `protobuf:"bytes,3,opt,name=password,proto3" json:"password,omitempty"`
	Congestion            *Congestion              `protobuf:"bytes,4,opt,name=congestion,proto3" json:"congestion,omitempty"`
	IgnoreClientBandwidth bool                     `protobuf:"varint,5,opt,name=ignore_client_bandwidth,json=ignoreClientBandwidth,proto3" json:"ignore_client_bandwidth,omitempty"`
	UseUdpExtension       bool                     `protobuf:"varint,6,opt,name=use_udp_extension,json=useUdpExtension,proto3" json:"use_udp_extension,omitempty"`
}

func (x *Config) Reset() {
	*x = Config{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transport_internet_hysteria2_config_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Config) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Config) ProtoMessage() {}

func (x *Config) ProtoReflect() protoreflect.Message {
	mi := &file_transport_internet_hysteria2_config_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Config.ProtoReflect.Descriptor instead.
func (*Config) Descriptor() ([]byte, []int) {
	return file_transport_internet_hysteria2_config_proto_rawDescGZIP(), []int{1}
}

func (x *Config) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *Config) GetSecurity() *protocol.SecurityConfig {
	if x != nil {
		return x.Security
	}
	return nil
}

func (x *Config) GetPassword() string {
	if x != nil {
		return x.Password
	}
	return ""
}

func (x *Config) GetCongestion() *Congestion {
	if x != nil {
		return x.Congestion
	}
	return nil
}

func (x *Config) GetIgnoreClientBandwidth() bool {
	if x != nil {
		return x.IgnoreClientBandwidth
	}
	return false
}

func (x *Config) GetUseUdpExtension() bool {
	if x != nil {
		return x.UseUdpExtension
	}
	return false
}

var File_transport_internet_hysteria2_config_proto protoreflect.FileDescriptor

var file_transport_internet_hysteria2_config_proto_rawDesc = []byte{
	0x0a, 0x29, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x69, 0x6e, 0x74, 0x65,
	0x72, 0x6e, 0x65, 0x74, 0x2f, 0x68, 0x79, 0x73, 0x74, 0x65, 0x72, 0x69, 0x61, 0x32, 0x2f, 0x63,
	0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x27, 0x76, 0x32, 0x72,
	0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72,
	0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2e, 0x68, 0x79, 0x73, 0x74, 0x65,
	0x72, 0x69, 0x61, 0x32, 0x1a, 0x1d, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x2f, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0x56, 0x0a, 0x0a, 0x43, 0x6f, 0x6e, 0x67, 0x65, 0x73, 0x74, 0x69, 0x6f,
	0x6e, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x17, 0x0a, 0x07, 0x75, 0x70, 0x5f, 0x6d, 0x62, 0x70, 0x73,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x52, 0x06, 0x75, 0x70, 0x4d, 0x62, 0x70, 0x73, 0x12, 0x1b,
	0x0a, 0x09, 0x64, 0x6f, 0x77, 0x6e, 0x5f, 0x6d, 0x62, 0x70, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x04, 0x52, 0x08, 0x64, 0x6f, 0x77, 0x6e, 0x4d, 0x62, 0x70, 0x73, 0x22, 0xb7, 0x02, 0x0a, 0x06,
	0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x46, 0x0a, 0x08, 0x73, 0x65, 0x63, 0x75,
	0x72, 0x69, 0x74, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x76, 0x32, 0x72,
	0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x2e, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79,
	0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x52, 0x08, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79,
	0x12, 0x1a, 0x0a, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x12, 0x53, 0x0a, 0x0a,
	0x63, 0x6f, 0x6e, 0x67, 0x65, 0x73, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x33, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x74, 0x72,
	0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74,
	0x2e, 0x68, 0x79, 0x73, 0x74, 0x65, 0x72, 0x69, 0x61, 0x32, 0x2e, 0x43, 0x6f, 0x6e, 0x67, 0x65,
	0x73, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0a, 0x63, 0x6f, 0x6e, 0x67, 0x65, 0x73, 0x74, 0x69, 0x6f,
	0x6e, 0x12, 0x36, 0x0a, 0x17, 0x69, 0x67, 0x6e, 0x6f, 0x72, 0x65, 0x5f, 0x63, 0x6c, 0x69, 0x65,
	0x6e, 0x74, 0x5f, 0x62, 0x61, 0x6e, 0x64, 0x77, 0x69, 0x64, 0x74, 0x68, 0x18, 0x05, 0x20, 0x01,
	0x28, 0x08, 0x52, 0x15, 0x69, 0x67, 0x6e, 0x6f, 0x72, 0x65, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74,
	0x42, 0x61, 0x6e, 0x64, 0x77, 0x69, 0x64, 0x74, 0x68, 0x12, 0x2a, 0x0a, 0x11, 0x75, 0x73, 0x65,
	0x5f, 0x75, 0x64, 0x70, 0x5f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x06,
	0x20, 0x01, 0x28, 0x08, 0x52, 0x0f, 0x75, 0x73, 0x65, 0x55, 0x64, 0x70, 0x45, 0x78, 0x74, 0x65,
	0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x42, 0x96, 0x01, 0x0a, 0x2b, 0x63, 0x6f, 0x6d, 0x2e, 0x76, 0x32,
	0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f,
	0x72, 0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2e, 0x68, 0x79, 0x73, 0x74,
	0x65, 0x72, 0x69, 0x61, 0x32, 0x50, 0x01, 0x5a, 0x3b, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e,
	0x63, 0x6f, 0x6d, 0x2f, 0x76, 0x32, 0x66, 0x6c, 0x79, 0x2f, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2d,
	0x63, 0x6f, 0x72, 0x65, 0x2f, 0x76, 0x34, 0x2f, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72,
	0x74, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2f, 0x68, 0x79, 0x73, 0x74, 0x65,
	0x72, 0x69, 0x61, 0x32, 0xaa, 0x02, 0x27, 0x56, 0x32, 0x52, 0x61, 0x79, 0x2e, 0x43, 0x6f, 0x72,
	0x65, 0x2e, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x49, 0x6e, 0x74, 0x65,
	0x72, 0x6e, 0x65, 0x74, 0x2e, 0x48, 0x79, 0x73, 0x74, 0x65, 0x72, 0x69, 0x61, 0x32, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_transport_internet_hysteria2_config_proto_rawDescOnce sync.Once
	file_transport_internet_hysteria2_config_proto_rawDescData = file_transport_internet_hysteria2_config_proto_rawDesc
)

func file_transport_internet_hysteria2_config_proto_rawDescGZIP() []byte {
	file_transport_internet_hysteria2_config_proto_rawDescOnce.Do(func() {
		file_transport_internet_hysteria2_config_proto_rawDescData = protoimpl.X.CompressGZIP(file_transport_internet_hysteria2_config_proto_rawDescData)
	})
	return file_transport_internet_hysteria2_config_proto_rawDescData
}

var file_transport_internet_hysteria2_config_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_transport_internet_hysteria2_config_proto_goTypes = []any{
	(*Congestion)(nil),              // 0: v2ray.core.transport.internet.hysteria2.Congestion
	(*Config)(nil),                  // 1: v2ray.core.transport.internet.hysteria2.Config
	(*protocol.SecurityConfig)(nil), // 2: v2ray.core.common.protocol.SecurityConfig
}
var file_transport_internet_hysteria2_config_proto_depIdxs = []int32{
	2, // 0: v2ray.core.transport.internet.hysteria2.Config.security:type_name -> v2ray.core.common.protocol.SecurityConfig
	0, // 1: v2ray.core.transport.internet.hysteria2.Config.congestion:type_name -> v2ray.core.transport.internet.hysteria2.Congestion
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_transport_internet_hysteria2_config_proto_init() }
func file_transport_internet_hysteria2_config_proto_init() {
	if File_transport_internet_hysteria2_config_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_transport_internet_hysteria2_config_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*Congestion); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_transport_internet_hysteria2_config_proto_msgTypes[1].Exporter = func(v any, i int) any {
			switch v := v.(*Config); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_transport_internet_hysteria2_config_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_transport_internet_hysteria2_config_proto_goTypes,
		DependencyIndexes: file_transport_internet_hysteria2_config_proto_depIdxs,
		MessageInfos:      file_transport_internet_hysteria2_config_proto_msgTypes,
	}.Build()
	File_transport_internet_hysteria2_config_proto = out.File
	file_transport_internet_hysteria2_config_proto_rawDesc = nil
	file_transport_internet_hysteria2_config_proto_goTypes = nil
	file_transport_internet_hysteria2_config_proto_depIdxs = nil
}
