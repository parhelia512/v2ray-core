package utls

import (
	tls "github.com/v2fly/v2ray-core/v4/transport/internet/tls"
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

type ForcedALPN int32

const (
	ForcedALPN_TRANSPORT_PREFERENCE_TAKE_PRIORITY ForcedALPN = 0
	ForcedALPN_NO_ALPN                            ForcedALPN = 1
	ForcedALPN_UTLS_PRESET                        ForcedALPN = 2
)

// Enum value maps for ForcedALPN.
var (
	ForcedALPN_name = map[int32]string{
		0: "TRANSPORT_PREFERENCE_TAKE_PRIORITY",
		1: "NO_ALPN",
		2: "UTLS_PRESET",
	}
	ForcedALPN_value = map[string]int32{
		"TRANSPORT_PREFERENCE_TAKE_PRIORITY": 0,
		"NO_ALPN":                            1,
		"UTLS_PRESET":                        2,
	}
)

func (x ForcedALPN) Enum() *ForcedALPN {
	p := new(ForcedALPN)
	*p = x
	return p
}

func (x ForcedALPN) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ForcedALPN) Descriptor() protoreflect.EnumDescriptor {
	return file_transport_internet_tls_utls_config_proto_enumTypes[0].Descriptor()
}

func (ForcedALPN) Type() protoreflect.EnumType {
	return &file_transport_internet_tls_utls_config_proto_enumTypes[0]
}

func (x ForcedALPN) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ForcedALPN.Descriptor instead.
func (ForcedALPN) EnumDescriptor() ([]byte, []int) {
	return file_transport_internet_tls_utls_config_proto_rawDescGZIP(), []int{0}
}

type Config struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	TlsConfig *tls.Config `protobuf:"bytes,1,opt,name=tls_config,json=tlsConfig,proto3" json:"tls_config,omitempty"`
	Imitate   string      `protobuf:"bytes,2,opt,name=imitate,proto3" json:"imitate,omitempty"`
	NoSNI     bool        `protobuf:"varint,3,opt,name=noSNI,proto3" json:"noSNI,omitempty"`
	ForceAlpn ForcedALPN  `protobuf:"varint,4,opt,name=force_alpn,json=forceAlpn,proto3,enum=v2ray.core.transport.internet.tls.utls.ForcedALPN" json:"force_alpn,omitempty"`
}

func (x *Config) Reset() {
	*x = Config{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transport_internet_tls_utls_config_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Config) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Config) ProtoMessage() {}

func (x *Config) ProtoReflect() protoreflect.Message {
	mi := &file_transport_internet_tls_utls_config_proto_msgTypes[0]
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
	return file_transport_internet_tls_utls_config_proto_rawDescGZIP(), []int{0}
}

func (x *Config) GetTlsConfig() *tls.Config {
	if x != nil {
		return x.TlsConfig
	}
	return nil
}

func (x *Config) GetImitate() string {
	if x != nil {
		return x.Imitate
	}
	return ""
}

func (x *Config) GetNoSNI() bool {
	if x != nil {
		return x.NoSNI
	}
	return false
}

func (x *Config) GetForceAlpn() ForcedALPN {
	if x != nil {
		return x.ForceAlpn
	}
	return ForcedALPN_TRANSPORT_PREFERENCE_TAKE_PRIORITY
}

var File_transport_internet_tls_utls_config_proto protoreflect.FileDescriptor

var file_transport_internet_tls_utls_config_proto_rawDesc = []byte{
	0x0a, 0x28, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x69, 0x6e, 0x74, 0x65,
	0x72, 0x6e, 0x65, 0x74, 0x2f, 0x74, 0x6c, 0x73, 0x2f, 0x75, 0x74, 0x6c, 0x73, 0x2f, 0x63, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x26, 0x76, 0x32, 0x72, 0x61,
	0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74,
	0x2e, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2e, 0x74, 0x6c, 0x73, 0x2e, 0x75, 0x74,
	0x6c, 0x73, 0x1a, 0x23, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x69, 0x6e,
	0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2f, 0x74, 0x6c, 0x73, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xd5, 0x01, 0x0a, 0x06, 0x43, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x12, 0x48, 0x0a, 0x0a, 0x74, 0x6c, 0x73, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x29, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63,
	0x6f, 0x72, 0x65, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x69, 0x6e,
	0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2e, 0x74, 0x6c, 0x73, 0x2e, 0x43, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x52, 0x09, 0x74, 0x6c, 0x73, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x18, 0x0a, 0x07,
	0x69, 0x6d, 0x69, 0x74, 0x61, 0x74, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x69,
	0x6d, 0x69, 0x74, 0x61, 0x74, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x6e, 0x6f, 0x53, 0x4e, 0x49, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x08, 0x52, 0x05, 0x6e, 0x6f, 0x53, 0x4e, 0x49, 0x12, 0x51, 0x0a, 0x0a,
	0x66, 0x6f, 0x72, 0x63, 0x65, 0x5f, 0x61, 0x6c, 0x70, 0x6e, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0e,
	0x32, 0x32, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x74, 0x72,
	0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74,
	0x2e, 0x74, 0x6c, 0x73, 0x2e, 0x75, 0x74, 0x6c, 0x73, 0x2e, 0x46, 0x6f, 0x72, 0x63, 0x65, 0x64,
	0x41, 0x4c, 0x50, 0x4e, 0x52, 0x09, 0x66, 0x6f, 0x72, 0x63, 0x65, 0x41, 0x6c, 0x70, 0x6e, 0x2a,
	0x52, 0x0a, 0x0a, 0x46, 0x6f, 0x72, 0x63, 0x65, 0x64, 0x41, 0x4c, 0x50, 0x4e, 0x12, 0x26, 0x0a,
	0x22, 0x54, 0x52, 0x41, 0x4e, 0x53, 0x50, 0x4f, 0x52, 0x54, 0x5f, 0x50, 0x52, 0x45, 0x46, 0x45,
	0x52, 0x45, 0x4e, 0x43, 0x45, 0x5f, 0x54, 0x41, 0x4b, 0x45, 0x5f, 0x50, 0x52, 0x49, 0x4f, 0x52,
	0x49, 0x54, 0x59, 0x10, 0x00, 0x12, 0x0b, 0x0a, 0x07, 0x4e, 0x4f, 0x5f, 0x41, 0x4c, 0x50, 0x4e,
	0x10, 0x01, 0x12, 0x0f, 0x0a, 0x0b, 0x55, 0x54, 0x4c, 0x53, 0x5f, 0x50, 0x52, 0x45, 0x53, 0x45,
	0x54, 0x10, 0x02, 0x42, 0x93, 0x01, 0x0a, 0x2a, 0x63, 0x6f, 0x6d, 0x2e, 0x76, 0x32, 0x72, 0x61,
	0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74,
	0x2e, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2e, 0x74, 0x6c, 0x73, 0x2e, 0x75, 0x74,
	0x6c, 0x73, 0x50, 0x01, 0x5a, 0x3a, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x76, 0x32, 0x66, 0x6c, 0x79, 0x2f, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2d, 0x63, 0x6f, 0x72,
	0x65, 0x2f, 0x76, 0x34, 0x2f, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x69,
	0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2f, 0x74, 0x6c, 0x73, 0x2f, 0x75, 0x74, 0x6c, 0x73,
	0xaa, 0x02, 0x26, 0x56, 0x32, 0x52, 0x61, 0x79, 0x2e, 0x43, 0x6f, 0x72, 0x65, 0x2e, 0x54, 0x72,
	0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74,
	0x2e, 0x54, 0x6c, 0x73, 0x2e, 0x55, 0x54, 0x6c, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_transport_internet_tls_utls_config_proto_rawDescOnce sync.Once
	file_transport_internet_tls_utls_config_proto_rawDescData = file_transport_internet_tls_utls_config_proto_rawDesc
)

func file_transport_internet_tls_utls_config_proto_rawDescGZIP() []byte {
	file_transport_internet_tls_utls_config_proto_rawDescOnce.Do(func() {
		file_transport_internet_tls_utls_config_proto_rawDescData = protoimpl.X.CompressGZIP(file_transport_internet_tls_utls_config_proto_rawDescData)
	})
	return file_transport_internet_tls_utls_config_proto_rawDescData
}

var file_transport_internet_tls_utls_config_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_transport_internet_tls_utls_config_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_transport_internet_tls_utls_config_proto_goTypes = []any{
	(ForcedALPN)(0),    // 0: v2ray.core.transport.internet.tls.utls.ForcedALPN
	(*Config)(nil),     // 1: v2ray.core.transport.internet.tls.utls.Config
	(*tls.Config)(nil), // 2: v2ray.core.transport.internet.tls.Config
}
var file_transport_internet_tls_utls_config_proto_depIdxs = []int32{
	2, // 0: v2ray.core.transport.internet.tls.utls.Config.tls_config:type_name -> v2ray.core.transport.internet.tls.Config
	0, // 1: v2ray.core.transport.internet.tls.utls.Config.force_alpn:type_name -> v2ray.core.transport.internet.tls.utls.ForcedALPN
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_transport_internet_tls_utls_config_proto_init() }
func file_transport_internet_tls_utls_config_proto_init() {
	if File_transport_internet_tls_utls_config_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_transport_internet_tls_utls_config_proto_msgTypes[0].Exporter = func(v any, i int) any {
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
			RawDescriptor: file_transport_internet_tls_utls_config_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_transport_internet_tls_utls_config_proto_goTypes,
		DependencyIndexes: file_transport_internet_tls_utls_config_proto_depIdxs,
		EnumInfos:         file_transport_internet_tls_utls_config_proto_enumTypes,
		MessageInfos:      file_transport_internet_tls_utls_config_proto_msgTypes,
	}.Build()
	File_transport_internet_tls_utls_config_proto = out.File
	file_transport_internet_tls_utls_config_proto_rawDesc = nil
	file_transport_internet_tls_utls_config_proto_goTypes = nil
	file_transport_internet_tls_utls_config_proto_depIdxs = nil
}
