package dtls

import (
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

type DTLSMode int32

const (
	DTLSMode_INVALID DTLSMode = 0
	DTLSMode_PSK     DTLSMode = 1
)

// Enum value maps for DTLSMode.
var (
	DTLSMode_name = map[int32]string{
		0: "INVALID",
		1: "PSK",
	}
	DTLSMode_value = map[string]int32{
		"INVALID": 0,
		"PSK":     1,
	}
)

func (x DTLSMode) Enum() *DTLSMode {
	p := new(DTLSMode)
	*p = x
	return p
}

func (x DTLSMode) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (DTLSMode) Descriptor() protoreflect.EnumDescriptor {
	return file_transport_internet_dtls_config_proto_enumTypes[0].Descriptor()
}

func (DTLSMode) Type() protoreflect.EnumType {
	return &file_transport_internet_dtls_config_proto_enumTypes[0]
}

func (x DTLSMode) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use DTLSMode.Descriptor instead.
func (DTLSMode) EnumDescriptor() ([]byte, []int) {
	return file_transport_internet_dtls_config_proto_rawDescGZIP(), []int{0}
}

type Config struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Mode                   DTLSMode `protobuf:"varint,1,opt,name=mode,proto3,enum=v2ray.core.transport.internet.dtls.DTLSMode" json:"mode,omitempty"`
	Psk                    []byte   `protobuf:"bytes,2,opt,name=psk,proto3" json:"psk,omitempty"`
	Mtu                    uint32   `protobuf:"varint,3,opt,name=mtu,proto3" json:"mtu,omitempty"`
	ReplayProtectionWindow uint32   `protobuf:"varint,4,opt,name=replay_protection_window,json=replayProtectionWindow,proto3" json:"replay_protection_window,omitempty"`
}

func (x *Config) Reset() {
	*x = Config{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transport_internet_dtls_config_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Config) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Config) ProtoMessage() {}

func (x *Config) ProtoReflect() protoreflect.Message {
	mi := &file_transport_internet_dtls_config_proto_msgTypes[0]
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
	return file_transport_internet_dtls_config_proto_rawDescGZIP(), []int{0}
}

func (x *Config) GetMode() DTLSMode {
	if x != nil {
		return x.Mode
	}
	return DTLSMode_INVALID
}

func (x *Config) GetPsk() []byte {
	if x != nil {
		return x.Psk
	}
	return nil
}

func (x *Config) GetMtu() uint32 {
	if x != nil {
		return x.Mtu
	}
	return 0
}

func (x *Config) GetReplayProtectionWindow() uint32 {
	if x != nil {
		return x.ReplayProtectionWindow
	}
	return 0
}

var File_transport_internet_dtls_config_proto protoreflect.FileDescriptor

var file_transport_internet_dtls_config_proto_rawDesc = []byte{
	0x0a, 0x24, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x69, 0x6e, 0x74, 0x65,
	0x72, 0x6e, 0x65, 0x74, 0x2f, 0x64, 0x74, 0x6c, 0x73, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x22, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f,
	0x72, 0x65, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x69, 0x6e, 0x74,
	0x65, 0x72, 0x6e, 0x65, 0x74, 0x2e, 0x64, 0x74, 0x6c, 0x73, 0x22, 0xa8, 0x01, 0x0a, 0x06, 0x43,
	0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x40, 0x0a, 0x04, 0x6d, 0x6f, 0x64, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0e, 0x32, 0x2c, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65,
	0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x72,
	0x6e, 0x65, 0x74, 0x2e, 0x64, 0x74, 0x6c, 0x73, 0x2e, 0x44, 0x54, 0x4c, 0x53, 0x4d, 0x6f, 0x64,
	0x65, 0x52, 0x04, 0x6d, 0x6f, 0x64, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x70, 0x73, 0x6b, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x03, 0x70, 0x73, 0x6b, 0x12, 0x10, 0x0a, 0x03, 0x6d, 0x74, 0x75,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x03, 0x6d, 0x74, 0x75, 0x12, 0x38, 0x0a, 0x18, 0x72,
	0x65, 0x70, 0x6c, 0x61, 0x79, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,
	0x5f, 0x77, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x16, 0x72,
	0x65, 0x70, 0x6c, 0x61, 0x79, 0x50, 0x72, 0x6f, 0x74, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x57,
	0x69, 0x6e, 0x64, 0x6f, 0x77, 0x2a, 0x20, 0x0a, 0x08, 0x44, 0x54, 0x4c, 0x53, 0x4d, 0x6f, 0x64,
	0x65, 0x12, 0x0b, 0x0a, 0x07, 0x49, 0x4e, 0x56, 0x41, 0x4c, 0x49, 0x44, 0x10, 0x00, 0x12, 0x07,
	0x0a, 0x03, 0x50, 0x53, 0x4b, 0x10, 0x01, 0x42, 0x87, 0x01, 0x0a, 0x26, 0x63, 0x6f, 0x6d, 0x2e,
	0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73,
	0x70, 0x6f, 0x72, 0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2e, 0x64, 0x74,
	0x6c, 0x73, 0x50, 0x01, 0x5a, 0x36, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x76, 0x32, 0x66, 0x6c, 0x79, 0x2f, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2d, 0x63, 0x6f, 0x72,
	0x65, 0x2f, 0x76, 0x34, 0x2f, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x69,
	0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2f, 0x64, 0x74, 0x6c, 0x73, 0xaa, 0x02, 0x22, 0x56,
	0x32, 0x52, 0x61, 0x79, 0x2e, 0x43, 0x6f, 0x72, 0x65, 0x2e, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x70,
	0x6f, 0x72, 0x74, 0x2e, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2e, 0x44, 0x74, 0x6c,
	0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_transport_internet_dtls_config_proto_rawDescOnce sync.Once
	file_transport_internet_dtls_config_proto_rawDescData = file_transport_internet_dtls_config_proto_rawDesc
)

func file_transport_internet_dtls_config_proto_rawDescGZIP() []byte {
	file_transport_internet_dtls_config_proto_rawDescOnce.Do(func() {
		file_transport_internet_dtls_config_proto_rawDescData = protoimpl.X.CompressGZIP(file_transport_internet_dtls_config_proto_rawDescData)
	})
	return file_transport_internet_dtls_config_proto_rawDescData
}

var file_transport_internet_dtls_config_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_transport_internet_dtls_config_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_transport_internet_dtls_config_proto_goTypes = []any{
	(DTLSMode)(0),  // 0: v2ray.core.transport.internet.dtls.DTLSMode
	(*Config)(nil), // 1: v2ray.core.transport.internet.dtls.Config
}
var file_transport_internet_dtls_config_proto_depIdxs = []int32{
	0, // 0: v2ray.core.transport.internet.dtls.Config.mode:type_name -> v2ray.core.transport.internet.dtls.DTLSMode
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_transport_internet_dtls_config_proto_init() }
func file_transport_internet_dtls_config_proto_init() {
	if File_transport_internet_dtls_config_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_transport_internet_dtls_config_proto_msgTypes[0].Exporter = func(v any, i int) any {
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
			RawDescriptor: file_transport_internet_dtls_config_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_transport_internet_dtls_config_proto_goTypes,
		DependencyIndexes: file_transport_internet_dtls_config_proto_depIdxs,
		EnumInfos:         file_transport_internet_dtls_config_proto_enumTypes,
		MessageInfos:      file_transport_internet_dtls_config_proto_msgTypes,
	}.Build()
	File_transport_internet_dtls_config_proto = out.File
	file_transport_internet_dtls_config_proto_rawDesc = nil
	file_transport_internet_dtls_config_proto_goTypes = nil
	file_transport_internet_dtls_config_proto_depIdxs = nil
}
