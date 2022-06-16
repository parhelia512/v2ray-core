// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.21.1
// source: transport/internet/grpc/config.proto

package grpc

import (
	_ "github.com/v2fly/v2ray-core/v5/common/protoext"
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

type Mode int32

const (
	Mode_Gun   Mode = 0
	Mode_Multi Mode = 1
	Mode_Raw   Mode = 2
)

// Enum value maps for Mode.
var (
	Mode_name = map[int32]string{
		0: "Gun",
		1: "Multi",
		2: "Raw",
	}
	Mode_value = map[string]int32{
		"Gun":   0,
		"Multi": 1,
		"Raw":   2,
	}
)

func (x Mode) Enum() *Mode {
	p := new(Mode)
	*p = x
	return p
}

func (x Mode) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Mode) Descriptor() protoreflect.EnumDescriptor {
	return file_transport_internet_grpc_config_proto_enumTypes[0].Descriptor()
}

func (Mode) Type() protoreflect.EnumType {
	return &file_transport_internet_grpc_config_proto_enumTypes[0]
}

func (x Mode) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Mode.Descriptor instead.
func (Mode) EnumDescriptor() ([]byte, []int) {
	return file_transport_internet_grpc_config_proto_rawDescGZIP(), []int{0}
}

type Config struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Host                string `protobuf:"bytes,1,opt,name=host,proto3" json:"host,omitempty"`
	ServiceName         string `protobuf:"bytes,2,opt,name=service_name,json=serviceName,proto3" json:"service_name,omitempty"`
	Mode                Mode   `protobuf:"varint,3,opt,name=mode,proto3,enum=v2ray.core.transport.internet.grpc.encoding.Mode" json:"mode,omitempty"`
	IdleTimeout         int32  `protobuf:"varint,4,opt,name=idle_timeout,json=idleTimeout,proto3" json:"idle_timeout,omitempty"`
	HealthCheckTimeout  int32  `protobuf:"varint,5,opt,name=health_check_timeout,json=healthCheckTimeout,proto3" json:"health_check_timeout,omitempty"`
	PermitWithoutStream bool   `protobuf:"varint,6,opt,name=permit_without_stream,json=permitWithoutStream,proto3" json:"permit_without_stream,omitempty"`
	InitialWindowsSize  int32  `protobuf:"varint,7,opt,name=initial_windows_size,json=initialWindowsSize,proto3" json:"initial_windows_size,omitempty"`
}

func (x *Config) Reset() {
	*x = Config{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transport_internet_grpc_config_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Config) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Config) ProtoMessage() {}

func (x *Config) ProtoReflect() protoreflect.Message {
	mi := &file_transport_internet_grpc_config_proto_msgTypes[0]
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
	return file_transport_internet_grpc_config_proto_rawDescGZIP(), []int{0}
}

func (x *Config) GetHost() string {
	if x != nil {
		return x.Host
	}
	return ""
}

func (x *Config) GetServiceName() string {
	if x != nil {
		return x.ServiceName
	}
	return ""
}

func (x *Config) GetMode() Mode {
	if x != nil {
		return x.Mode
	}
	return Mode_Gun
}

func (x *Config) GetIdleTimeout() int32 {
	if x != nil {
		return x.IdleTimeout
	}
	return 0
}

func (x *Config) GetHealthCheckTimeout() int32 {
	if x != nil {
		return x.HealthCheckTimeout
	}
	return 0
}

func (x *Config) GetPermitWithoutStream() bool {
	if x != nil {
		return x.PermitWithoutStream
	}
	return false
}

func (x *Config) GetInitialWindowsSize() int32 {
	if x != nil {
		return x.InitialWindowsSize
	}
	return 0
}

var File_transport_internet_grpc_config_proto protoreflect.FileDescriptor

var file_transport_internet_grpc_config_proto_rawDesc = []byte{
	0x0a, 0x24, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x69, 0x6e, 0x74, 0x65,
	0x72, 0x6e, 0x65, 0x74, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x2b, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f,
	0x72, 0x65, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x69, 0x6e, 0x74,
	0x65, 0x72, 0x6e, 0x65, 0x74, 0x2e, 0x67, 0x72, 0x70, 0x63, 0x2e, 0x65, 0x6e, 0x63, 0x6f, 0x64,
	0x69, 0x6e, 0x67, 0x1a, 0x20, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x65, 0x78, 0x74, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xe7, 0x02, 0x0a, 0x06, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x12, 0x12, 0x0a, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04,
	0x68, 0x6f, 0x73, 0x74, 0x12, 0x21, 0x0a, 0x0c, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x5f,
	0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x73, 0x65, 0x72, 0x76,
	0x69, 0x63, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x45, 0x0a, 0x04, 0x6d, 0x6f, 0x64, 0x65, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x31, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f,
	0x72, 0x65, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x69, 0x6e, 0x74,
	0x65, 0x72, 0x6e, 0x65, 0x74, 0x2e, 0x67, 0x72, 0x70, 0x63, 0x2e, 0x65, 0x6e, 0x63, 0x6f, 0x64,
	0x69, 0x6e, 0x67, 0x2e, 0x4d, 0x6f, 0x64, 0x65, 0x52, 0x04, 0x6d, 0x6f, 0x64, 0x65, 0x12, 0x21,
	0x0a, 0x0c, 0x69, 0x64, 0x6c, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x05, 0x52, 0x0b, 0x69, 0x64, 0x6c, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x6f, 0x75,
	0x74, 0x12, 0x30, 0x0a, 0x14, 0x68, 0x65, 0x61, 0x6c, 0x74, 0x68, 0x5f, 0x63, 0x68, 0x65, 0x63,
	0x6b, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x05, 0x52,
	0x12, 0x68, 0x65, 0x61, 0x6c, 0x74, 0x68, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x54, 0x69, 0x6d, 0x65,
	0x6f, 0x75, 0x74, 0x12, 0x32, 0x0a, 0x15, 0x70, 0x65, 0x72, 0x6d, 0x69, 0x74, 0x5f, 0x77, 0x69,
	0x74, 0x68, 0x6f, 0x75, 0x74, 0x5f, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x18, 0x06, 0x20, 0x01,
	0x28, 0x08, 0x52, 0x13, 0x70, 0x65, 0x72, 0x6d, 0x69, 0x74, 0x57, 0x69, 0x74, 0x68, 0x6f, 0x75,
	0x74, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x12, 0x30, 0x0a, 0x14, 0x69, 0x6e, 0x69, 0x74, 0x69,
	0x61, 0x6c, 0x5f, 0x77, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x5f, 0x73, 0x69, 0x7a, 0x65, 0x18,
	0x07, 0x20, 0x01, 0x28, 0x05, 0x52, 0x12, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x6c, 0x57, 0x69,
	0x6e, 0x64, 0x6f, 0x77, 0x73, 0x53, 0x69, 0x7a, 0x65, 0x3a, 0x24, 0x82, 0xb5, 0x18, 0x0b, 0x0a,
	0x09, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x82, 0xb5, 0x18, 0x06, 0x12, 0x04,
	0x67, 0x72, 0x70, 0x63, 0x82, 0xb5, 0x18, 0x07, 0x8a, 0xff, 0x29, 0x03, 0x67, 0x75, 0x6e, 0x2a,
	0x23, 0x0a, 0x04, 0x4d, 0x6f, 0x64, 0x65, 0x12, 0x07, 0x0a, 0x03, 0x47, 0x75, 0x6e, 0x10, 0x00,
	0x12, 0x09, 0x0a, 0x05, 0x4d, 0x75, 0x6c, 0x74, 0x69, 0x10, 0x01, 0x12, 0x07, 0x0a, 0x03, 0x52,
	0x61, 0x77, 0x10, 0x02, 0x42, 0x85, 0x01, 0x0a, 0x26, 0x63, 0x6f, 0x6d, 0x2e, 0x76, 0x32, 0x72,
	0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72,
	0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2e, 0x67, 0x72, 0x70, 0x63, 0x5a,
	0x36, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x76, 0x32, 0x66, 0x6c,
	0x79, 0x2f, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2d, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x76, 0x35, 0x2f,
	0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e,
	0x65, 0x74, 0x2f, 0x67, 0x72, 0x70, 0x63, 0xaa, 0x02, 0x22, 0x56, 0x32, 0x52, 0x61, 0x79, 0x2e,
	0x43, 0x6f, 0x72, 0x65, 0x2e, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x49,
	0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2e, 0x47, 0x72, 0x70, 0x63, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_transport_internet_grpc_config_proto_rawDescOnce sync.Once
	file_transport_internet_grpc_config_proto_rawDescData = file_transport_internet_grpc_config_proto_rawDesc
)

func file_transport_internet_grpc_config_proto_rawDescGZIP() []byte {
	file_transport_internet_grpc_config_proto_rawDescOnce.Do(func() {
		file_transport_internet_grpc_config_proto_rawDescData = protoimpl.X.CompressGZIP(file_transport_internet_grpc_config_proto_rawDescData)
	})
	return file_transport_internet_grpc_config_proto_rawDescData
}

var file_transport_internet_grpc_config_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_transport_internet_grpc_config_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_transport_internet_grpc_config_proto_goTypes = []interface{}{
	(Mode)(0),      // 0: v2ray.core.transport.internet.grpc.encoding.Mode
	(*Config)(nil), // 1: v2ray.core.transport.internet.grpc.encoding.Config
}
var file_transport_internet_grpc_config_proto_depIdxs = []int32{
	0, // 0: v2ray.core.transport.internet.grpc.encoding.Config.mode:type_name -> v2ray.core.transport.internet.grpc.encoding.Mode
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_transport_internet_grpc_config_proto_init() }
func file_transport_internet_grpc_config_proto_init() {
	if File_transport_internet_grpc_config_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_transport_internet_grpc_config_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
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
			RawDescriptor: file_transport_internet_grpc_config_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_transport_internet_grpc_config_proto_goTypes,
		DependencyIndexes: file_transport_internet_grpc_config_proto_depIdxs,
		EnumInfos:         file_transport_internet_grpc_config_proto_enumTypes,
		MessageInfos:      file_transport_internet_grpc_config_proto_msgTypes,
	}.Build()
	File_transport_internet_grpc_config_proto = out.File
	file_transport_internet_grpc_config_proto_rawDesc = nil
	file_transport_internet_grpc_config_proto_goTypes = nil
	file_transport_internet_grpc_config_proto_depIdxs = nil
}
