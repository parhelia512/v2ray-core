package stats

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

type Config struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *Config) Reset() {
	*x = Config{}
	if protoimpl.UnsafeEnabled {
		mi := &file_app_stats_config_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Config) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Config) ProtoMessage() {}

func (x *Config) ProtoReflect() protoreflect.Message {
	mi := &file_app_stats_config_proto_msgTypes[0]
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
	return file_app_stats_config_proto_rawDescGZIP(), []int{0}
}

type ChannelConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Blocking        bool  `protobuf:"varint,1,opt,name=Blocking,proto3" json:"Blocking,omitempty"`
	SubscriberLimit int32 `protobuf:"varint,2,opt,name=SubscriberLimit,proto3" json:"SubscriberLimit,omitempty"`
	BufferSize      int32 `protobuf:"varint,3,opt,name=BufferSize,proto3" json:"BufferSize,omitempty"`
}

func (x *ChannelConfig) Reset() {
	*x = ChannelConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_app_stats_config_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ChannelConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ChannelConfig) ProtoMessage() {}

func (x *ChannelConfig) ProtoReflect() protoreflect.Message {
	mi := &file_app_stats_config_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ChannelConfig.ProtoReflect.Descriptor instead.
func (*ChannelConfig) Descriptor() ([]byte, []int) {
	return file_app_stats_config_proto_rawDescGZIP(), []int{1}
}

func (x *ChannelConfig) GetBlocking() bool {
	if x != nil {
		return x.Blocking
	}
	return false
}

func (x *ChannelConfig) GetSubscriberLimit() int32 {
	if x != nil {
		return x.SubscriberLimit
	}
	return 0
}

func (x *ChannelConfig) GetBufferSize() int32 {
	if x != nil {
		return x.BufferSize
	}
	return 0
}

var File_app_stats_config_proto protoreflect.FileDescriptor

var file_app_stats_config_proto_rawDesc = []byte{
	0x0a, 0x16, 0x61, 0x70, 0x70, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x73, 0x2f, 0x63, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x14, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e,
	0x63, 0x6f, 0x72, 0x65, 0x2e, 0x61, 0x70, 0x70, 0x2e, 0x73, 0x74, 0x61, 0x74, 0x73, 0x22, 0x08,
	0x0a, 0x06, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x22, 0x75, 0x0a, 0x0d, 0x43, 0x68, 0x61, 0x6e,
	0x6e, 0x65, 0x6c, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x1a, 0x0a, 0x08, 0x42, 0x6c, 0x6f,
	0x63, 0x6b, 0x69, 0x6e, 0x67, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x08, 0x42, 0x6c, 0x6f,
	0x63, 0x6b, 0x69, 0x6e, 0x67, 0x12, 0x28, 0x0a, 0x0f, 0x53, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69,
	0x62, 0x65, 0x72, 0x4c, 0x69, 0x6d, 0x69, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x05, 0x52, 0x0f,
	0x53, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69, 0x62, 0x65, 0x72, 0x4c, 0x69, 0x6d, 0x69, 0x74, 0x12,
	0x1e, 0x0a, 0x0a, 0x42, 0x75, 0x66, 0x66, 0x65, 0x72, 0x53, 0x69, 0x7a, 0x65, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x05, 0x52, 0x0a, 0x42, 0x75, 0x66, 0x66, 0x65, 0x72, 0x53, 0x69, 0x7a, 0x65, 0x42,
	0x5d, 0x0a, 0x18, 0x63, 0x6f, 0x6d, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72,
	0x65, 0x2e, 0x61, 0x70, 0x70, 0x2e, 0x73, 0x74, 0x61, 0x74, 0x73, 0x50, 0x01, 0x5a, 0x28, 0x67,
	0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x76, 0x32, 0x66, 0x6c, 0x79, 0x2f,
	0x76, 0x32, 0x72, 0x61, 0x79, 0x2d, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x76, 0x34, 0x2f, 0x61, 0x70,
	0x70, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x73, 0xaa, 0x02, 0x14, 0x56, 0x32, 0x52, 0x61, 0x79, 0x2e,
	0x43, 0x6f, 0x72, 0x65, 0x2e, 0x41, 0x70, 0x70, 0x2e, 0x53, 0x74, 0x61, 0x74, 0x73, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_app_stats_config_proto_rawDescOnce sync.Once
	file_app_stats_config_proto_rawDescData = file_app_stats_config_proto_rawDesc
)

func file_app_stats_config_proto_rawDescGZIP() []byte {
	file_app_stats_config_proto_rawDescOnce.Do(func() {
		file_app_stats_config_proto_rawDescData = protoimpl.X.CompressGZIP(file_app_stats_config_proto_rawDescData)
	})
	return file_app_stats_config_proto_rawDescData
}

var file_app_stats_config_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_app_stats_config_proto_goTypes = []interface{}{
	(*Config)(nil),        // 0: v2ray.core.app.stats.Config
	(*ChannelConfig)(nil), // 1: v2ray.core.app.stats.ChannelConfig
}
var file_app_stats_config_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_app_stats_config_proto_init() }
func file_app_stats_config_proto_init() {
	if File_app_stats_config_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_app_stats_config_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
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
		file_app_stats_config_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ChannelConfig); i {
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
			RawDescriptor: file_app_stats_config_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_app_stats_config_proto_goTypes,
		DependencyIndexes: file_app_stats_config_proto_depIdxs,
		MessageInfos:      file_app_stats_config_proto_msgTypes,
	}.Build()
	File_app_stats_config_proto = out.File
	file_app_stats_config_proto_rawDesc = nil
	file_app_stats_config_proto_goTypes = nil
	file_app_stats_config_proto_depIdxs = nil
}
