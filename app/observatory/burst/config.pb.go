// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.21.1
// source: app/observatory/burst/config.proto

package burst

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

type Config struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// @Document The selectors for outbound under observation
	SubjectSelector []string          `protobuf:"bytes,2,rep,name=subject_selector,json=subjectSelector,proto3" json:"subject_selector,omitempty"`
	PingConfig      *HealthPingConfig `protobuf:"bytes,3,opt,name=ping_config,json=pingConfig,proto3" json:"ping_config,omitempty"`
}

func (x *Config) Reset() {
	*x = Config{}
	if protoimpl.UnsafeEnabled {
		mi := &file_app_observatory_burst_config_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Config) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Config) ProtoMessage() {}

func (x *Config) ProtoReflect() protoreflect.Message {
	mi := &file_app_observatory_burst_config_proto_msgTypes[0]
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
	return file_app_observatory_burst_config_proto_rawDescGZIP(), []int{0}
}

func (x *Config) GetSubjectSelector() []string {
	if x != nil {
		return x.SubjectSelector
	}
	return nil
}

func (x *Config) GetPingConfig() *HealthPingConfig {
	if x != nil {
		return x.PingConfig
	}
	return nil
}

type HealthPingConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// destination url, need 204 for success return
	// default http://www.google.com/gen_204
	Destination string `protobuf:"bytes,1,opt,name=destination,proto3" json:"destination,omitempty"`
	// connectivity check url
	Connectivity string `protobuf:"bytes,2,opt,name=connectivity,proto3" json:"connectivity,omitempty"`
	// health check interval, int64 values of time.Duration
	Interval int64 `protobuf:"varint,3,opt,name=interval,proto3" json:"interval,omitempty"`
	// sampling count is the amount of recent ping results which are kept for calculation
	SamplingCount int32 `protobuf:"varint,4,opt,name=samplingCount,proto3" json:"samplingCount,omitempty"`
	// ping timeout, int64 values of time.Duration
	Timeout int64 `protobuf:"varint,5,opt,name=timeout,proto3" json:"timeout,omitempty"`
}

func (x *HealthPingConfig) Reset() {
	*x = HealthPingConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_app_observatory_burst_config_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HealthPingConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HealthPingConfig) ProtoMessage() {}

func (x *HealthPingConfig) ProtoReflect() protoreflect.Message {
	mi := &file_app_observatory_burst_config_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HealthPingConfig.ProtoReflect.Descriptor instead.
func (*HealthPingConfig) Descriptor() ([]byte, []int) {
	return file_app_observatory_burst_config_proto_rawDescGZIP(), []int{1}
}

func (x *HealthPingConfig) GetDestination() string {
	if x != nil {
		return x.Destination
	}
	return ""
}

func (x *HealthPingConfig) GetConnectivity() string {
	if x != nil {
		return x.Connectivity
	}
	return ""
}

func (x *HealthPingConfig) GetInterval() int64 {
	if x != nil {
		return x.Interval
	}
	return 0
}

func (x *HealthPingConfig) GetSamplingCount() int32 {
	if x != nil {
		return x.SamplingCount
	}
	return 0
}

func (x *HealthPingConfig) GetTimeout() int64 {
	if x != nil {
		return x.Timeout
	}
	return 0
}

var File_app_observatory_burst_config_proto protoreflect.FileDescriptor

var file_app_observatory_burst_config_proto_rawDesc = []byte{
	0x0a, 0x22, 0x61, 0x70, 0x70, 0x2f, 0x6f, 0x62, 0x73, 0x65, 0x72, 0x76, 0x61, 0x74, 0x6f, 0x72,
	0x79, 0x2f, 0x62, 0x75, 0x72, 0x73, 0x74, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x20, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65,
	0x2e, 0x61, 0x70, 0x70, 0x2e, 0x6f, 0x62, 0x73, 0x65, 0x72, 0x76, 0x61, 0x74, 0x6f, 0x72, 0x79,
	0x2e, 0x62, 0x75, 0x72, 0x73, 0x74, 0x1a, 0x20, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x65, 0x78, 0x74, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f,
	0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xad, 0x01, 0x0a, 0x06, 0x43, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x12, 0x29, 0x0a, 0x10, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x73,
	0x65, 0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x18, 0x02, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0f, 0x73,
	0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x12, 0x53,
	0x0a, 0x0b, 0x70, 0x69, 0x6e, 0x67, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x32, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65,
	0x2e, 0x61, 0x70, 0x70, 0x2e, 0x6f, 0x62, 0x73, 0x65, 0x72, 0x76, 0x61, 0x74, 0x6f, 0x72, 0x79,
	0x2e, 0x62, 0x75, 0x72, 0x73, 0x74, 0x2e, 0x48, 0x65, 0x61, 0x6c, 0x74, 0x68, 0x50, 0x69, 0x6e,
	0x67, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x52, 0x0a, 0x70, 0x69, 0x6e, 0x67, 0x43, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x3a, 0x23, 0x82, 0xb5, 0x18, 0x09, 0x0a, 0x07, 0x73, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x82, 0xb5, 0x18, 0x12, 0x12, 0x10, 0x62, 0x75, 0x72, 0x73, 0x74, 0x4f, 0x62, 0x73,
	0x65, 0x72, 0x76, 0x61, 0x74, 0x6f, 0x72, 0x79, 0x22, 0xb4, 0x01, 0x0a, 0x10, 0x48, 0x65, 0x61,
	0x6c, 0x74, 0x68, 0x50, 0x69, 0x6e, 0x67, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x20, 0x0a,
	0x0b, 0x64, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12,
	0x22, 0x0a, 0x0c, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x76,
	0x69, 0x74, 0x79, 0x12, 0x1a, 0x0a, 0x08, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x76, 0x61, 0x6c, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x03, 0x52, 0x08, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x76, 0x61, 0x6c, 0x12,
	0x24, 0x0a, 0x0d, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x69, 0x6e, 0x67, 0x43, 0x6f, 0x75, 0x6e, 0x74,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x05, 0x52, 0x0d, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x69, 0x6e, 0x67,
	0x43, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74,
	0x18, 0x05, 0x20, 0x01, 0x28, 0x03, 0x52, 0x07, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x42,
	0x81, 0x01, 0x0a, 0x24, 0x63, 0x6f, 0x6d, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f,
	0x72, 0x65, 0x2e, 0x61, 0x70, 0x70, 0x2e, 0x6f, 0x62, 0x73, 0x65, 0x72, 0x76, 0x61, 0x74, 0x6f,
	0x72, 0x79, 0x2e, 0x62, 0x75, 0x72, 0x73, 0x74, 0x50, 0x01, 0x5a, 0x34, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x76, 0x32, 0x66, 0x6c, 0x79, 0x2f, 0x76, 0x32, 0x72,
	0x61, 0x79, 0x2d, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x76, 0x35, 0x2f, 0x61, 0x70, 0x70, 0x2f, 0x6f,
	0x62, 0x73, 0x65, 0x72, 0x76, 0x61, 0x74, 0x6f, 0x72, 0x79, 0x2f, 0x62, 0x75, 0x72, 0x73, 0x74,
	0xaa, 0x02, 0x20, 0x56, 0x32, 0x52, 0x61, 0x79, 0x2e, 0x43, 0x6f, 0x72, 0x65, 0x2e, 0x41, 0x70,
	0x70, 0x2e, 0x4f, 0x62, 0x73, 0x65, 0x72, 0x76, 0x61, 0x74, 0x6f, 0x72, 0x79, 0x2e, 0x42, 0x75,
	0x72, 0x73, 0x74, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_app_observatory_burst_config_proto_rawDescOnce sync.Once
	file_app_observatory_burst_config_proto_rawDescData = file_app_observatory_burst_config_proto_rawDesc
)

func file_app_observatory_burst_config_proto_rawDescGZIP() []byte {
	file_app_observatory_burst_config_proto_rawDescOnce.Do(func() {
		file_app_observatory_burst_config_proto_rawDescData = protoimpl.X.CompressGZIP(file_app_observatory_burst_config_proto_rawDescData)
	})
	return file_app_observatory_burst_config_proto_rawDescData
}

var file_app_observatory_burst_config_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_app_observatory_burst_config_proto_goTypes = []interface{}{
	(*Config)(nil),           // 0: v2ray.core.app.observatory.burst.Config
	(*HealthPingConfig)(nil), // 1: v2ray.core.app.observatory.burst.HealthPingConfig
}
var file_app_observatory_burst_config_proto_depIdxs = []int32{
	1, // 0: v2ray.core.app.observatory.burst.Config.ping_config:type_name -> v2ray.core.app.observatory.burst.HealthPingConfig
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_app_observatory_burst_config_proto_init() }
func file_app_observatory_burst_config_proto_init() {
	if File_app_observatory_burst_config_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_app_observatory_burst_config_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
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
		file_app_observatory_burst_config_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HealthPingConfig); i {
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
			RawDescriptor: file_app_observatory_burst_config_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_app_observatory_burst_config_proto_goTypes,
		DependencyIndexes: file_app_observatory_burst_config_proto_depIdxs,
		MessageInfos:      file_app_observatory_burst_config_proto_msgTypes,
	}.Build()
	File_app_observatory_burst_config_proto = out.File
	file_app_observatory_burst_config_proto_rawDesc = nil
	file_app_observatory_burst_config_proto_goTypes = nil
	file_app_observatory_burst_config_proto_depIdxs = nil
}
