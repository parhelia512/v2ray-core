package reality

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

	Show         bool     `protobuf:"varint,1,opt,name=show,proto3" json:"show,omitempty"`
	Dest         string   `protobuf:"bytes,2,opt,name=dest,proto3" json:"dest,omitempty"`
	Type         string   `protobuf:"bytes,3,opt,name=type,proto3" json:"type,omitempty"`
	Xver         uint64   `protobuf:"varint,4,opt,name=xver,proto3" json:"xver,omitempty"`
	ServerNames  []string `protobuf:"bytes,5,rep,name=server_names,json=serverNames,proto3" json:"server_names,omitempty"`
	PrivateKey   []byte   `protobuf:"bytes,6,opt,name=private_key,json=privateKey,proto3" json:"private_key,omitempty"`
	MinClientVer []byte   `protobuf:"bytes,7,opt,name=min_client_ver,json=minClientVer,proto3" json:"min_client_ver,omitempty"`
	MaxClientVer []byte   `protobuf:"bytes,8,opt,name=max_client_ver,json=maxClientVer,proto3" json:"max_client_ver,omitempty"`
	MaxTimeDiff  uint64   `protobuf:"varint,9,opt,name=max_time_diff,json=maxTimeDiff,proto3" json:"max_time_diff,omitempty"`
	ShortIds     [][]byte `protobuf:"bytes,10,rep,name=short_ids,json=shortIds,proto3" json:"short_ids,omitempty"`
	Fingerprint  string   `protobuf:"bytes,21,opt,name=Fingerprint,proto3" json:"Fingerprint,omitempty"`
	ServerName   string   `protobuf:"bytes,22,opt,name=server_name,json=serverName,proto3" json:"server_name,omitempty"`
	PublicKey    []byte   `protobuf:"bytes,23,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
	ShortId      []byte   `protobuf:"bytes,24,opt,name=short_id,json=shortId,proto3" json:"short_id,omitempty"`
	SpiderX      string   `protobuf:"bytes,25,opt,name=spider_x,json=spiderX,proto3" json:"spider_x,omitempty"`
	SpiderY      []int64  `protobuf:"varint,26,rep,packed,name=spider_y,json=spiderY,proto3" json:"spider_y,omitempty"`
	Version      []byte   `protobuf:"bytes,99,opt,name=version,proto3" json:"version,omitempty"`
}

func (x *Config) Reset() {
	*x = Config{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transport_internet_reality_config_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Config) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Config) ProtoMessage() {}

func (x *Config) ProtoReflect() protoreflect.Message {
	mi := &file_transport_internet_reality_config_proto_msgTypes[0]
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
	return file_transport_internet_reality_config_proto_rawDescGZIP(), []int{0}
}

func (x *Config) GetShow() bool {
	if x != nil {
		return x.Show
	}
	return false
}

func (x *Config) GetDest() string {
	if x != nil {
		return x.Dest
	}
	return ""
}

func (x *Config) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *Config) GetXver() uint64 {
	if x != nil {
		return x.Xver
	}
	return 0
}

func (x *Config) GetServerNames() []string {
	if x != nil {
		return x.ServerNames
	}
	return nil
}

func (x *Config) GetPrivateKey() []byte {
	if x != nil {
		return x.PrivateKey
	}
	return nil
}

func (x *Config) GetMinClientVer() []byte {
	if x != nil {
		return x.MinClientVer
	}
	return nil
}

func (x *Config) GetMaxClientVer() []byte {
	if x != nil {
		return x.MaxClientVer
	}
	return nil
}

func (x *Config) GetMaxTimeDiff() uint64 {
	if x != nil {
		return x.MaxTimeDiff
	}
	return 0
}

func (x *Config) GetShortIds() [][]byte {
	if x != nil {
		return x.ShortIds
	}
	return nil
}

func (x *Config) GetFingerprint() string {
	if x != nil {
		return x.Fingerprint
	}
	return ""
}

func (x *Config) GetServerName() string {
	if x != nil {
		return x.ServerName
	}
	return ""
}

func (x *Config) GetPublicKey() []byte {
	if x != nil {
		return x.PublicKey
	}
	return nil
}

func (x *Config) GetShortId() []byte {
	if x != nil {
		return x.ShortId
	}
	return nil
}

func (x *Config) GetSpiderX() string {
	if x != nil {
		return x.SpiderX
	}
	return ""
}

func (x *Config) GetSpiderY() []int64 {
	if x != nil {
		return x.SpiderY
	}
	return nil
}

func (x *Config) GetVersion() []byte {
	if x != nil {
		return x.Version
	}
	return nil
}

var File_transport_internet_reality_config_proto protoreflect.FileDescriptor

var file_transport_internet_reality_config_proto_rawDesc = []byte{
	0x0a, 0x27, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x69, 0x6e, 0x74, 0x65,
	0x72, 0x6e, 0x65, 0x74, 0x2f, 0x72, 0x65, 0x61, 0x6c, 0x69, 0x74, 0x79, 0x2f, 0x63, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x25, 0x76, 0x32, 0x72, 0x61, 0x79,
	0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e,
	0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2e, 0x72, 0x65, 0x61, 0x6c, 0x69, 0x74, 0x79,
	0x1a, 0x20, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x65, 0x78,
	0x74, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0x8f, 0x04, 0x0a, 0x06, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x12, 0x0a,
	0x04, 0x73, 0x68, 0x6f, 0x77, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x04, 0x73, 0x68, 0x6f,
	0x77, 0x12, 0x12, 0x0a, 0x04, 0x64, 0x65, 0x73, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x04, 0x64, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x78, 0x76, 0x65,
	0x72, 0x18, 0x04, 0x20, 0x01, 0x28, 0x04, 0x52, 0x04, 0x78, 0x76, 0x65, 0x72, 0x12, 0x21, 0x0a,
	0x0c, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x18, 0x05, 0x20,
	0x03, 0x28, 0x09, 0x52, 0x0b, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x4e, 0x61, 0x6d, 0x65, 0x73,
	0x12, 0x1f, 0x0a, 0x0b, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x5f, 0x6b, 0x65, 0x79, 0x18,
	0x06, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0a, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x4b, 0x65,
	0x79, 0x12, 0x24, 0x0a, 0x0e, 0x6d, 0x69, 0x6e, 0x5f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f,
	0x76, 0x65, 0x72, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0c, 0x6d, 0x69, 0x6e, 0x43, 0x6c,
	0x69, 0x65, 0x6e, 0x74, 0x56, 0x65, 0x72, 0x12, 0x24, 0x0a, 0x0e, 0x6d, 0x61, 0x78, 0x5f, 0x63,
	0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x76, 0x65, 0x72, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x0c, 0x6d, 0x61, 0x78, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x56, 0x65, 0x72, 0x12, 0x22, 0x0a,
	0x0d, 0x6d, 0x61, 0x78, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x5f, 0x64, 0x69, 0x66, 0x66, 0x18, 0x09,
	0x20, 0x01, 0x28, 0x04, 0x52, 0x0b, 0x6d, 0x61, 0x78, 0x54, 0x69, 0x6d, 0x65, 0x44, 0x69, 0x66,
	0x66, 0x12, 0x1b, 0x0a, 0x09, 0x73, 0x68, 0x6f, 0x72, 0x74, 0x5f, 0x69, 0x64, 0x73, 0x18, 0x0a,
	0x20, 0x03, 0x28, 0x0c, 0x52, 0x08, 0x73, 0x68, 0x6f, 0x72, 0x74, 0x49, 0x64, 0x73, 0x12, 0x20,
	0x0a, 0x0b, 0x46, 0x69, 0x6e, 0x67, 0x65, 0x72, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x18, 0x15, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0b, 0x46, 0x69, 0x6e, 0x67, 0x65, 0x72, 0x70, 0x72, 0x69, 0x6e, 0x74,
	0x12, 0x1f, 0x0a, 0x0b, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18,
	0x16, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x4e, 0x61, 0x6d,
	0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x6b, 0x65, 0x79, 0x18,
	0x17, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79,
	0x12, 0x19, 0x0a, 0x08, 0x73, 0x68, 0x6f, 0x72, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x18, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x07, 0x73, 0x68, 0x6f, 0x72, 0x74, 0x49, 0x64, 0x12, 0x19, 0x0a, 0x08, 0x73,
	0x70, 0x69, 0x64, 0x65, 0x72, 0x5f, 0x78, 0x18, 0x19, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x73,
	0x70, 0x69, 0x64, 0x65, 0x72, 0x58, 0x12, 0x19, 0x0a, 0x08, 0x73, 0x70, 0x69, 0x64, 0x65, 0x72,
	0x5f, 0x79, 0x18, 0x1a, 0x20, 0x03, 0x28, 0x03, 0x52, 0x07, 0x73, 0x70, 0x69, 0x64, 0x65, 0x72,
	0x59, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x63, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3a, 0x17, 0x82, 0xb5, 0x18,
	0x13, 0x0a, 0x08, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x12, 0x07, 0x72, 0x65, 0x61,
	0x6c, 0x69, 0x74, 0x79, 0x42, 0x90, 0x01, 0x0a, 0x29, 0x63, 0x6f, 0x6d, 0x2e, 0x76, 0x32, 0x72,
	0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72,
	0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2e, 0x72, 0x65, 0x61, 0x6c, 0x69,
	0x74, 0x79, 0x50, 0x01, 0x5a, 0x39, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x76, 0x32, 0x66, 0x6c, 0x79, 0x2f, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2d, 0x63, 0x6f, 0x72,
	0x65, 0x2f, 0x76, 0x35, 0x2f, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x69,
	0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2f, 0x72, 0x65, 0x61, 0x6c, 0x69, 0x74, 0x79, 0xaa,
	0x02, 0x25, 0x56, 0x32, 0x52, 0x61, 0x79, 0x2e, 0x43, 0x6f, 0x72, 0x65, 0x2e, 0x54, 0x72, 0x61,
	0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2e,
	0x52, 0x65, 0x61, 0x6c, 0x69, 0x74, 0x79, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_transport_internet_reality_config_proto_rawDescOnce sync.Once
	file_transport_internet_reality_config_proto_rawDescData = file_transport_internet_reality_config_proto_rawDesc
)

func file_transport_internet_reality_config_proto_rawDescGZIP() []byte {
	file_transport_internet_reality_config_proto_rawDescOnce.Do(func() {
		file_transport_internet_reality_config_proto_rawDescData = protoimpl.X.CompressGZIP(file_transport_internet_reality_config_proto_rawDescData)
	})
	return file_transport_internet_reality_config_proto_rawDescData
}

var file_transport_internet_reality_config_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_transport_internet_reality_config_proto_goTypes = []any{
	(*Config)(nil), // 0: v2ray.core.transport.internet.reality.Config
}
var file_transport_internet_reality_config_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_transport_internet_reality_config_proto_init() }
func file_transport_internet_reality_config_proto_init() {
	if File_transport_internet_reality_config_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_transport_internet_reality_config_proto_msgTypes[0].Exporter = func(v any, i int) any {
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
			RawDescriptor: file_transport_internet_reality_config_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_transport_internet_reality_config_proto_goTypes,
		DependencyIndexes: file_transport_internet_reality_config_proto_depIdxs,
		MessageInfos:      file_transport_internet_reality_config_proto_msgTypes,
	}.Build()
	File_transport_internet_reality_config_proto = out.File
	file_transport_internet_reality_config_proto_rawDesc = nil
	file_transport_internet_reality_config_proto_goTypes = nil
	file_transport_internet_reality_config_proto_depIdxs = nil
}
