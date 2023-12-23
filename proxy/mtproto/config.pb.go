package mtproto

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

type Account struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Secret []byte `protobuf:"bytes,1,opt,name=secret,proto3" json:"secret,omitempty"`
}

func (x *Account) Reset() {
	*x = Account{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proxy_mtproto_config_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Account) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Account) ProtoMessage() {}

func (x *Account) ProtoReflect() protoreflect.Message {
	mi := &file_proxy_mtproto_config_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Account.ProtoReflect.Descriptor instead.
func (*Account) Descriptor() ([]byte, []int) {
	return file_proxy_mtproto_config_proto_rawDescGZIP(), []int{0}
}

func (x *Account) GetSecret() []byte {
	if x != nil {
		return x.Secret
	}
	return nil
}

type ServerConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// User is a list of users that allowed to connect to this inbound.
	// Although this is a repeated field, only the first user is effective for
	// now.
	User []*protocol.User `protobuf:"bytes,1,rep,name=user,proto3" json:"user,omitempty"`
}

func (x *ServerConfig) Reset() {
	*x = ServerConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proxy_mtproto_config_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ServerConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ServerConfig) ProtoMessage() {}

func (x *ServerConfig) ProtoReflect() protoreflect.Message {
	mi := &file_proxy_mtproto_config_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ServerConfig.ProtoReflect.Descriptor instead.
func (*ServerConfig) Descriptor() ([]byte, []int) {
	return file_proxy_mtproto_config_proto_rawDescGZIP(), []int{1}
}

func (x *ServerConfig) GetUser() []*protocol.User {
	if x != nil {
		return x.User
	}
	return nil
}

type ClientConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *ClientConfig) Reset() {
	*x = ClientConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proxy_mtproto_config_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ClientConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ClientConfig) ProtoMessage() {}

func (x *ClientConfig) ProtoReflect() protoreflect.Message {
	mi := &file_proxy_mtproto_config_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ClientConfig.ProtoReflect.Descriptor instead.
func (*ClientConfig) Descriptor() ([]byte, []int) {
	return file_proxy_mtproto_config_proto_rawDescGZIP(), []int{2}
}

var File_proxy_mtproto_config_proto protoreflect.FileDescriptor

var file_proxy_mtproto_config_proto_rawDesc = []byte{
	0x0a, 0x1a, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x6d, 0x74, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f,
	0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x18, 0x76, 0x32,
	0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x6d,
	0x74, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1a, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x2f, 0x75, 0x73, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0x21, 0x0a, 0x07, 0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x16, 0x0a,
	0x06, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x73,
	0x65, 0x63, 0x72, 0x65, 0x74, 0x22, 0x44, 0x0a, 0x0c, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x43,
	0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x34, 0x0a, 0x04, 0x75, 0x73, 0x65, 0x72, 0x18, 0x01, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65,
	0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c,
	0x2e, 0x55, 0x73, 0x65, 0x72, 0x52, 0x04, 0x75, 0x73, 0x65, 0x72, 0x22, 0x0e, 0x0a, 0x0c, 0x43,
	0x6c, 0x69, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x42, 0x69, 0x0a, 0x1c, 0x63,
	0x6f, 0x6d, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x78, 0x79, 0x2e, 0x6d, 0x74, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x2c, 0x67,
	0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x76, 0x32, 0x66, 0x6c, 0x79, 0x2f,
	0x76, 0x32, 0x72, 0x61, 0x79, 0x2d, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x76, 0x34, 0x2f, 0x70, 0x72,
	0x6f, 0x78, 0x79, 0x2f, 0x6d, 0x74, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0xaa, 0x02, 0x18, 0x56, 0x32,
	0x52, 0x61, 0x79, 0x2e, 0x43, 0x6f, 0x72, 0x65, 0x2e, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x4d,
	0x74, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_proxy_mtproto_config_proto_rawDescOnce sync.Once
	file_proxy_mtproto_config_proto_rawDescData = file_proxy_mtproto_config_proto_rawDesc
)

func file_proxy_mtproto_config_proto_rawDescGZIP() []byte {
	file_proxy_mtproto_config_proto_rawDescOnce.Do(func() {
		file_proxy_mtproto_config_proto_rawDescData = protoimpl.X.CompressGZIP(file_proxy_mtproto_config_proto_rawDescData)
	})
	return file_proxy_mtproto_config_proto_rawDescData
}

var file_proxy_mtproto_config_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_proxy_mtproto_config_proto_goTypes = []any{
	(*Account)(nil),       // 0: v2ray.core.proxy.mtproto.Account
	(*ServerConfig)(nil),  // 1: v2ray.core.proxy.mtproto.ServerConfig
	(*ClientConfig)(nil),  // 2: v2ray.core.proxy.mtproto.ClientConfig
	(*protocol.User)(nil), // 3: v2ray.core.common.protocol.User
}
var file_proxy_mtproto_config_proto_depIdxs = []int32{
	3, // 0: v2ray.core.proxy.mtproto.ServerConfig.user:type_name -> v2ray.core.common.protocol.User
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_proxy_mtproto_config_proto_init() }
func file_proxy_mtproto_config_proto_init() {
	if File_proxy_mtproto_config_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_proxy_mtproto_config_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*Account); i {
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
		file_proxy_mtproto_config_proto_msgTypes[1].Exporter = func(v any, i int) any {
			switch v := v.(*ServerConfig); i {
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
		file_proxy_mtproto_config_proto_msgTypes[2].Exporter = func(v any, i int) any {
			switch v := v.(*ClientConfig); i {
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
			RawDescriptor: file_proxy_mtproto_config_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_proxy_mtproto_config_proto_goTypes,
		DependencyIndexes: file_proxy_mtproto_config_proto_depIdxs,
		MessageInfos:      file_proxy_mtproto_config_proto_msgTypes,
	}.Build()
	File_proxy_mtproto_config_proto = out.File
	file_proxy_mtproto_config_proto_rawDesc = nil
	file_proxy_mtproto_config_proto_goTypes = nil
	file_proxy_mtproto_config_proto_depIdxs = nil
}
