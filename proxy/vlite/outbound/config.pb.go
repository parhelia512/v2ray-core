// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.17.3
// source: proxy/vlite/outbound/config.proto

package outbound

import (
	net "github.com/v2fly/v2ray-core/v4/common/net"
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

type UDPProtocolConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Address                     *net.IPOrDomain `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"`
	Port                        uint32          `protobuf:"varint,2,opt,name=port,proto3" json:"port,omitempty"`
	Password                    string          `protobuf:"bytes,3,opt,name=password,proto3" json:"password,omitempty"`
	ScramblePacket              bool            `protobuf:"varint,4,opt,name=scramble_packet,json=scramblePacket,proto3" json:"scramble_packet,omitempty"`
	EnableFec                   bool            `protobuf:"varint,5,opt,name=enable_fec,json=enableFec,proto3" json:"enable_fec,omitempty"`
	EnableStabilization         bool            `protobuf:"varint,6,opt,name=enable_stabilization,json=enableStabilization,proto3" json:"enable_stabilization,omitempty"`
	EnableRenegotiation         bool            `protobuf:"varint,7,opt,name=enable_renegotiation,json=enableRenegotiation,proto3" json:"enable_renegotiation,omitempty"`
	HandshakeMaskingPaddingSize uint32          `protobuf:"varint,8,opt,name=handshake_masking_padding_size,json=handshakeMaskingPaddingSize,proto3" json:"handshake_masking_padding_size,omitempty"`
}

func (x *UDPProtocolConfig) Reset() {
	*x = UDPProtocolConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proxy_vlite_outbound_config_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UDPProtocolConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UDPProtocolConfig) ProtoMessage() {}

func (x *UDPProtocolConfig) ProtoReflect() protoreflect.Message {
	mi := &file_proxy_vlite_outbound_config_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UDPProtocolConfig.ProtoReflect.Descriptor instead.
func (*UDPProtocolConfig) Descriptor() ([]byte, []int) {
	return file_proxy_vlite_outbound_config_proto_rawDescGZIP(), []int{0}
}

func (x *UDPProtocolConfig) GetAddress() *net.IPOrDomain {
	if x != nil {
		return x.Address
	}
	return nil
}

func (x *UDPProtocolConfig) GetPort() uint32 {
	if x != nil {
		return x.Port
	}
	return 0
}

func (x *UDPProtocolConfig) GetPassword() string {
	if x != nil {
		return x.Password
	}
	return ""
}

func (x *UDPProtocolConfig) GetScramblePacket() bool {
	if x != nil {
		return x.ScramblePacket
	}
	return false
}

func (x *UDPProtocolConfig) GetEnableFec() bool {
	if x != nil {
		return x.EnableFec
	}
	return false
}

func (x *UDPProtocolConfig) GetEnableStabilization() bool {
	if x != nil {
		return x.EnableStabilization
	}
	return false
}

func (x *UDPProtocolConfig) GetEnableRenegotiation() bool {
	if x != nil {
		return x.EnableRenegotiation
	}
	return false
}

func (x *UDPProtocolConfig) GetHandshakeMaskingPaddingSize() uint32 {
	if x != nil {
		return x.HandshakeMaskingPaddingSize
	}
	return 0
}

var File_proxy_vlite_outbound_config_proto protoreflect.FileDescriptor

var file_proxy_vlite_outbound_config_proto_rawDesc = []byte{
	0x0a, 0x21, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x76, 0x6c, 0x69, 0x74, 0x65, 0x2f, 0x6f, 0x75,
	0x74, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x12, 0x1f, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76, 0x6c, 0x69, 0x74, 0x65, 0x2e, 0x6f, 0x75, 0x74, 0x62,
	0x6f, 0x75, 0x6e, 0x64, 0x1a, 0x18, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x6e, 0x65, 0x74,
	0x2f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xf3,
	0x02, 0x0a, 0x11, 0x55, 0x44, 0x50, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x43, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x12, 0x3b, 0x0a, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x21, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f,
	0x72, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x6e, 0x65, 0x74, 0x2e, 0x49, 0x50,
	0x4f, 0x72, 0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x52, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73,
	0x73, 0x12, 0x12, 0x0a, 0x04, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x04, 0x70, 0x6f, 0x72, 0x74, 0x12, 0x1a, 0x0a, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72,
	0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72,
	0x64, 0x12, 0x27, 0x0a, 0x0f, 0x73, 0x63, 0x72, 0x61, 0x6d, 0x62, 0x6c, 0x65, 0x5f, 0x70, 0x61,
	0x63, 0x6b, 0x65, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0e, 0x73, 0x63, 0x72, 0x61,
	0x6d, 0x62, 0x6c, 0x65, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x12, 0x1d, 0x0a, 0x0a, 0x65, 0x6e,
	0x61, 0x62, 0x6c, 0x65, 0x5f, 0x66, 0x65, 0x63, 0x18, 0x05, 0x20, 0x01, 0x28, 0x08, 0x52, 0x09,
	0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x46, 0x65, 0x63, 0x12, 0x31, 0x0a, 0x14, 0x65, 0x6e, 0x61,
	0x62, 0x6c, 0x65, 0x5f, 0x73, 0x74, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x18, 0x06, 0x20, 0x01, 0x28, 0x08, 0x52, 0x13, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x53,
	0x74, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x31, 0x0a, 0x14,
	0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x5f, 0x72, 0x65, 0x6e, 0x65, 0x67, 0x6f, 0x74, 0x69, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x18, 0x07, 0x20, 0x01, 0x28, 0x08, 0x52, 0x13, 0x65, 0x6e, 0x61, 0x62,
	0x6c, 0x65, 0x52, 0x65, 0x6e, 0x65, 0x67, 0x6f, 0x74, 0x69, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12,
	0x43, 0x0a, 0x1e, 0x68, 0x61, 0x6e, 0x64, 0x73, 0x68, 0x61, 0x6b, 0x65, 0x5f, 0x6d, 0x61, 0x73,
	0x6b, 0x69, 0x6e, 0x67, 0x5f, 0x70, 0x61, 0x64, 0x64, 0x69, 0x6e, 0x67, 0x5f, 0x73, 0x69, 0x7a,
	0x65, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x1b, 0x68, 0x61, 0x6e, 0x64, 0x73, 0x68, 0x61,
	0x6b, 0x65, 0x4d, 0x61, 0x73, 0x6b, 0x69, 0x6e, 0x67, 0x50, 0x61, 0x64, 0x64, 0x69, 0x6e, 0x67,
	0x53, 0x69, 0x7a, 0x65, 0x42, 0x7e, 0x0a, 0x23, 0x63, 0x6f, 0x6d, 0x2e, 0x76, 0x32, 0x72, 0x61,
	0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76, 0x6c, 0x69,
	0x74, 0x65, 0x2e, 0x6f, 0x75, 0x74, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x50, 0x01, 0x5a, 0x33, 0x67,
	0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x76, 0x32, 0x66, 0x6c, 0x79, 0x2f,
	0x76, 0x32, 0x72, 0x61, 0x79, 0x2d, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x76, 0x34, 0x2f, 0x70, 0x72,
	0x6f, 0x78, 0x79, 0x2f, 0x76, 0x6c, 0x69, 0x74, 0x65, 0x2f, 0x6f, 0x75, 0x74, 0x62, 0x6f, 0x75,
	0x6e, 0x64, 0xaa, 0x02, 0x1f, 0x56, 0x32, 0x52, 0x61, 0x79, 0x2e, 0x43, 0x6f, 0x72, 0x65, 0x2e,
	0x50, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x56, 0x6c, 0x69, 0x74, 0x65, 0x2e, 0x4f, 0x75, 0x74, 0x62,
	0x6f, 0x75, 0x6e, 0x64, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_proxy_vlite_outbound_config_proto_rawDescOnce sync.Once
	file_proxy_vlite_outbound_config_proto_rawDescData = file_proxy_vlite_outbound_config_proto_rawDesc
)

func file_proxy_vlite_outbound_config_proto_rawDescGZIP() []byte {
	file_proxy_vlite_outbound_config_proto_rawDescOnce.Do(func() {
		file_proxy_vlite_outbound_config_proto_rawDescData = protoimpl.X.CompressGZIP(file_proxy_vlite_outbound_config_proto_rawDescData)
	})
	return file_proxy_vlite_outbound_config_proto_rawDescData
}

var file_proxy_vlite_outbound_config_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_proxy_vlite_outbound_config_proto_goTypes = []interface{}{
	(*UDPProtocolConfig)(nil), // 0: v2ray.core.proxy.vlite.outbound.UDPProtocolConfig
	(*net.IPOrDomain)(nil),    // 1: v2ray.core.common.net.IPOrDomain
}
var file_proxy_vlite_outbound_config_proto_depIdxs = []int32{
	1, // 0: v2ray.core.proxy.vlite.outbound.UDPProtocolConfig.address:type_name -> v2ray.core.common.net.IPOrDomain
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_proxy_vlite_outbound_config_proto_init() }
func file_proxy_vlite_outbound_config_proto_init() {
	if File_proxy_vlite_outbound_config_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_proxy_vlite_outbound_config_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UDPProtocolConfig); i {
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
			RawDescriptor: file_proxy_vlite_outbound_config_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_proxy_vlite_outbound_config_proto_goTypes,
		DependencyIndexes: file_proxy_vlite_outbound_config_proto_depIdxs,
		MessageInfos:      file_proxy_vlite_outbound_config_proto_msgTypes,
	}.Build()
	File_proxy_vlite_outbound_config_proto = out.File
	file_proxy_vlite_outbound_config_proto_rawDesc = nil
	file_proxy_vlite_outbound_config_proto_goTypes = nil
	file_proxy_vlite_outbound_config_proto_depIdxs = nil
}
