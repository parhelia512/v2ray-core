package net

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

type Network int32

const (
	Network_Unknown Network = 0
	// Deprecated: Marked as deprecated in common/net/network.proto.
	Network_RawTCP Network = 1
	Network_TCP    Network = 2
	Network_UDP    Network = 3
	Network_UNIX   Network = 4
)

// Enum value maps for Network.
var (
	Network_name = map[int32]string{
		0: "Unknown",
		1: "RawTCP",
		2: "TCP",
		3: "UDP",
		4: "UNIX",
	}
	Network_value = map[string]int32{
		"Unknown": 0,
		"RawTCP":  1,
		"TCP":     2,
		"UDP":     3,
		"UNIX":    4,
	}
)

func (x Network) Enum() *Network {
	p := new(Network)
	*p = x
	return p
}

func (x Network) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Network) Descriptor() protoreflect.EnumDescriptor {
	return file_common_net_network_proto_enumTypes[0].Descriptor()
}

func (Network) Type() protoreflect.EnumType {
	return &file_common_net_network_proto_enumTypes[0]
}

func (x Network) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Network.Descriptor instead.
func (Network) EnumDescriptor() ([]byte, []int) {
	return file_common_net_network_proto_rawDescGZIP(), []int{0}
}

// NetworkList is a list of Networks.
type NetworkList struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Network []Network `protobuf:"varint,1,rep,packed,name=network,proto3,enum=v2ray.core.common.net.Network" json:"network,omitempty"`
}

func (x *NetworkList) Reset() {
	*x = NetworkList{}
	if protoimpl.UnsafeEnabled {
		mi := &file_common_net_network_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *NetworkList) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NetworkList) ProtoMessage() {}

func (x *NetworkList) ProtoReflect() protoreflect.Message {
	mi := &file_common_net_network_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NetworkList.ProtoReflect.Descriptor instead.
func (*NetworkList) Descriptor() ([]byte, []int) {
	return file_common_net_network_proto_rawDescGZIP(), []int{0}
}

func (x *NetworkList) GetNetwork() []Network {
	if x != nil {
		return x.Network
	}
	return nil
}

var File_common_net_network_proto protoreflect.FileDescriptor

var file_common_net_network_proto_rawDesc = []byte{
	0x0a, 0x18, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x6e, 0x65, 0x74, 0x2f, 0x6e, 0x65, 0x74,
	0x77, 0x6f, 0x72, 0x6b, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x15, 0x76, 0x32, 0x72, 0x61,
	0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x6e, 0x65,
	0x74, 0x22, 0x47, 0x0a, 0x0b, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x4c, 0x69, 0x73, 0x74,
	0x12, 0x38, 0x0a, 0x07, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x18, 0x01, 0x20, 0x03, 0x28,
	0x0e, 0x32, 0x1e, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63,
	0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x6e, 0x65, 0x74, 0x2e, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72,
	0x6b, 0x52, 0x07, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2a, 0x42, 0x0a, 0x07, 0x4e, 0x65,
	0x74, 0x77, 0x6f, 0x72, 0x6b, 0x12, 0x0b, 0x0a, 0x07, 0x55, 0x6e, 0x6b, 0x6e, 0x6f, 0x77, 0x6e,
	0x10, 0x00, 0x12, 0x0e, 0x0a, 0x06, 0x52, 0x61, 0x77, 0x54, 0x43, 0x50, 0x10, 0x01, 0x1a, 0x02,
	0x08, 0x01, 0x12, 0x07, 0x0a, 0x03, 0x54, 0x43, 0x50, 0x10, 0x02, 0x12, 0x07, 0x0a, 0x03, 0x55,
	0x44, 0x50, 0x10, 0x03, 0x12, 0x08, 0x0a, 0x04, 0x55, 0x4e, 0x49, 0x58, 0x10, 0x04, 0x42, 0x60,
	0x0a, 0x19, 0x63, 0x6f, 0x6d, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65,
	0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x6e, 0x65, 0x74, 0x50, 0x01, 0x5a, 0x29, 0x67,
	0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x76, 0x32, 0x66, 0x6c, 0x79, 0x2f,
	0x76, 0x32, 0x72, 0x61, 0x79, 0x2d, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x76, 0x34, 0x2f, 0x63, 0x6f,
	0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x6e, 0x65, 0x74, 0xaa, 0x02, 0x15, 0x56, 0x32, 0x52, 0x61, 0x79,
	0x2e, 0x43, 0x6f, 0x72, 0x65, 0x2e, 0x43, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x4e, 0x65, 0x74,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_common_net_network_proto_rawDescOnce sync.Once
	file_common_net_network_proto_rawDescData = file_common_net_network_proto_rawDesc
)

func file_common_net_network_proto_rawDescGZIP() []byte {
	file_common_net_network_proto_rawDescOnce.Do(func() {
		file_common_net_network_proto_rawDescData = protoimpl.X.CompressGZIP(file_common_net_network_proto_rawDescData)
	})
	return file_common_net_network_proto_rawDescData
}

var file_common_net_network_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_common_net_network_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_common_net_network_proto_goTypes = []interface{}{
	(Network)(0),        // 0: v2ray.core.common.net.Network
	(*NetworkList)(nil), // 1: v2ray.core.common.net.NetworkList
}
var file_common_net_network_proto_depIdxs = []int32{
	0, // 0: v2ray.core.common.net.NetworkList.network:type_name -> v2ray.core.common.net.Network
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_common_net_network_proto_init() }
func file_common_net_network_proto_init() {
	if File_common_net_network_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_common_net_network_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*NetworkList); i {
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
			RawDescriptor: file_common_net_network_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_common_net_network_proto_goTypes,
		DependencyIndexes: file_common_net_network_proto_depIdxs,
		EnumInfos:         file_common_net_network_proto_enumTypes,
		MessageInfos:      file_common_net_network_proto_msgTypes,
	}.Build()
	File_common_net_network_proto = out.File
	file_common_net_network_proto_rawDesc = nil
	file_common_net_network_proto_goTypes = nil
	file_common_net_network_proto_depIdxs = nil
}
