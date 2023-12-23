package serial

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

// TypedMessage is a serialized proto message along with its type name.
type TypedMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The name of the message type, retrieved from protobuf API.
	Type string `protobuf:"bytes,1,opt,name=type,proto3" json:"type,omitempty"`
	// Serialized proto message.
	Value []byte `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
}

func (x *TypedMessage) Reset() {
	*x = TypedMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_common_serial_typed_message_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TypedMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TypedMessage) ProtoMessage() {}

func (x *TypedMessage) ProtoReflect() protoreflect.Message {
	mi := &file_common_serial_typed_message_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TypedMessage.ProtoReflect.Descriptor instead.
func (*TypedMessage) Descriptor() ([]byte, []int) {
	return file_common_serial_typed_message_proto_rawDescGZIP(), []int{0}
}

func (x *TypedMessage) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *TypedMessage) GetValue() []byte {
	if x != nil {
		return x.Value
	}
	return nil
}

var File_common_serial_typed_message_proto protoreflect.FileDescriptor

var file_common_serial_typed_message_proto_rawDesc = []byte{
	0x0a, 0x21, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x73, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x2f,
	0x74, 0x79, 0x70, 0x65, 0x64, 0x5f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x12, 0x18, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e,
	0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x73, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x22, 0x38, 0x0a,
	0x0c, 0x54, 0x79, 0x70, 0x65, 0x64, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x12, 0x0a,
	0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x74, 0x79, 0x70,
	0x65, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x42, 0x69, 0x0a, 0x1c, 0x63, 0x6f, 0x6d, 0x2e, 0x76,
	0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e,
	0x2e, 0x73, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x50, 0x01, 0x5a, 0x2c, 0x67, 0x69, 0x74, 0x68, 0x75,
	0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x76, 0x32, 0x66, 0x6c, 0x79, 0x2f, 0x76, 0x32, 0x72, 0x61,
	0x79, 0x2d, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x76, 0x34, 0x2f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e,
	0x2f, 0x73, 0x65, 0x72, 0x69, 0x61, 0x6c, 0xaa, 0x02, 0x18, 0x56, 0x32, 0x52, 0x61, 0x79, 0x2e,
	0x43, 0x6f, 0x72, 0x65, 0x2e, 0x43, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x53, 0x65, 0x72, 0x69,
	0x61, 0x6c, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_common_serial_typed_message_proto_rawDescOnce sync.Once
	file_common_serial_typed_message_proto_rawDescData = file_common_serial_typed_message_proto_rawDesc
)

func file_common_serial_typed_message_proto_rawDescGZIP() []byte {
	file_common_serial_typed_message_proto_rawDescOnce.Do(func() {
		file_common_serial_typed_message_proto_rawDescData = protoimpl.X.CompressGZIP(file_common_serial_typed_message_proto_rawDescData)
	})
	return file_common_serial_typed_message_proto_rawDescData
}

var file_common_serial_typed_message_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_common_serial_typed_message_proto_goTypes = []any{
	(*TypedMessage)(nil), // 0: v2ray.core.common.serial.TypedMessage
}
var file_common_serial_typed_message_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_common_serial_typed_message_proto_init() }
func file_common_serial_typed_message_proto_init() {
	if File_common_serial_typed_message_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_common_serial_typed_message_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*TypedMessage); i {
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
			RawDescriptor: file_common_serial_typed_message_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_common_serial_typed_message_proto_goTypes,
		DependencyIndexes: file_common_serial_typed_message_proto_depIdxs,
		MessageInfos:      file_common_serial_typed_message_proto_msgTypes,
	}.Build()
	File_common_serial_typed_message_proto = out.File
	file_common_serial_typed_message_proto_rawDesc = nil
	file_common_serial_typed_message_proto_goTypes = nil
	file_common_serial_typed_message_proto_depIdxs = nil
}
