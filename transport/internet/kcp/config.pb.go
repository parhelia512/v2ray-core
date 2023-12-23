package kcp

import (
	_ "github.com/v2fly/v2ray-core/v5/common/protoext"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	anypb "google.golang.org/protobuf/types/known/anypb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Maximum Transmission Unit, in bytes.
type MTU struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Value uint32 `protobuf:"varint,1,opt,name=value,proto3" json:"value,omitempty"`
}

func (x *MTU) Reset() {
	*x = MTU{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transport_internet_kcp_config_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MTU) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MTU) ProtoMessage() {}

func (x *MTU) ProtoReflect() protoreflect.Message {
	mi := &file_transport_internet_kcp_config_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MTU.ProtoReflect.Descriptor instead.
func (*MTU) Descriptor() ([]byte, []int) {
	return file_transport_internet_kcp_config_proto_rawDescGZIP(), []int{0}
}

func (x *MTU) GetValue() uint32 {
	if x != nil {
		return x.Value
	}
	return 0
}

// Transmission Time Interview, in milli-sec.
type TTI struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Value uint32 `protobuf:"varint,1,opt,name=value,proto3" json:"value,omitempty"`
}

func (x *TTI) Reset() {
	*x = TTI{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transport_internet_kcp_config_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TTI) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TTI) ProtoMessage() {}

func (x *TTI) ProtoReflect() protoreflect.Message {
	mi := &file_transport_internet_kcp_config_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TTI.ProtoReflect.Descriptor instead.
func (*TTI) Descriptor() ([]byte, []int) {
	return file_transport_internet_kcp_config_proto_rawDescGZIP(), []int{1}
}

func (x *TTI) GetValue() uint32 {
	if x != nil {
		return x.Value
	}
	return 0
}

// Uplink capacity, in MB.
type UplinkCapacity struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Value uint32 `protobuf:"varint,1,opt,name=value,proto3" json:"value,omitempty"`
}

func (x *UplinkCapacity) Reset() {
	*x = UplinkCapacity{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transport_internet_kcp_config_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UplinkCapacity) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UplinkCapacity) ProtoMessage() {}

func (x *UplinkCapacity) ProtoReflect() protoreflect.Message {
	mi := &file_transport_internet_kcp_config_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UplinkCapacity.ProtoReflect.Descriptor instead.
func (*UplinkCapacity) Descriptor() ([]byte, []int) {
	return file_transport_internet_kcp_config_proto_rawDescGZIP(), []int{2}
}

func (x *UplinkCapacity) GetValue() uint32 {
	if x != nil {
		return x.Value
	}
	return 0
}

// Downlink capacity, in MB.
type DownlinkCapacity struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Value uint32 `protobuf:"varint,1,opt,name=value,proto3" json:"value,omitempty"`
}

func (x *DownlinkCapacity) Reset() {
	*x = DownlinkCapacity{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transport_internet_kcp_config_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DownlinkCapacity) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DownlinkCapacity) ProtoMessage() {}

func (x *DownlinkCapacity) ProtoReflect() protoreflect.Message {
	mi := &file_transport_internet_kcp_config_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DownlinkCapacity.ProtoReflect.Descriptor instead.
func (*DownlinkCapacity) Descriptor() ([]byte, []int) {
	return file_transport_internet_kcp_config_proto_rawDescGZIP(), []int{3}
}

func (x *DownlinkCapacity) GetValue() uint32 {
	if x != nil {
		return x.Value
	}
	return 0
}

type WriteBuffer struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Buffer size in bytes.
	Size uint32 `protobuf:"varint,1,opt,name=size,proto3" json:"size,omitempty"`
}

func (x *WriteBuffer) Reset() {
	*x = WriteBuffer{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transport_internet_kcp_config_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *WriteBuffer) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*WriteBuffer) ProtoMessage() {}

func (x *WriteBuffer) ProtoReflect() protoreflect.Message {
	mi := &file_transport_internet_kcp_config_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use WriteBuffer.ProtoReflect.Descriptor instead.
func (*WriteBuffer) Descriptor() ([]byte, []int) {
	return file_transport_internet_kcp_config_proto_rawDescGZIP(), []int{4}
}

func (x *WriteBuffer) GetSize() uint32 {
	if x != nil {
		return x.Size
	}
	return 0
}

type ReadBuffer struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Buffer size in bytes.
	Size uint32 `protobuf:"varint,1,opt,name=size,proto3" json:"size,omitempty"`
}

func (x *ReadBuffer) Reset() {
	*x = ReadBuffer{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transport_internet_kcp_config_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ReadBuffer) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReadBuffer) ProtoMessage() {}

func (x *ReadBuffer) ProtoReflect() protoreflect.Message {
	mi := &file_transport_internet_kcp_config_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReadBuffer.ProtoReflect.Descriptor instead.
func (*ReadBuffer) Descriptor() ([]byte, []int) {
	return file_transport_internet_kcp_config_proto_rawDescGZIP(), []int{5}
}

func (x *ReadBuffer) GetSize() uint32 {
	if x != nil {
		return x.Size
	}
	return 0
}

type ConnectionReuse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Enable bool `protobuf:"varint,1,opt,name=enable,proto3" json:"enable,omitempty"`
}

func (x *ConnectionReuse) Reset() {
	*x = ConnectionReuse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transport_internet_kcp_config_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ConnectionReuse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConnectionReuse) ProtoMessage() {}

func (x *ConnectionReuse) ProtoReflect() protoreflect.Message {
	mi := &file_transport_internet_kcp_config_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConnectionReuse.ProtoReflect.Descriptor instead.
func (*ConnectionReuse) Descriptor() ([]byte, []int) {
	return file_transport_internet_kcp_config_proto_rawDescGZIP(), []int{6}
}

func (x *ConnectionReuse) GetEnable() bool {
	if x != nil {
		return x.Enable
	}
	return false
}

// Maximum Transmission Unit, in bytes.
type EncryptionSeed struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Seed string `protobuf:"bytes,1,opt,name=seed,proto3" json:"seed,omitempty"`
}

func (x *EncryptionSeed) Reset() {
	*x = EncryptionSeed{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transport_internet_kcp_config_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EncryptionSeed) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EncryptionSeed) ProtoMessage() {}

func (x *EncryptionSeed) ProtoReflect() protoreflect.Message {
	mi := &file_transport_internet_kcp_config_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EncryptionSeed.ProtoReflect.Descriptor instead.
func (*EncryptionSeed) Descriptor() ([]byte, []int) {
	return file_transport_internet_kcp_config_proto_rawDescGZIP(), []int{7}
}

func (x *EncryptionSeed) GetSeed() string {
	if x != nil {
		return x.Seed
	}
	return ""
}

type Config struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Mtu              *MTU              `protobuf:"bytes,1,opt,name=mtu,proto3" json:"mtu,omitempty"`
	Tti              *TTI              `protobuf:"bytes,2,opt,name=tti,proto3" json:"tti,omitempty"`
	UplinkCapacity   *UplinkCapacity   `protobuf:"bytes,3,opt,name=uplink_capacity,json=uplinkCapacity,proto3" json:"uplink_capacity,omitempty"`
	DownlinkCapacity *DownlinkCapacity `protobuf:"bytes,4,opt,name=downlink_capacity,json=downlinkCapacity,proto3" json:"downlink_capacity,omitempty"`
	Congestion       bool              `protobuf:"varint,5,opt,name=congestion,proto3" json:"congestion,omitempty"`
	WriteBuffer      *WriteBuffer      `protobuf:"bytes,6,opt,name=write_buffer,json=writeBuffer,proto3" json:"write_buffer,omitempty"`
	ReadBuffer       *ReadBuffer       `protobuf:"bytes,7,opt,name=read_buffer,json=readBuffer,proto3" json:"read_buffer,omitempty"`
	HeaderConfig     *anypb.Any        `protobuf:"bytes,8,opt,name=header_config,json=headerConfig,proto3" json:"header_config,omitempty"`
	Seed             *EncryptionSeed   `protobuf:"bytes,10,opt,name=seed,proto3" json:"seed,omitempty"`
}

func (x *Config) Reset() {
	*x = Config{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transport_internet_kcp_config_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Config) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Config) ProtoMessage() {}

func (x *Config) ProtoReflect() protoreflect.Message {
	mi := &file_transport_internet_kcp_config_proto_msgTypes[8]
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
	return file_transport_internet_kcp_config_proto_rawDescGZIP(), []int{8}
}

func (x *Config) GetMtu() *MTU {
	if x != nil {
		return x.Mtu
	}
	return nil
}

func (x *Config) GetTti() *TTI {
	if x != nil {
		return x.Tti
	}
	return nil
}

func (x *Config) GetUplinkCapacity() *UplinkCapacity {
	if x != nil {
		return x.UplinkCapacity
	}
	return nil
}

func (x *Config) GetDownlinkCapacity() *DownlinkCapacity {
	if x != nil {
		return x.DownlinkCapacity
	}
	return nil
}

func (x *Config) GetCongestion() bool {
	if x != nil {
		return x.Congestion
	}
	return false
}

func (x *Config) GetWriteBuffer() *WriteBuffer {
	if x != nil {
		return x.WriteBuffer
	}
	return nil
}

func (x *Config) GetReadBuffer() *ReadBuffer {
	if x != nil {
		return x.ReadBuffer
	}
	return nil
}

func (x *Config) GetHeaderConfig() *anypb.Any {
	if x != nil {
		return x.HeaderConfig
	}
	return nil
}

func (x *Config) GetSeed() *EncryptionSeed {
	if x != nil {
		return x.Seed
	}
	return nil
}

var File_transport_internet_kcp_config_proto protoreflect.FileDescriptor

var file_transport_internet_kcp_config_proto_rawDesc = []byte{
	0x0a, 0x23, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x69, 0x6e, 0x74, 0x65,
	0x72, 0x6e, 0x65, 0x74, 0x2f, 0x6b, 0x63, 0x70, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x21, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72,
	0x65, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65,
	0x72, 0x6e, 0x65, 0x74, 0x2e, 0x6b, 0x63, 0x70, 0x1a, 0x19, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x61, 0x6e, 0x79, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x20, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x65, 0x78, 0x74, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x1b, 0x0a, 0x03, 0x4d, 0x54, 0x55, 0x12, 0x14, 0x0a, 0x05,
	0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x76, 0x61, 0x6c,
	0x75, 0x65, 0x22, 0x1b, 0x0a, 0x03, 0x54, 0x54, 0x49, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c,
	0x75, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x22,
	0x26, 0x0a, 0x0e, 0x55, 0x70, 0x6c, 0x69, 0x6e, 0x6b, 0x43, 0x61, 0x70, 0x61, 0x63, 0x69, 0x74,
	0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x22, 0x28, 0x0a, 0x10, 0x44, 0x6f, 0x77, 0x6e, 0x6c,
	0x69, 0x6e, 0x6b, 0x43, 0x61, 0x70, 0x61, 0x63, 0x69, 0x74, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76,
	0x61, 0x6c, 0x75, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x22, 0x21, 0x0a, 0x0b, 0x57, 0x72, 0x69, 0x74, 0x65, 0x42, 0x75, 0x66, 0x66, 0x65, 0x72,
	0x12, 0x12, 0x0a, 0x04, 0x73, 0x69, 0x7a, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x04,
	0x73, 0x69, 0x7a, 0x65, 0x22, 0x20, 0x0a, 0x0a, 0x52, 0x65, 0x61, 0x64, 0x42, 0x75, 0x66, 0x66,
	0x65, 0x72, 0x12, 0x12, 0x0a, 0x04, 0x73, 0x69, 0x7a, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x04, 0x73, 0x69, 0x7a, 0x65, 0x22, 0x29, 0x0a, 0x0f, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63,
	0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x75, 0x73, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x65, 0x6e, 0x61,
	0x62, 0x6c, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x06, 0x65, 0x6e, 0x61, 0x62, 0x6c,
	0x65, 0x22, 0x24, 0x0a, 0x0e, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x53,
	0x65, 0x65, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x73, 0x65, 0x65, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x04, 0x73, 0x65, 0x65, 0x64, 0x22, 0xa7, 0x05, 0x0a, 0x06, 0x43, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x12, 0x38, 0x0a, 0x03, 0x6d, 0x74, 0x75, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x26, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x74, 0x72, 0x61,
	0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2e,
	0x6b, 0x63, 0x70, 0x2e, 0x4d, 0x54, 0x55, 0x52, 0x03, 0x6d, 0x74, 0x75, 0x12, 0x38, 0x0a, 0x03,
	0x74, 0x74, 0x69, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x26, 0x2e, 0x76, 0x32, 0x72, 0x61,
	0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74,
	0x2e, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2e, 0x6b, 0x63, 0x70, 0x2e, 0x54, 0x54,
	0x49, 0x52, 0x03, 0x74, 0x74, 0x69, 0x12, 0x5a, 0x0a, 0x0f, 0x75, 0x70, 0x6c, 0x69, 0x6e, 0x6b,
	0x5f, 0x63, 0x61, 0x70, 0x61, 0x63, 0x69, 0x74, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x31, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x74, 0x72, 0x61,
	0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2e,
	0x6b, 0x63, 0x70, 0x2e, 0x55, 0x70, 0x6c, 0x69, 0x6e, 0x6b, 0x43, 0x61, 0x70, 0x61, 0x63, 0x69,
	0x74, 0x79, 0x52, 0x0e, 0x75, 0x70, 0x6c, 0x69, 0x6e, 0x6b, 0x43, 0x61, 0x70, 0x61, 0x63, 0x69,
	0x74, 0x79, 0x12, 0x60, 0x0a, 0x11, 0x64, 0x6f, 0x77, 0x6e, 0x6c, 0x69, 0x6e, 0x6b, 0x5f, 0x63,
	0x61, 0x70, 0x61, 0x63, 0x69, 0x74, 0x79, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x33, 0x2e,
	0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73,
	0x70, 0x6f, 0x72, 0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2e, 0x6b, 0x63,
	0x70, 0x2e, 0x44, 0x6f, 0x77, 0x6e, 0x6c, 0x69, 0x6e, 0x6b, 0x43, 0x61, 0x70, 0x61, 0x63, 0x69,
	0x74, 0x79, 0x52, 0x10, 0x64, 0x6f, 0x77, 0x6e, 0x6c, 0x69, 0x6e, 0x6b, 0x43, 0x61, 0x70, 0x61,
	0x63, 0x69, 0x74, 0x79, 0x12, 0x1e, 0x0a, 0x0a, 0x63, 0x6f, 0x6e, 0x67, 0x65, 0x73, 0x74, 0x69,
	0x6f, 0x6e, 0x18, 0x05, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0a, 0x63, 0x6f, 0x6e, 0x67, 0x65, 0x73,
	0x74, 0x69, 0x6f, 0x6e, 0x12, 0x51, 0x0a, 0x0c, 0x77, 0x72, 0x69, 0x74, 0x65, 0x5f, 0x62, 0x75,
	0x66, 0x66, 0x65, 0x72, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2e, 0x2e, 0x76, 0x32, 0x72,
	0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72,
	0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2e, 0x6b, 0x63, 0x70, 0x2e, 0x57,
	0x72, 0x69, 0x74, 0x65, 0x42, 0x75, 0x66, 0x66, 0x65, 0x72, 0x52, 0x0b, 0x77, 0x72, 0x69, 0x74,
	0x65, 0x42, 0x75, 0x66, 0x66, 0x65, 0x72, 0x12, 0x4e, 0x0a, 0x0b, 0x72, 0x65, 0x61, 0x64, 0x5f,
	0x62, 0x75, 0x66, 0x66, 0x65, 0x72, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2d, 0x2e, 0x76,
	0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70,
	0x6f, 0x72, 0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2e, 0x6b, 0x63, 0x70,
	0x2e, 0x52, 0x65, 0x61, 0x64, 0x42, 0x75, 0x66, 0x66, 0x65, 0x72, 0x52, 0x0a, 0x72, 0x65, 0x61,
	0x64, 0x42, 0x75, 0x66, 0x66, 0x65, 0x72, 0x12, 0x39, 0x0a, 0x0d, 0x68, 0x65, 0x61, 0x64, 0x65,
	0x72, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x41, 0x6e, 0x79, 0x52, 0x0c, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x43, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x12, 0x45, 0x0a, 0x04, 0x73, 0x65, 0x65, 0x64, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x31, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x74, 0x72,
	0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74,
	0x2e, 0x6b, 0x63, 0x70, 0x2e, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x53,
	0x65, 0x65, 0x64, 0x52, 0x04, 0x73, 0x65, 0x65, 0x64, 0x3a, 0x20, 0x82, 0xb5, 0x18, 0x1c, 0x0a,
	0x09, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x12, 0x03, 0x6b, 0x63, 0x70, 0x8a,
	0xff, 0x29, 0x04, 0x6d, 0x6b, 0x63, 0x70, 0x90, 0xff, 0x29, 0x01, 0x4a, 0x04, 0x08, 0x09, 0x10,
	0x0a, 0x42, 0x84, 0x01, 0x0a, 0x25, 0x63, 0x6f, 0x6d, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e,
	0x63, 0x6f, 0x72, 0x65, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x69,
	0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2e, 0x6b, 0x63, 0x70, 0x50, 0x01, 0x5a, 0x35, 0x67,
	0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x76, 0x32, 0x66, 0x6c, 0x79, 0x2f,
	0x76, 0x32, 0x72, 0x61, 0x79, 0x2d, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x76, 0x35, 0x2f, 0x74, 0x72,
	0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74,
	0x2f, 0x6b, 0x63, 0x70, 0xaa, 0x02, 0x21, 0x56, 0x32, 0x52, 0x61, 0x79, 0x2e, 0x43, 0x6f, 0x72,
	0x65, 0x2e, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x49, 0x6e, 0x74, 0x65,
	0x72, 0x6e, 0x65, 0x74, 0x2e, 0x4b, 0x63, 0x70, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_transport_internet_kcp_config_proto_rawDescOnce sync.Once
	file_transport_internet_kcp_config_proto_rawDescData = file_transport_internet_kcp_config_proto_rawDesc
)

func file_transport_internet_kcp_config_proto_rawDescGZIP() []byte {
	file_transport_internet_kcp_config_proto_rawDescOnce.Do(func() {
		file_transport_internet_kcp_config_proto_rawDescData = protoimpl.X.CompressGZIP(file_transport_internet_kcp_config_proto_rawDescData)
	})
	return file_transport_internet_kcp_config_proto_rawDescData
}

var file_transport_internet_kcp_config_proto_msgTypes = make([]protoimpl.MessageInfo, 9)
var file_transport_internet_kcp_config_proto_goTypes = []any{
	(*MTU)(nil),              // 0: v2ray.core.transport.internet.kcp.MTU
	(*TTI)(nil),              // 1: v2ray.core.transport.internet.kcp.TTI
	(*UplinkCapacity)(nil),   // 2: v2ray.core.transport.internet.kcp.UplinkCapacity
	(*DownlinkCapacity)(nil), // 3: v2ray.core.transport.internet.kcp.DownlinkCapacity
	(*WriteBuffer)(nil),      // 4: v2ray.core.transport.internet.kcp.WriteBuffer
	(*ReadBuffer)(nil),       // 5: v2ray.core.transport.internet.kcp.ReadBuffer
	(*ConnectionReuse)(nil),  // 6: v2ray.core.transport.internet.kcp.ConnectionReuse
	(*EncryptionSeed)(nil),   // 7: v2ray.core.transport.internet.kcp.EncryptionSeed
	(*Config)(nil),           // 8: v2ray.core.transport.internet.kcp.Config
	(*anypb.Any)(nil),        // 9: google.protobuf.Any
}
var file_transport_internet_kcp_config_proto_depIdxs = []int32{
	0, // 0: v2ray.core.transport.internet.kcp.Config.mtu:type_name -> v2ray.core.transport.internet.kcp.MTU
	1, // 1: v2ray.core.transport.internet.kcp.Config.tti:type_name -> v2ray.core.transport.internet.kcp.TTI
	2, // 2: v2ray.core.transport.internet.kcp.Config.uplink_capacity:type_name -> v2ray.core.transport.internet.kcp.UplinkCapacity
	3, // 3: v2ray.core.transport.internet.kcp.Config.downlink_capacity:type_name -> v2ray.core.transport.internet.kcp.DownlinkCapacity
	4, // 4: v2ray.core.transport.internet.kcp.Config.write_buffer:type_name -> v2ray.core.transport.internet.kcp.WriteBuffer
	5, // 5: v2ray.core.transport.internet.kcp.Config.read_buffer:type_name -> v2ray.core.transport.internet.kcp.ReadBuffer
	9, // 6: v2ray.core.transport.internet.kcp.Config.header_config:type_name -> google.protobuf.Any
	7, // 7: v2ray.core.transport.internet.kcp.Config.seed:type_name -> v2ray.core.transport.internet.kcp.EncryptionSeed
	8, // [8:8] is the sub-list for method output_type
	8, // [8:8] is the sub-list for method input_type
	8, // [8:8] is the sub-list for extension type_name
	8, // [8:8] is the sub-list for extension extendee
	0, // [0:8] is the sub-list for field type_name
}

func init() { file_transport_internet_kcp_config_proto_init() }
func file_transport_internet_kcp_config_proto_init() {
	if File_transport_internet_kcp_config_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_transport_internet_kcp_config_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*MTU); i {
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
		file_transport_internet_kcp_config_proto_msgTypes[1].Exporter = func(v any, i int) any {
			switch v := v.(*TTI); i {
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
		file_transport_internet_kcp_config_proto_msgTypes[2].Exporter = func(v any, i int) any {
			switch v := v.(*UplinkCapacity); i {
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
		file_transport_internet_kcp_config_proto_msgTypes[3].Exporter = func(v any, i int) any {
			switch v := v.(*DownlinkCapacity); i {
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
		file_transport_internet_kcp_config_proto_msgTypes[4].Exporter = func(v any, i int) any {
			switch v := v.(*WriteBuffer); i {
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
		file_transport_internet_kcp_config_proto_msgTypes[5].Exporter = func(v any, i int) any {
			switch v := v.(*ReadBuffer); i {
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
		file_transport_internet_kcp_config_proto_msgTypes[6].Exporter = func(v any, i int) any {
			switch v := v.(*ConnectionReuse); i {
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
		file_transport_internet_kcp_config_proto_msgTypes[7].Exporter = func(v any, i int) any {
			switch v := v.(*EncryptionSeed); i {
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
		file_transport_internet_kcp_config_proto_msgTypes[8].Exporter = func(v any, i int) any {
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
			RawDescriptor: file_transport_internet_kcp_config_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   9,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_transport_internet_kcp_config_proto_goTypes,
		DependencyIndexes: file_transport_internet_kcp_config_proto_depIdxs,
		MessageInfos:      file_transport_internet_kcp_config_proto_msgTypes,
	}.Build()
	File_transport_internet_kcp_config_proto = out.File
	file_transport_internet_kcp_config_proto_rawDesc = nil
	file_transport_internet_kcp_config_proto_goTypes = nil
	file_transport_internet_kcp_config_proto_depIdxs = nil
}
