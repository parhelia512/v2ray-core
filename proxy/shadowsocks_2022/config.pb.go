package shadowsocks_2022

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

type ServerConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Method  string        `protobuf:"bytes,1,opt,name=method,proto3" json:"method,omitempty"`
	Key     string        `protobuf:"bytes,2,opt,name=key,proto3" json:"key,omitempty"`
	Email   string        `protobuf:"bytes,3,opt,name=email,proto3" json:"email,omitempty"`
	Level   int32         `protobuf:"varint,4,opt,name=level,proto3" json:"level,omitempty"`
	Network []net.Network `protobuf:"varint,5,rep,packed,name=network,proto3,enum=v2ray.core.common.net.Network" json:"network,omitempty"`
}

func (x *ServerConfig) Reset() {
	*x = ServerConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proxy_shadowsocks_2022_config_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ServerConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ServerConfig) ProtoMessage() {}

func (x *ServerConfig) ProtoReflect() protoreflect.Message {
	mi := &file_proxy_shadowsocks_2022_config_proto_msgTypes[0]
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
	return file_proxy_shadowsocks_2022_config_proto_rawDescGZIP(), []int{0}
}

func (x *ServerConfig) GetMethod() string {
	if x != nil {
		return x.Method
	}
	return ""
}

func (x *ServerConfig) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *ServerConfig) GetEmail() string {
	if x != nil {
		return x.Email
	}
	return ""
}

func (x *ServerConfig) GetLevel() int32 {
	if x != nil {
		return x.Level
	}
	return 0
}

func (x *ServerConfig) GetNetwork() []net.Network {
	if x != nil {
		return x.Network
	}
	return nil
}

type MultiUserServerConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Method  string        `protobuf:"bytes,1,opt,name=method,proto3" json:"method,omitempty"`
	Key     string        `protobuf:"bytes,2,opt,name=key,proto3" json:"key,omitempty"`
	Users   []*User       `protobuf:"bytes,3,rep,name=users,proto3" json:"users,omitempty"`
	Network []net.Network `protobuf:"varint,4,rep,packed,name=network,proto3,enum=v2ray.core.common.net.Network" json:"network,omitempty"`
}

func (x *MultiUserServerConfig) Reset() {
	*x = MultiUserServerConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proxy_shadowsocks_2022_config_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MultiUserServerConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MultiUserServerConfig) ProtoMessage() {}

func (x *MultiUserServerConfig) ProtoReflect() protoreflect.Message {
	mi := &file_proxy_shadowsocks_2022_config_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MultiUserServerConfig.ProtoReflect.Descriptor instead.
func (*MultiUserServerConfig) Descriptor() ([]byte, []int) {
	return file_proxy_shadowsocks_2022_config_proto_rawDescGZIP(), []int{1}
}

func (x *MultiUserServerConfig) GetMethod() string {
	if x != nil {
		return x.Method
	}
	return ""
}

func (x *MultiUserServerConfig) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *MultiUserServerConfig) GetUsers() []*User {
	if x != nil {
		return x.Users
	}
	return nil
}

func (x *MultiUserServerConfig) GetNetwork() []net.Network {
	if x != nil {
		return x.Network
	}
	return nil
}

type RelayDestination struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Key     string          `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	Address *net.IPOrDomain `protobuf:"bytes,2,opt,name=address,proto3" json:"address,omitempty"`
	Port    uint32          `protobuf:"varint,3,opt,name=port,proto3" json:"port,omitempty"`
	Email   string          `protobuf:"bytes,4,opt,name=email,proto3" json:"email,omitempty"`
	Level   int32           `protobuf:"varint,5,opt,name=level,proto3" json:"level,omitempty"`
}

func (x *RelayDestination) Reset() {
	*x = RelayDestination{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proxy_shadowsocks_2022_config_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RelayDestination) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RelayDestination) ProtoMessage() {}

func (x *RelayDestination) ProtoReflect() protoreflect.Message {
	mi := &file_proxy_shadowsocks_2022_config_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RelayDestination.ProtoReflect.Descriptor instead.
func (*RelayDestination) Descriptor() ([]byte, []int) {
	return file_proxy_shadowsocks_2022_config_proto_rawDescGZIP(), []int{2}
}

func (x *RelayDestination) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *RelayDestination) GetAddress() *net.IPOrDomain {
	if x != nil {
		return x.Address
	}
	return nil
}

func (x *RelayDestination) GetPort() uint32 {
	if x != nil {
		return x.Port
	}
	return 0
}

func (x *RelayDestination) GetEmail() string {
	if x != nil {
		return x.Email
	}
	return ""
}

func (x *RelayDestination) GetLevel() int32 {
	if x != nil {
		return x.Level
	}
	return 0
}

type RelayServerConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Method       string              `protobuf:"bytes,1,opt,name=method,proto3" json:"method,omitempty"`
	Key          string              `protobuf:"bytes,2,opt,name=key,proto3" json:"key,omitempty"`
	Destinations []*RelayDestination `protobuf:"bytes,3,rep,name=destinations,proto3" json:"destinations,omitempty"`
	Network      []net.Network       `protobuf:"varint,4,rep,packed,name=network,proto3,enum=v2ray.core.common.net.Network" json:"network,omitempty"`
}

func (x *RelayServerConfig) Reset() {
	*x = RelayServerConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proxy_shadowsocks_2022_config_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RelayServerConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RelayServerConfig) ProtoMessage() {}

func (x *RelayServerConfig) ProtoReflect() protoreflect.Message {
	mi := &file_proxy_shadowsocks_2022_config_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RelayServerConfig.ProtoReflect.Descriptor instead.
func (*RelayServerConfig) Descriptor() ([]byte, []int) {
	return file_proxy_shadowsocks_2022_config_proto_rawDescGZIP(), []int{3}
}

func (x *RelayServerConfig) GetMethod() string {
	if x != nil {
		return x.Method
	}
	return ""
}

func (x *RelayServerConfig) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *RelayServerConfig) GetDestinations() []*RelayDestination {
	if x != nil {
		return x.Destinations
	}
	return nil
}

func (x *RelayServerConfig) GetNetwork() []net.Network {
	if x != nil {
		return x.Network
	}
	return nil
}

type User struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Key   string `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	Email string `protobuf:"bytes,2,opt,name=email,proto3" json:"email,omitempty"`
	Level int32  `protobuf:"varint,3,opt,name=level,proto3" json:"level,omitempty"`
}

func (x *User) Reset() {
	*x = User{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proxy_shadowsocks_2022_config_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *User) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*User) ProtoMessage() {}

func (x *User) ProtoReflect() protoreflect.Message {
	mi := &file_proxy_shadowsocks_2022_config_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use User.ProtoReflect.Descriptor instead.
func (*User) Descriptor() ([]byte, []int) {
	return file_proxy_shadowsocks_2022_config_proto_rawDescGZIP(), []int{4}
}

func (x *User) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *User) GetEmail() string {
	if x != nil {
		return x.Email
	}
	return ""
}

func (x *User) GetLevel() int32 {
	if x != nil {
		return x.Level
	}
	return 0
}

type ClientConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Address *net.IPOrDomain `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"`
	Port    uint32          `protobuf:"varint,2,opt,name=port,proto3" json:"port,omitempty"`
	Method  string          `protobuf:"bytes,3,opt,name=method,proto3" json:"method,omitempty"`
	Key     string          `protobuf:"bytes,4,opt,name=key,proto3" json:"key,omitempty"`
}

func (x *ClientConfig) Reset() {
	*x = ClientConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proxy_shadowsocks_2022_config_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ClientConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ClientConfig) ProtoMessage() {}

func (x *ClientConfig) ProtoReflect() protoreflect.Message {
	mi := &file_proxy_shadowsocks_2022_config_proto_msgTypes[5]
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
	return file_proxy_shadowsocks_2022_config_proto_rawDescGZIP(), []int{5}
}

func (x *ClientConfig) GetAddress() *net.IPOrDomain {
	if x != nil {
		return x.Address
	}
	return nil
}

func (x *ClientConfig) GetPort() uint32 {
	if x != nil {
		return x.Port
	}
	return 0
}

func (x *ClientConfig) GetMethod() string {
	if x != nil {
		return x.Method
	}
	return ""
}

func (x *ClientConfig) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

var File_proxy_shadowsocks_2022_config_proto protoreflect.FileDescriptor

var file_proxy_shadowsocks_2022_config_proto_rawDesc = []byte{
	0x0a, 0x23, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x73, 0x68, 0x61, 0x64, 0x6f, 0x77, 0x73, 0x6f,
	0x63, 0x6b, 0x73, 0x5f, 0x32, 0x30, 0x32, 0x32, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x21, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x73, 0x68, 0x61, 0x64, 0x6f, 0x77, 0x73, 0x6f,
	0x63, 0x6b, 0x73, 0x5f, 0x32, 0x30, 0x32, 0x32, 0x1a, 0x18, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e,
	0x2f, 0x6e, 0x65, 0x74, 0x2f, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x18, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x6e, 0x65, 0x74, 0x2f, 0x61,
	0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x9e, 0x01, 0x0a,
	0x0c, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x16, 0x0a,
	0x06, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x6d,
	0x65, 0x74, 0x68, 0x6f, 0x64, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x65, 0x6d, 0x61, 0x69, 0x6c,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x65, 0x6d, 0x61, 0x69, 0x6c, 0x12, 0x14, 0x0a,
	0x05, 0x6c, 0x65, 0x76, 0x65, 0x6c, 0x18, 0x04, 0x20, 0x01, 0x28, 0x05, 0x52, 0x05, 0x6c, 0x65,
	0x76, 0x65, 0x6c, 0x12, 0x38, 0x0a, 0x07, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x18, 0x05,
	0x20, 0x03, 0x28, 0x0e, 0x32, 0x1e, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72,
	0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x6e, 0x65, 0x74, 0x2e, 0x4e, 0x65, 0x74,
	0x77, 0x6f, 0x72, 0x6b, 0x52, 0x07, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x22, 0xba, 0x01,
	0x0a, 0x15, 0x4d, 0x75, 0x6c, 0x74, 0x69, 0x55, 0x73, 0x65, 0x72, 0x53, 0x65, 0x72, 0x76, 0x65,
	0x72, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x16, 0x0a, 0x06, 0x6d, 0x65, 0x74, 0x68, 0x6f,
	0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x12,
	0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65,
	0x79, 0x12, 0x3d, 0x0a, 0x05, 0x75, 0x73, 0x65, 0x72, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x27, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x78, 0x79, 0x2e, 0x73, 0x68, 0x61, 0x64, 0x6f, 0x77, 0x73, 0x6f, 0x63, 0x6b, 0x73, 0x5f,
	0x32, 0x30, 0x32, 0x32, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x52, 0x05, 0x75, 0x73, 0x65, 0x72, 0x73,
	0x12, 0x38, 0x0a, 0x07, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x18, 0x04, 0x20, 0x03, 0x28,
	0x0e, 0x32, 0x1e, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63,
	0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x6e, 0x65, 0x74, 0x2e, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72,
	0x6b, 0x52, 0x07, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x22, 0xa1, 0x01, 0x0a, 0x10, 0x52,
	0x65, 0x6c, 0x61, 0x79, 0x44, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12,
	0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65,
	0x79, 0x12, 0x3b, 0x0a, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x21, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e,
	0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x6e, 0x65, 0x74, 0x2e, 0x49, 0x50, 0x4f, 0x72, 0x44,
	0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x52, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x12,
	0x0a, 0x04, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x04, 0x70, 0x6f,
	0x72, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x65, 0x6d, 0x61, 0x69, 0x6c, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x05, 0x65, 0x6d, 0x61, 0x69, 0x6c, 0x12, 0x14, 0x0a, 0x05, 0x6c, 0x65, 0x76, 0x65,
	0x6c, 0x18, 0x05, 0x20, 0x01, 0x28, 0x05, 0x52, 0x05, 0x6c, 0x65, 0x76, 0x65, 0x6c, 0x22, 0xd0,
	0x01, 0x0a, 0x11, 0x52, 0x65, 0x6c, 0x61, 0x79, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x43, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x12, 0x16, 0x0a, 0x06, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x12, 0x10, 0x0a, 0x03,
	0x6b, 0x65, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x57,
	0x0a, 0x0c, 0x64, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x03,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x33, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x73, 0x68, 0x61, 0x64, 0x6f, 0x77, 0x73, 0x6f,
	0x63, 0x6b, 0x73, 0x5f, 0x32, 0x30, 0x32, 0x32, 0x2e, 0x52, 0x65, 0x6c, 0x61, 0x79, 0x44, 0x65,
	0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0c, 0x64, 0x65, 0x73, 0x74, 0x69,
	0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x38, 0x0a, 0x07, 0x6e, 0x65, 0x74, 0x77, 0x6f,
	0x72, 0x6b, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0e, 0x32, 0x1e, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79,
	0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x6e, 0x65, 0x74,
	0x2e, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x52, 0x07, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72,
	0x6b, 0x22, 0x44, 0x0a, 0x04, 0x55, 0x73, 0x65, 0x72, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x65,
	0x6d, 0x61, 0x69, 0x6c, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x65, 0x6d, 0x61, 0x69,
	0x6c, 0x12, 0x14, 0x0a, 0x05, 0x6c, 0x65, 0x76, 0x65, 0x6c, 0x18, 0x03, 0x20, 0x01, 0x28, 0x05,
	0x52, 0x05, 0x6c, 0x65, 0x76, 0x65, 0x6c, 0x22, 0x89, 0x01, 0x0a, 0x0c, 0x43, 0x6c, 0x69, 0x65,
	0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x3b, 0x0a, 0x07, 0x61, 0x64, 0x64, 0x72,
	0x65, 0x73, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x21, 0x2e, 0x76, 0x32, 0x72, 0x61,
	0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x6e, 0x65,
	0x74, 0x2e, 0x49, 0x50, 0x4f, 0x72, 0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x52, 0x07, 0x61, 0x64,
	0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x12, 0x0a, 0x04, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x04, 0x70, 0x6f, 0x72, 0x74, 0x12, 0x16, 0x0a, 0x06, 0x6d, 0x65, 0x74,
	0x68, 0x6f, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x6d, 0x65, 0x74, 0x68, 0x6f,
	0x64, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03,
	0x6b, 0x65, 0x79, 0x42, 0x84, 0x01, 0x0a, 0x25, 0x63, 0x6f, 0x6d, 0x2e, 0x76, 0x32, 0x72, 0x61,
	0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x73, 0x68, 0x61,
	0x64, 0x6f, 0x77, 0x73, 0x6f, 0x63, 0x6b, 0x73, 0x5f, 0x32, 0x30, 0x32, 0x32, 0x50, 0x01, 0x5a,
	0x35, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x76, 0x32, 0x66, 0x6c,
	0x79, 0x2f, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2d, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x76, 0x34, 0x2f,
	0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x73, 0x68, 0x61, 0x64, 0x6f, 0x77, 0x73, 0x6f, 0x63, 0x6b,
	0x73, 0x5f, 0x32, 0x30, 0x32, 0x32, 0xaa, 0x02, 0x21, 0x56, 0x32, 0x52, 0x61, 0x79, 0x2e, 0x43,
	0x6f, 0x72, 0x65, 0x2e, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x53, 0x68, 0x61, 0x64, 0x6f, 0x77,
	0x73, 0x6f, 0x63, 0x6b, 0x73, 0x5f, 0x32, 0x30, 0x32, 0x32, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_proxy_shadowsocks_2022_config_proto_rawDescOnce sync.Once
	file_proxy_shadowsocks_2022_config_proto_rawDescData = file_proxy_shadowsocks_2022_config_proto_rawDesc
)

func file_proxy_shadowsocks_2022_config_proto_rawDescGZIP() []byte {
	file_proxy_shadowsocks_2022_config_proto_rawDescOnce.Do(func() {
		file_proxy_shadowsocks_2022_config_proto_rawDescData = protoimpl.X.CompressGZIP(file_proxy_shadowsocks_2022_config_proto_rawDescData)
	})
	return file_proxy_shadowsocks_2022_config_proto_rawDescData
}

var file_proxy_shadowsocks_2022_config_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_proxy_shadowsocks_2022_config_proto_goTypes = []any{
	(*ServerConfig)(nil),          // 0: v2ray.core.proxy.shadowsocks_2022.ServerConfig
	(*MultiUserServerConfig)(nil), // 1: v2ray.core.proxy.shadowsocks_2022.MultiUserServerConfig
	(*RelayDestination)(nil),      // 2: v2ray.core.proxy.shadowsocks_2022.RelayDestination
	(*RelayServerConfig)(nil),     // 3: v2ray.core.proxy.shadowsocks_2022.RelayServerConfig
	(*User)(nil),                  // 4: v2ray.core.proxy.shadowsocks_2022.User
	(*ClientConfig)(nil),          // 5: v2ray.core.proxy.shadowsocks_2022.ClientConfig
	(net.Network)(0),              // 6: v2ray.core.common.net.Network
	(*net.IPOrDomain)(nil),        // 7: v2ray.core.common.net.IPOrDomain
}
var file_proxy_shadowsocks_2022_config_proto_depIdxs = []int32{
	6, // 0: v2ray.core.proxy.shadowsocks_2022.ServerConfig.network:type_name -> v2ray.core.common.net.Network
	4, // 1: v2ray.core.proxy.shadowsocks_2022.MultiUserServerConfig.users:type_name -> v2ray.core.proxy.shadowsocks_2022.User
	6, // 2: v2ray.core.proxy.shadowsocks_2022.MultiUserServerConfig.network:type_name -> v2ray.core.common.net.Network
	7, // 3: v2ray.core.proxy.shadowsocks_2022.RelayDestination.address:type_name -> v2ray.core.common.net.IPOrDomain
	2, // 4: v2ray.core.proxy.shadowsocks_2022.RelayServerConfig.destinations:type_name -> v2ray.core.proxy.shadowsocks_2022.RelayDestination
	6, // 5: v2ray.core.proxy.shadowsocks_2022.RelayServerConfig.network:type_name -> v2ray.core.common.net.Network
	7, // 6: v2ray.core.proxy.shadowsocks_2022.ClientConfig.address:type_name -> v2ray.core.common.net.IPOrDomain
	7, // [7:7] is the sub-list for method output_type
	7, // [7:7] is the sub-list for method input_type
	7, // [7:7] is the sub-list for extension type_name
	7, // [7:7] is the sub-list for extension extendee
	0, // [0:7] is the sub-list for field type_name
}

func init() { file_proxy_shadowsocks_2022_config_proto_init() }
func file_proxy_shadowsocks_2022_config_proto_init() {
	if File_proxy_shadowsocks_2022_config_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_proxy_shadowsocks_2022_config_proto_msgTypes[0].Exporter = func(v any, i int) any {
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
		file_proxy_shadowsocks_2022_config_proto_msgTypes[1].Exporter = func(v any, i int) any {
			switch v := v.(*MultiUserServerConfig); i {
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
		file_proxy_shadowsocks_2022_config_proto_msgTypes[2].Exporter = func(v any, i int) any {
			switch v := v.(*RelayDestination); i {
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
		file_proxy_shadowsocks_2022_config_proto_msgTypes[3].Exporter = func(v any, i int) any {
			switch v := v.(*RelayServerConfig); i {
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
		file_proxy_shadowsocks_2022_config_proto_msgTypes[4].Exporter = func(v any, i int) any {
			switch v := v.(*User); i {
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
		file_proxy_shadowsocks_2022_config_proto_msgTypes[5].Exporter = func(v any, i int) any {
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
			RawDescriptor: file_proxy_shadowsocks_2022_config_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_proxy_shadowsocks_2022_config_proto_goTypes,
		DependencyIndexes: file_proxy_shadowsocks_2022_config_proto_depIdxs,
		MessageInfos:      file_proxy_shadowsocks_2022_config_proto_msgTypes,
	}.Build()
	File_proxy_shadowsocks_2022_config_proto = out.File
	file_proxy_shadowsocks_2022_config_proto_rawDesc = nil
	file_proxy_shadowsocks_2022_config_proto_goTypes = nil
	file_proxy_shadowsocks_2022_config_proto_depIdxs = nil
}
