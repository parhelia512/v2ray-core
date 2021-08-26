package observatory

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

type ObservationResult struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Status []*OutboundStatus `protobuf:"bytes,1,rep,name=status,proto3" json:"status,omitempty"`
}

func (x *ObservationResult) Reset() {
	*x = ObservationResult{}
	if protoimpl.UnsafeEnabled {
		mi := &file_app_observatory_config_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ObservationResult) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ObservationResult) ProtoMessage() {}

func (x *ObservationResult) ProtoReflect() protoreflect.Message {
	mi := &file_app_observatory_config_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ObservationResult.ProtoReflect.Descriptor instead.
func (*ObservationResult) Descriptor() ([]byte, []int) {
	return file_app_observatory_config_proto_rawDescGZIP(), []int{0}
}

func (x *ObservationResult) GetStatus() []*OutboundStatus {
	if x != nil {
		return x.Status
	}
	return nil
}

type HealthPingMeasurementResult struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	All       int64 `protobuf:"varint,1,opt,name=all,proto3" json:"all,omitempty"`
	Fail      int64 `protobuf:"varint,2,opt,name=fail,proto3" json:"fail,omitempty"`
	Deviation int64 `protobuf:"varint,3,opt,name=deviation,proto3" json:"deviation,omitempty"`
	Average   int64 `protobuf:"varint,4,opt,name=average,proto3" json:"average,omitempty"`
	Max       int64 `protobuf:"varint,5,opt,name=max,proto3" json:"max,omitempty"`
	Min       int64 `protobuf:"varint,6,opt,name=min,proto3" json:"min,omitempty"`
}

func (x *HealthPingMeasurementResult) Reset() {
	*x = HealthPingMeasurementResult{}
	if protoimpl.UnsafeEnabled {
		mi := &file_app_observatory_config_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HealthPingMeasurementResult) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HealthPingMeasurementResult) ProtoMessage() {}

func (x *HealthPingMeasurementResult) ProtoReflect() protoreflect.Message {
	mi := &file_app_observatory_config_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HealthPingMeasurementResult.ProtoReflect.Descriptor instead.
func (*HealthPingMeasurementResult) Descriptor() ([]byte, []int) {
	return file_app_observatory_config_proto_rawDescGZIP(), []int{1}
}

func (x *HealthPingMeasurementResult) GetAll() int64 {
	if x != nil {
		return x.All
	}
	return 0
}

func (x *HealthPingMeasurementResult) GetFail() int64 {
	if x != nil {
		return x.Fail
	}
	return 0
}

func (x *HealthPingMeasurementResult) GetDeviation() int64 {
	if x != nil {
		return x.Deviation
	}
	return 0
}

func (x *HealthPingMeasurementResult) GetAverage() int64 {
	if x != nil {
		return x.Average
	}
	return 0
}

func (x *HealthPingMeasurementResult) GetMax() int64 {
	if x != nil {
		return x.Max
	}
	return 0
}

func (x *HealthPingMeasurementResult) GetMin() int64 {
	if x != nil {
		return x.Min
	}
	return 0
}

type OutboundStatus struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// @Document Whether this outbound is usable
	// @Restriction ReadOnlyForUser
	Alive bool `protobuf:"varint,1,opt,name=alive,proto3" json:"alive,omitempty"`
	// @Document The time for probe request to finish.
	// @Type time.ms
	// @Restriction ReadOnlyForUser
	Delay int64 `protobuf:"varint,2,opt,name=delay,proto3" json:"delay,omitempty"`
	// @Document The last error caused this outbound failed to relay probe request
	// @Restriction NotMachineReadable
	LastErrorReason string `protobuf:"bytes,3,opt,name=last_error_reason,json=lastErrorReason,proto3" json:"last_error_reason,omitempty"`
	// @Document The outbound tag for this Server
	// @Type id.outboundTag
	OutboundTag string `protobuf:"bytes,4,opt,name=outbound_tag,json=outboundTag,proto3" json:"outbound_tag,omitempty"`
	// @Document The time this outbound is known to be alive
	// @Type id.outboundTag
	LastSeenTime int64 `protobuf:"varint,5,opt,name=last_seen_time,json=lastSeenTime,proto3" json:"last_seen_time,omitempty"`
	// @Document The time this outbound is tried
	// @Type id.outboundTag
	LastTryTime int64                        `protobuf:"varint,6,opt,name=last_try_time,json=lastTryTime,proto3" json:"last_try_time,omitempty"`
	HealthPing  *HealthPingMeasurementResult `protobuf:"bytes,7,opt,name=health_ping,json=healthPing,proto3" json:"health_ping,omitempty"`
}

func (x *OutboundStatus) Reset() {
	*x = OutboundStatus{}
	if protoimpl.UnsafeEnabled {
		mi := &file_app_observatory_config_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *OutboundStatus) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*OutboundStatus) ProtoMessage() {}

func (x *OutboundStatus) ProtoReflect() protoreflect.Message {
	mi := &file_app_observatory_config_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use OutboundStatus.ProtoReflect.Descriptor instead.
func (*OutboundStatus) Descriptor() ([]byte, []int) {
	return file_app_observatory_config_proto_rawDescGZIP(), []int{2}
}

func (x *OutboundStatus) GetAlive() bool {
	if x != nil {
		return x.Alive
	}
	return false
}

func (x *OutboundStatus) GetDelay() int64 {
	if x != nil {
		return x.Delay
	}
	return 0
}

func (x *OutboundStatus) GetLastErrorReason() string {
	if x != nil {
		return x.LastErrorReason
	}
	return ""
}

func (x *OutboundStatus) GetOutboundTag() string {
	if x != nil {
		return x.OutboundTag
	}
	return ""
}

func (x *OutboundStatus) GetLastSeenTime() int64 {
	if x != nil {
		return x.LastSeenTime
	}
	return 0
}

func (x *OutboundStatus) GetLastTryTime() int64 {
	if x != nil {
		return x.LastTryTime
	}
	return 0
}

func (x *OutboundStatus) GetHealthPing() *HealthPingMeasurementResult {
	if x != nil {
		return x.HealthPing
	}
	return nil
}

type ProbeResult struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// @Document Whether this outbound is usable
	// @Restriction ReadOnlyForUser
	Alive bool `protobuf:"varint,1,opt,name=alive,proto3" json:"alive,omitempty"`
	// @Document The time for probe request to finish.
	// @Type time.ms
	// @Restriction ReadOnlyForUser
	Delay int64 `protobuf:"varint,2,opt,name=delay,proto3" json:"delay,omitempty"`
	// @Document The error caused this outbound failed to relay probe request
	// @Restriction NotMachineReadable
	LastErrorReason string `protobuf:"bytes,3,opt,name=last_error_reason,json=lastErrorReason,proto3" json:"last_error_reason,omitempty"`
}

func (x *ProbeResult) Reset() {
	*x = ProbeResult{}
	if protoimpl.UnsafeEnabled {
		mi := &file_app_observatory_config_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ProbeResult) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ProbeResult) ProtoMessage() {}

func (x *ProbeResult) ProtoReflect() protoreflect.Message {
	mi := &file_app_observatory_config_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ProbeResult.ProtoReflect.Descriptor instead.
func (*ProbeResult) Descriptor() ([]byte, []int) {
	return file_app_observatory_config_proto_rawDescGZIP(), []int{3}
}

func (x *ProbeResult) GetAlive() bool {
	if x != nil {
		return x.Alive
	}
	return false
}

func (x *ProbeResult) GetDelay() int64 {
	if x != nil {
		return x.Delay
	}
	return 0
}

func (x *ProbeResult) GetLastErrorReason() string {
	if x != nil {
		return x.LastErrorReason
	}
	return ""
}

type Intensity struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// @Document The time interval for a probe request in ms.
	// @Type time.ms
	ProbeInterval uint32 `protobuf:"varint,1,opt,name=probe_interval,json=probeInterval,proto3" json:"probe_interval,omitempty"`
}

func (x *Intensity) Reset() {
	*x = Intensity{}
	if protoimpl.UnsafeEnabled {
		mi := &file_app_observatory_config_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Intensity) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Intensity) ProtoMessage() {}

func (x *Intensity) ProtoReflect() protoreflect.Message {
	mi := &file_app_observatory_config_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Intensity.ProtoReflect.Descriptor instead.
func (*Intensity) Descriptor() ([]byte, []int) {
	return file_app_observatory_config_proto_rawDescGZIP(), []int{4}
}

func (x *Intensity) GetProbeInterval() uint32 {
	if x != nil {
		return x.ProbeInterval
	}
	return 0
}

type Config struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// @Document The selectors for outbound under observation
	SubjectSelector   []string `protobuf:"bytes,2,rep,name=subject_selector,json=subjectSelector,proto3" json:"subject_selector,omitempty"`
	ProbeUrl          string   `protobuf:"bytes,3,opt,name=probe_url,json=probeUrl,proto3" json:"probe_url,omitempty"`
	ProbeInterval     int64    `protobuf:"varint,4,opt,name=probe_interval,json=probeInterval,proto3" json:"probe_interval,omitempty"`
	EnableConcurrency bool     `protobuf:"varint,5,opt,name=enable_concurrency,json=enableConcurrency,proto3" json:"enable_concurrency,omitempty"`
}

func (x *Config) Reset() {
	*x = Config{}
	if protoimpl.UnsafeEnabled {
		mi := &file_app_observatory_config_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Config) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Config) ProtoMessage() {}

func (x *Config) ProtoReflect() protoreflect.Message {
	mi := &file_app_observatory_config_proto_msgTypes[5]
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
	return file_app_observatory_config_proto_rawDescGZIP(), []int{5}
}

func (x *Config) GetSubjectSelector() []string {
	if x != nil {
		return x.SubjectSelector
	}
	return nil
}

func (x *Config) GetProbeUrl() string {
	if x != nil {
		return x.ProbeUrl
	}
	return ""
}

func (x *Config) GetProbeInterval() int64 {
	if x != nil {
		return x.ProbeInterval
	}
	return 0
}

func (x *Config) GetEnableConcurrency() bool {
	if x != nil {
		return x.EnableConcurrency
	}
	return false
}

var File_app_observatory_config_proto protoreflect.FileDescriptor

var file_app_observatory_config_proto_rawDesc = []byte{
	0x0a, 0x1c, 0x61, 0x70, 0x70, 0x2f, 0x6f, 0x62, 0x73, 0x65, 0x72, 0x76, 0x61, 0x74, 0x6f, 0x72,
	0x79, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1a,
	0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x61, 0x70, 0x70, 0x2e, 0x6f,
	0x62, 0x73, 0x65, 0x72, 0x76, 0x61, 0x74, 0x6f, 0x72, 0x79, 0x1a, 0x20, 0x63, 0x6f, 0x6d, 0x6d,
	0x6f, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x65, 0x78, 0x74, 0x2f, 0x65, 0x78, 0x74, 0x65,
	0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x57, 0x0a, 0x11,
	0x4f, 0x62, 0x73, 0x65, 0x72, 0x76, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x75, 0x6c,
	0x74, 0x12, 0x42, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28,
	0x0b, 0x32, 0x2a, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x61,
	0x70, 0x70, 0x2e, 0x6f, 0x62, 0x73, 0x65, 0x72, 0x76, 0x61, 0x74, 0x6f, 0x72, 0x79, 0x2e, 0x4f,
	0x75, 0x74, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x06, 0x73,
	0x74, 0x61, 0x74, 0x75, 0x73, 0x22, 0x9f, 0x01, 0x0a, 0x1b, 0x48, 0x65, 0x61, 0x6c, 0x74, 0x68,
	0x50, 0x69, 0x6e, 0x67, 0x4d, 0x65, 0x61, 0x73, 0x75, 0x72, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x52,
	0x65, 0x73, 0x75, 0x6c, 0x74, 0x12, 0x10, 0x0a, 0x03, 0x61, 0x6c, 0x6c, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x03, 0x52, 0x03, 0x61, 0x6c, 0x6c, 0x12, 0x12, 0x0a, 0x04, 0x66, 0x61, 0x69, 0x6c, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x03, 0x52, 0x04, 0x66, 0x61, 0x69, 0x6c, 0x12, 0x1c, 0x0a, 0x09, 0x64,
	0x65, 0x76, 0x69, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x03, 0x52, 0x09,
	0x64, 0x65, 0x76, 0x69, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x18, 0x0a, 0x07, 0x61, 0x76, 0x65,
	0x72, 0x61, 0x67, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x03, 0x52, 0x07, 0x61, 0x76, 0x65, 0x72,
	0x61, 0x67, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x6d, 0x61, 0x78, 0x18, 0x05, 0x20, 0x01, 0x28, 0x03,
	0x52, 0x03, 0x6d, 0x61, 0x78, 0x12, 0x10, 0x0a, 0x03, 0x6d, 0x69, 0x6e, 0x18, 0x06, 0x20, 0x01,
	0x28, 0x03, 0x52, 0x03, 0x6d, 0x69, 0x6e, 0x22, 0xaf, 0x02, 0x0a, 0x0e, 0x4f, 0x75, 0x74, 0x62,
	0x6f, 0x75, 0x6e, 0x64, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x14, 0x0a, 0x05, 0x61, 0x6c,
	0x69, 0x76, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x05, 0x61, 0x6c, 0x69, 0x76, 0x65,
	0x12, 0x14, 0x0a, 0x05, 0x64, 0x65, 0x6c, 0x61, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x03, 0x52,
	0x05, 0x64, 0x65, 0x6c, 0x61, 0x79, 0x12, 0x2a, 0x0a, 0x11, 0x6c, 0x61, 0x73, 0x74, 0x5f, 0x65,
	0x72, 0x72, 0x6f, 0x72, 0x5f, 0x72, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x0f, 0x6c, 0x61, 0x73, 0x74, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x52, 0x65, 0x61, 0x73,
	0x6f, 0x6e, 0x12, 0x21, 0x0a, 0x0c, 0x6f, 0x75, 0x74, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x5f, 0x74,
	0x61, 0x67, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x6f, 0x75, 0x74, 0x62, 0x6f, 0x75,
	0x6e, 0x64, 0x54, 0x61, 0x67, 0x12, 0x24, 0x0a, 0x0e, 0x6c, 0x61, 0x73, 0x74, 0x5f, 0x73, 0x65,
	0x65, 0x6e, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0c, 0x6c,
	0x61, 0x73, 0x74, 0x53, 0x65, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x22, 0x0a, 0x0d, 0x6c,
	0x61, 0x73, 0x74, 0x5f, 0x74, 0x72, 0x79, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x06, 0x20, 0x01,
	0x28, 0x03, 0x52, 0x0b, 0x6c, 0x61, 0x73, 0x74, 0x54, 0x72, 0x79, 0x54, 0x69, 0x6d, 0x65, 0x12,
	0x58, 0x0a, 0x0b, 0x68, 0x65, 0x61, 0x6c, 0x74, 0x68, 0x5f, 0x70, 0x69, 0x6e, 0x67, 0x18, 0x07,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x37, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72,
	0x65, 0x2e, 0x61, 0x70, 0x70, 0x2e, 0x6f, 0x62, 0x73, 0x65, 0x72, 0x76, 0x61, 0x74, 0x6f, 0x72,
	0x79, 0x2e, 0x48, 0x65, 0x61, 0x6c, 0x74, 0x68, 0x50, 0x69, 0x6e, 0x67, 0x4d, 0x65, 0x61, 0x73,
	0x75, 0x72, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x52, 0x0a, 0x68,
	0x65, 0x61, 0x6c, 0x74, 0x68, 0x50, 0x69, 0x6e, 0x67, 0x22, 0x65, 0x0a, 0x0b, 0x50, 0x72, 0x6f,
	0x62, 0x65, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x61, 0x6c, 0x69, 0x76,
	0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x05, 0x61, 0x6c, 0x69, 0x76, 0x65, 0x12, 0x14,
	0x0a, 0x05, 0x64, 0x65, 0x6c, 0x61, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x03, 0x52, 0x05, 0x64,
	0x65, 0x6c, 0x61, 0x79, 0x12, 0x2a, 0x0a, 0x11, 0x6c, 0x61, 0x73, 0x74, 0x5f, 0x65, 0x72, 0x72,
	0x6f, 0x72, 0x5f, 0x72, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x0f, 0x6c, 0x61, 0x73, 0x74, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e,
	0x22, 0x32, 0x0a, 0x09, 0x49, 0x6e, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x74, 0x79, 0x12, 0x25, 0x0a,
	0x0e, 0x70, 0x72, 0x6f, 0x62, 0x65, 0x5f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x76, 0x61, 0x6c, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0d, 0x70, 0x72, 0x6f, 0x62, 0x65, 0x49, 0x6e, 0x74, 0x65,
	0x72, 0x76, 0x61, 0x6c, 0x22, 0xd0, 0x01, 0x0a, 0x06, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12,
	0x29, 0x0a, 0x10, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x73, 0x65, 0x6c, 0x65, 0x63,
	0x74, 0x6f, 0x72, 0x18, 0x02, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0f, 0x73, 0x75, 0x62, 0x6a, 0x65,
	0x63, 0x74, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x12, 0x1b, 0x0a, 0x09, 0x70, 0x72,
	0x6f, 0x62, 0x65, 0x5f, 0x75, 0x72, 0x6c, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70,
	0x72, 0x6f, 0x62, 0x65, 0x55, 0x72, 0x6c, 0x12, 0x25, 0x0a, 0x0e, 0x70, 0x72, 0x6f, 0x62, 0x65,
	0x5f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x76, 0x61, 0x6c, 0x18, 0x04, 0x20, 0x01, 0x28, 0x03, 0x52,
	0x0d, 0x70, 0x72, 0x6f, 0x62, 0x65, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x76, 0x61, 0x6c, 0x12, 0x2d,
	0x0a, 0x12, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x5f, 0x63, 0x6f, 0x6e, 0x63, 0x75, 0x72, 0x72,
	0x65, 0x6e, 0x63, 0x79, 0x18, 0x05, 0x20, 0x01, 0x28, 0x08, 0x52, 0x11, 0x65, 0x6e, 0x61, 0x62,
	0x6c, 0x65, 0x43, 0x6f, 0x6e, 0x63, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x63, 0x79, 0x3a, 0x28, 0x82,
	0xb5, 0x18, 0x09, 0x0a, 0x07, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x82, 0xb5, 0x18, 0x17,
	0x12, 0x15, 0x62, 0x61, 0x63, 0x6b, 0x67, 0x72, 0x6f, 0x75, 0x6e, 0x64, 0x4f, 0x62, 0x73, 0x65,
	0x72, 0x76, 0x61, 0x74, 0x6f, 0x72, 0x79, 0x42, 0x6f, 0x0a, 0x1e, 0x63, 0x6f, 0x6d, 0x2e, 0x76,
	0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x61, 0x70, 0x70, 0x2e, 0x6f, 0x62,
	0x73, 0x65, 0x72, 0x76, 0x61, 0x74, 0x6f, 0x72, 0x79, 0x50, 0x01, 0x5a, 0x2e, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x76, 0x32, 0x66, 0x6c, 0x79, 0x2f, 0x76, 0x32,
	0x72, 0x61, 0x79, 0x2d, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x76, 0x35, 0x2f, 0x61, 0x70, 0x70, 0x2f,
	0x6f, 0x62, 0x73, 0x65, 0x72, 0x76, 0x61, 0x74, 0x6f, 0x72, 0x79, 0xaa, 0x02, 0x1a, 0x56, 0x32,
	0x52, 0x61, 0x79, 0x2e, 0x43, 0x6f, 0x72, 0x65, 0x2e, 0x41, 0x70, 0x70, 0x2e, 0x4f, 0x62, 0x73,
	0x65, 0x72, 0x76, 0x61, 0x74, 0x6f, 0x72, 0x79, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_app_observatory_config_proto_rawDescOnce sync.Once
	file_app_observatory_config_proto_rawDescData = file_app_observatory_config_proto_rawDesc
)

func file_app_observatory_config_proto_rawDescGZIP() []byte {
	file_app_observatory_config_proto_rawDescOnce.Do(func() {
		file_app_observatory_config_proto_rawDescData = protoimpl.X.CompressGZIP(file_app_observatory_config_proto_rawDescData)
	})
	return file_app_observatory_config_proto_rawDescData
}

var file_app_observatory_config_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_app_observatory_config_proto_goTypes = []interface{}{
	(*ObservationResult)(nil),           // 0: v2ray.core.app.observatory.ObservationResult
	(*HealthPingMeasurementResult)(nil), // 1: v2ray.core.app.observatory.HealthPingMeasurementResult
	(*OutboundStatus)(nil),              // 2: v2ray.core.app.observatory.OutboundStatus
	(*ProbeResult)(nil),                 // 3: v2ray.core.app.observatory.ProbeResult
	(*Intensity)(nil),                   // 4: v2ray.core.app.observatory.Intensity
	(*Config)(nil),                      // 5: v2ray.core.app.observatory.Config
}
var file_app_observatory_config_proto_depIdxs = []int32{
	2, // 0: v2ray.core.app.observatory.ObservationResult.status:type_name -> v2ray.core.app.observatory.OutboundStatus
	1, // 1: v2ray.core.app.observatory.OutboundStatus.health_ping:type_name -> v2ray.core.app.observatory.HealthPingMeasurementResult
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_app_observatory_config_proto_init() }
func file_app_observatory_config_proto_init() {
	if File_app_observatory_config_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_app_observatory_config_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ObservationResult); i {
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
		file_app_observatory_config_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HealthPingMeasurementResult); i {
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
		file_app_observatory_config_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*OutboundStatus); i {
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
		file_app_observatory_config_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ProbeResult); i {
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
		file_app_observatory_config_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Intensity); i {
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
		file_app_observatory_config_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
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
			RawDescriptor: file_app_observatory_config_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_app_observatory_config_proto_goTypes,
		DependencyIndexes: file_app_observatory_config_proto_depIdxs,
		MessageInfos:      file_app_observatory_config_proto_msgTypes,
	}.Build()
	File_app_observatory_config_proto = out.File
	file_app_observatory_config_proto_rawDesc = nil
	file_app_observatory_config_proto_goTypes = nil
	file_app_observatory_config_proto_depIdxs = nil
}
