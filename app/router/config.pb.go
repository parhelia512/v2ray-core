package router

import (
	net "github.com/v2fly/v2ray-core/v4/common/net"
	serial "github.com/v2fly/v2ray-core/v4/common/serial"
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

// Type of domain value.
type Domain_Type int32

const (
	// The value is used as is.
	Domain_Plain Domain_Type = 0
	// The value is used as a regular expression.
	Domain_Regex Domain_Type = 1
	// The value is a root domain.
	Domain_Domain Domain_Type = 2
	// The value is a domain.
	Domain_Full Domain_Type = 3
)

// Enum value maps for Domain_Type.
var (
	Domain_Type_name = map[int32]string{
		0: "Plain",
		1: "Regex",
		2: "Domain",
		3: "Full",
	}
	Domain_Type_value = map[string]int32{
		"Plain":  0,
		"Regex":  1,
		"Domain": 2,
		"Full":   3,
	}
)

func (x Domain_Type) Enum() *Domain_Type {
	p := new(Domain_Type)
	*p = x
	return p
}

func (x Domain_Type) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Domain_Type) Descriptor() protoreflect.EnumDescriptor {
	return file_app_router_config_proto_enumTypes[0].Descriptor()
}

func (Domain_Type) Type() protoreflect.EnumType {
	return &file_app_router_config_proto_enumTypes[0]
}

func (x Domain_Type) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Domain_Type.Descriptor instead.
func (Domain_Type) EnumDescriptor() ([]byte, []int) {
	return file_app_router_config_proto_rawDescGZIP(), []int{0, 0}
}

type Config_DomainStrategy int32

const (
	// Use domain as is.
	Config_AsIs Config_DomainStrategy = 0
	// Always resolve IP for domains.
	Config_UseIp Config_DomainStrategy = 1
	// Resolve to IP if the domain doesn't match any rules.
	Config_IpIfNonMatch Config_DomainStrategy = 2
	// Resolve to IP if any rule requires IP matching.
	Config_IpOnDemand Config_DomainStrategy = 3
)

// Enum value maps for Config_DomainStrategy.
var (
	Config_DomainStrategy_name = map[int32]string{
		0: "AsIs",
		1: "UseIp",
		2: "IpIfNonMatch",
		3: "IpOnDemand",
	}
	Config_DomainStrategy_value = map[string]int32{
		"AsIs":         0,
		"UseIp":        1,
		"IpIfNonMatch": 2,
		"IpOnDemand":   3,
	}
)

func (x Config_DomainStrategy) Enum() *Config_DomainStrategy {
	p := new(Config_DomainStrategy)
	*p = x
	return p
}

func (x Config_DomainStrategy) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Config_DomainStrategy) Descriptor() protoreflect.EnumDescriptor {
	return file_app_router_config_proto_enumTypes[1].Descriptor()
}

func (Config_DomainStrategy) Type() protoreflect.EnumType {
	return &file_app_router_config_proto_enumTypes[1]
}

func (x Config_DomainStrategy) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Config_DomainStrategy.Descriptor instead.
func (Config_DomainStrategy) EnumDescriptor() ([]byte, []int) {
	return file_app_router_config_proto_rawDescGZIP(), []int{12, 0}
}

// Domain for routing decision.
type Domain struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Domain matching type.
	Type Domain_Type `protobuf:"varint,1,opt,name=type,proto3,enum=v2ray.core.app.router.Domain_Type" json:"type,omitempty"`
	// Domain value.
	Value string `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
	// Attributes of this domain. May be used for filtering.
	Attribute []*Domain_Attribute `protobuf:"bytes,3,rep,name=attribute,proto3" json:"attribute,omitempty"`
}

func (x *Domain) Reset() {
	*x = Domain{}
	if protoimpl.UnsafeEnabled {
		mi := &file_app_router_config_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Domain) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Domain) ProtoMessage() {}

func (x *Domain) ProtoReflect() protoreflect.Message {
	mi := &file_app_router_config_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Domain.ProtoReflect.Descriptor instead.
func (*Domain) Descriptor() ([]byte, []int) {
	return file_app_router_config_proto_rawDescGZIP(), []int{0}
}

func (x *Domain) GetType() Domain_Type {
	if x != nil {
		return x.Type
	}
	return Domain_Plain
}

func (x *Domain) GetValue() string {
	if x != nil {
		return x.Value
	}
	return ""
}

func (x *Domain) GetAttribute() []*Domain_Attribute {
	if x != nil {
		return x.Attribute
	}
	return nil
}

// IP for routing decision, in CIDR form.
type CIDR struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// IP address, should be either 4 or 16 bytes.
	Ip []byte `protobuf:"bytes,1,opt,name=ip,proto3" json:"ip,omitempty"`
	// Number of leading ones in the network mask.
	Prefix uint32 `protobuf:"varint,2,opt,name=prefix,proto3" json:"prefix,omitempty"`
}

func (x *CIDR) Reset() {
	*x = CIDR{}
	if protoimpl.UnsafeEnabled {
		mi := &file_app_router_config_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CIDR) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CIDR) ProtoMessage() {}

func (x *CIDR) ProtoReflect() protoreflect.Message {
	mi := &file_app_router_config_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CIDR.ProtoReflect.Descriptor instead.
func (*CIDR) Descriptor() ([]byte, []int) {
	return file_app_router_config_proto_rawDescGZIP(), []int{1}
}

func (x *CIDR) GetIp() []byte {
	if x != nil {
		return x.Ip
	}
	return nil
}

func (x *CIDR) GetPrefix() uint32 {
	if x != nil {
		return x.Prefix
	}
	return 0
}

type GeoIP struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	CountryCode  string  `protobuf:"bytes,1,opt,name=country_code,json=countryCode,proto3" json:"country_code,omitempty"`
	Cidr         []*CIDR `protobuf:"bytes,2,rep,name=cidr,proto3" json:"cidr,omitempty"`
	ReverseMatch bool    `protobuf:"varint,3,opt,name=reverse_match,json=reverseMatch,proto3" json:"reverse_match,omitempty"`
}

func (x *GeoIP) Reset() {
	*x = GeoIP{}
	if protoimpl.UnsafeEnabled {
		mi := &file_app_router_config_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GeoIP) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GeoIP) ProtoMessage() {}

func (x *GeoIP) ProtoReflect() protoreflect.Message {
	mi := &file_app_router_config_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GeoIP.ProtoReflect.Descriptor instead.
func (*GeoIP) Descriptor() ([]byte, []int) {
	return file_app_router_config_proto_rawDescGZIP(), []int{2}
}

func (x *GeoIP) GetCountryCode() string {
	if x != nil {
		return x.CountryCode
	}
	return ""
}

func (x *GeoIP) GetCidr() []*CIDR {
	if x != nil {
		return x.Cidr
	}
	return nil
}

func (x *GeoIP) GetReverseMatch() bool {
	if x != nil {
		return x.ReverseMatch
	}
	return false
}

type GeoIPList struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Entry []*GeoIP `protobuf:"bytes,1,rep,name=entry,proto3" json:"entry,omitempty"`
}

func (x *GeoIPList) Reset() {
	*x = GeoIPList{}
	if protoimpl.UnsafeEnabled {
		mi := &file_app_router_config_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GeoIPList) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GeoIPList) ProtoMessage() {}

func (x *GeoIPList) ProtoReflect() protoreflect.Message {
	mi := &file_app_router_config_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GeoIPList.ProtoReflect.Descriptor instead.
func (*GeoIPList) Descriptor() ([]byte, []int) {
	return file_app_router_config_proto_rawDescGZIP(), []int{3}
}

func (x *GeoIPList) GetEntry() []*GeoIP {
	if x != nil {
		return x.Entry
	}
	return nil
}

type GeoSite struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	CountryCode string    `protobuf:"bytes,1,opt,name=country_code,json=countryCode,proto3" json:"country_code,omitempty"`
	Domain      []*Domain `protobuf:"bytes,2,rep,name=domain,proto3" json:"domain,omitempty"`
}

func (x *GeoSite) Reset() {
	*x = GeoSite{}
	if protoimpl.UnsafeEnabled {
		mi := &file_app_router_config_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GeoSite) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GeoSite) ProtoMessage() {}

func (x *GeoSite) ProtoReflect() protoreflect.Message {
	mi := &file_app_router_config_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GeoSite.ProtoReflect.Descriptor instead.
func (*GeoSite) Descriptor() ([]byte, []int) {
	return file_app_router_config_proto_rawDescGZIP(), []int{4}
}

func (x *GeoSite) GetCountryCode() string {
	if x != nil {
		return x.CountryCode
	}
	return ""
}

func (x *GeoSite) GetDomain() []*Domain {
	if x != nil {
		return x.Domain
	}
	return nil
}

type GeoSiteList struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Entry []*GeoSite `protobuf:"bytes,1,rep,name=entry,proto3" json:"entry,omitempty"`
}

func (x *GeoSiteList) Reset() {
	*x = GeoSiteList{}
	if protoimpl.UnsafeEnabled {
		mi := &file_app_router_config_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GeoSiteList) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GeoSiteList) ProtoMessage() {}

func (x *GeoSiteList) ProtoReflect() protoreflect.Message {
	mi := &file_app_router_config_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GeoSiteList.ProtoReflect.Descriptor instead.
func (*GeoSiteList) Descriptor() ([]byte, []int) {
	return file_app_router_config_proto_rawDescGZIP(), []int{5}
}

func (x *GeoSiteList) GetEntry() []*GeoSite {
	if x != nil {
		return x.Entry
	}
	return nil
}

type RoutingRule struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to TargetTag:
	//
	//	*RoutingRule_Tag
	//	*RoutingRule_BalancingTag
	TargetTag isRoutingRule_TargetTag `protobuf_oneof:"target_tag"`
	// List of domains for target domain matching.
	Domain []*Domain `protobuf:"bytes,2,rep,name=domain,proto3" json:"domain,omitempty"`
	// List of CIDRs for target IP address matching.
	// Deprecated. Use geoip below.
	//
	// Deprecated: Marked as deprecated in app/router/config.proto.
	Cidr []*CIDR `protobuf:"bytes,3,rep,name=cidr,proto3" json:"cidr,omitempty"`
	// List of GeoIPs for target IP address matching. If this entry exists, the
	// cidr above will have no effect. GeoIP fields with the same country code are
	// supposed to contain exactly same content. They will be merged during
	// runtime. For customized GeoIPs, please leave country code empty.
	Geoip []*GeoIP `protobuf:"bytes,10,rep,name=geoip,proto3" json:"geoip,omitempty"`
	// A range of port [from, to]. If the destination port is in this range, this
	// rule takes effect. Deprecated. Use port_list.
	//
	// Deprecated: Marked as deprecated in app/router/config.proto.
	PortRange *net.PortRange `protobuf:"bytes,4,opt,name=port_range,json=portRange,proto3" json:"port_range,omitempty"`
	// List of ports.
	PortList *net.PortList `protobuf:"bytes,14,opt,name=port_list,json=portList,proto3" json:"port_list,omitempty"`
	// List of networks. Deprecated. Use networks.
	//
	// Deprecated: Marked as deprecated in app/router/config.proto.
	NetworkList *net.NetworkList `protobuf:"bytes,5,opt,name=network_list,json=networkList,proto3" json:"network_list,omitempty"`
	// List of networks for matching.
	Networks []net.Network `protobuf:"varint,13,rep,packed,name=networks,proto3,enum=v2ray.core.common.net.Network" json:"networks,omitempty"`
	// List of CIDRs for source IP address matching.
	//
	// Deprecated: Marked as deprecated in app/router/config.proto.
	SourceCidr []*CIDR `protobuf:"bytes,6,rep,name=source_cidr,json=sourceCidr,proto3" json:"source_cidr,omitempty"`
	// List of GeoIPs for source IP address matching. If this entry exists, the
	// source_cidr above will have no effect.
	SourceGeoip []*GeoIP `protobuf:"bytes,11,rep,name=source_geoip,json=sourceGeoip,proto3" json:"source_geoip,omitempty"`
	// List of ports for source port matching.
	SourcePortList *net.PortList `protobuf:"bytes,16,opt,name=source_port_list,json=sourcePortList,proto3" json:"source_port_list,omitempty"`
	UserEmail      []string      `protobuf:"bytes,7,rep,name=user_email,json=userEmail,proto3" json:"user_email,omitempty"`
	InboundTag     []string      `protobuf:"bytes,8,rep,name=inbound_tag,json=inboundTag,proto3" json:"inbound_tag,omitempty"`
	Protocol       []string      `protobuf:"bytes,9,rep,name=protocol,proto3" json:"protocol,omitempty"`
	Attributes     string        `protobuf:"bytes,15,opt,name=attributes,proto3" json:"attributes,omitempty"`
	DomainMatcher  string        `protobuf:"bytes,17,opt,name=domain_matcher,json=domainMatcher,proto3" json:"domain_matcher,omitempty"`
}

func (x *RoutingRule) Reset() {
	*x = RoutingRule{}
	if protoimpl.UnsafeEnabled {
		mi := &file_app_router_config_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RoutingRule) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RoutingRule) ProtoMessage() {}

func (x *RoutingRule) ProtoReflect() protoreflect.Message {
	mi := &file_app_router_config_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RoutingRule.ProtoReflect.Descriptor instead.
func (*RoutingRule) Descriptor() ([]byte, []int) {
	return file_app_router_config_proto_rawDescGZIP(), []int{6}
}

func (m *RoutingRule) GetTargetTag() isRoutingRule_TargetTag {
	if m != nil {
		return m.TargetTag
	}
	return nil
}

func (x *RoutingRule) GetTag() string {
	if x, ok := x.GetTargetTag().(*RoutingRule_Tag); ok {
		return x.Tag
	}
	return ""
}

func (x *RoutingRule) GetBalancingTag() string {
	if x, ok := x.GetTargetTag().(*RoutingRule_BalancingTag); ok {
		return x.BalancingTag
	}
	return ""
}

func (x *RoutingRule) GetDomain() []*Domain {
	if x != nil {
		return x.Domain
	}
	return nil
}

// Deprecated: Marked as deprecated in app/router/config.proto.
func (x *RoutingRule) GetCidr() []*CIDR {
	if x != nil {
		return x.Cidr
	}
	return nil
}

func (x *RoutingRule) GetGeoip() []*GeoIP {
	if x != nil {
		return x.Geoip
	}
	return nil
}

// Deprecated: Marked as deprecated in app/router/config.proto.
func (x *RoutingRule) GetPortRange() *net.PortRange {
	if x != nil {
		return x.PortRange
	}
	return nil
}

func (x *RoutingRule) GetPortList() *net.PortList {
	if x != nil {
		return x.PortList
	}
	return nil
}

// Deprecated: Marked as deprecated in app/router/config.proto.
func (x *RoutingRule) GetNetworkList() *net.NetworkList {
	if x != nil {
		return x.NetworkList
	}
	return nil
}

func (x *RoutingRule) GetNetworks() []net.Network {
	if x != nil {
		return x.Networks
	}
	return nil
}

// Deprecated: Marked as deprecated in app/router/config.proto.
func (x *RoutingRule) GetSourceCidr() []*CIDR {
	if x != nil {
		return x.SourceCidr
	}
	return nil
}

func (x *RoutingRule) GetSourceGeoip() []*GeoIP {
	if x != nil {
		return x.SourceGeoip
	}
	return nil
}

func (x *RoutingRule) GetSourcePortList() *net.PortList {
	if x != nil {
		return x.SourcePortList
	}
	return nil
}

func (x *RoutingRule) GetUserEmail() []string {
	if x != nil {
		return x.UserEmail
	}
	return nil
}

func (x *RoutingRule) GetInboundTag() []string {
	if x != nil {
		return x.InboundTag
	}
	return nil
}

func (x *RoutingRule) GetProtocol() []string {
	if x != nil {
		return x.Protocol
	}
	return nil
}

func (x *RoutingRule) GetAttributes() string {
	if x != nil {
		return x.Attributes
	}
	return ""
}

func (x *RoutingRule) GetDomainMatcher() string {
	if x != nil {
		return x.DomainMatcher
	}
	return ""
}

type isRoutingRule_TargetTag interface {
	isRoutingRule_TargetTag()
}

type RoutingRule_Tag struct {
	// Tag of outbound that this rule is pointing to.
	Tag string `protobuf:"bytes,1,opt,name=tag,proto3,oneof"`
}

type RoutingRule_BalancingTag struct {
	// Tag of routing balancer.
	BalancingTag string `protobuf:"bytes,12,opt,name=balancing_tag,json=balancingTag,proto3,oneof"`
}

func (*RoutingRule_Tag) isRoutingRule_TargetTag() {}

func (*RoutingRule_BalancingTag) isRoutingRule_TargetTag() {}

type BalancingRule struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Tag              string               `protobuf:"bytes,1,opt,name=tag,proto3" json:"tag,omitempty"`
	OutboundSelector []string             `protobuf:"bytes,2,rep,name=outbound_selector,json=outboundSelector,proto3" json:"outbound_selector,omitempty"`
	Strategy         string               `protobuf:"bytes,3,opt,name=strategy,proto3" json:"strategy,omitempty"`
	StrategySettings *serial.TypedMessage `protobuf:"bytes,4,opt,name=strategy_settings,json=strategySettings,proto3" json:"strategy_settings,omitempty"`
	FallbackTag      string               `protobuf:"bytes,5,opt,name=fallback_tag,json=fallbackTag,proto3" json:"fallback_tag,omitempty"`
}

func (x *BalancingRule) Reset() {
	*x = BalancingRule{}
	if protoimpl.UnsafeEnabled {
		mi := &file_app_router_config_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BalancingRule) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BalancingRule) ProtoMessage() {}

func (x *BalancingRule) ProtoReflect() protoreflect.Message {
	mi := &file_app_router_config_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BalancingRule.ProtoReflect.Descriptor instead.
func (*BalancingRule) Descriptor() ([]byte, []int) {
	return file_app_router_config_proto_rawDescGZIP(), []int{7}
}

func (x *BalancingRule) GetTag() string {
	if x != nil {
		return x.Tag
	}
	return ""
}

func (x *BalancingRule) GetOutboundSelector() []string {
	if x != nil {
		return x.OutboundSelector
	}
	return nil
}

func (x *BalancingRule) GetStrategy() string {
	if x != nil {
		return x.Strategy
	}
	return ""
}

func (x *BalancingRule) GetStrategySettings() *serial.TypedMessage {
	if x != nil {
		return x.StrategySettings
	}
	return nil
}

func (x *BalancingRule) GetFallbackTag() string {
	if x != nil {
		return x.FallbackTag
	}
	return ""
}

type StrategyWeight struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Regexp bool    `protobuf:"varint,1,opt,name=regexp,proto3" json:"regexp,omitempty"`
	Match  string  `protobuf:"bytes,2,opt,name=match,proto3" json:"match,omitempty"`
	Value  float32 `protobuf:"fixed32,3,opt,name=value,proto3" json:"value,omitempty"`
}

func (x *StrategyWeight) Reset() {
	*x = StrategyWeight{}
	if protoimpl.UnsafeEnabled {
		mi := &file_app_router_config_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StrategyWeight) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StrategyWeight) ProtoMessage() {}

func (x *StrategyWeight) ProtoReflect() protoreflect.Message {
	mi := &file_app_router_config_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StrategyWeight.ProtoReflect.Descriptor instead.
func (*StrategyWeight) Descriptor() ([]byte, []int) {
	return file_app_router_config_proto_rawDescGZIP(), []int{8}
}

func (x *StrategyWeight) GetRegexp() bool {
	if x != nil {
		return x.Regexp
	}
	return false
}

func (x *StrategyWeight) GetMatch() string {
	if x != nil {
		return x.Match
	}
	return ""
}

func (x *StrategyWeight) GetValue() float32 {
	if x != nil {
		return x.Value
	}
	return 0
}

type StrategyRandomConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ObserverTag string `protobuf:"bytes,7,opt,name=observer_tag,json=observerTag,proto3" json:"observer_tag,omitempty"`
	AliveOnly   bool   `protobuf:"varint,8,opt,name=alive_only,json=aliveOnly,proto3" json:"alive_only,omitempty"`
}

func (x *StrategyRandomConfig) Reset() {
	*x = StrategyRandomConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_app_router_config_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StrategyRandomConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StrategyRandomConfig) ProtoMessage() {}

func (x *StrategyRandomConfig) ProtoReflect() protoreflect.Message {
	mi := &file_app_router_config_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StrategyRandomConfig.ProtoReflect.Descriptor instead.
func (*StrategyRandomConfig) Descriptor() ([]byte, []int) {
	return file_app_router_config_proto_rawDescGZIP(), []int{9}
}

func (x *StrategyRandomConfig) GetObserverTag() string {
	if x != nil {
		return x.ObserverTag
	}
	return ""
}

func (x *StrategyRandomConfig) GetAliveOnly() bool {
	if x != nil {
		return x.AliveOnly
	}
	return false
}

type StrategyLeastPingConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ObserverTag string `protobuf:"bytes,7,opt,name=observer_tag,json=observerTag,proto3" json:"observer_tag,omitempty"`
}

func (x *StrategyLeastPingConfig) Reset() {
	*x = StrategyLeastPingConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_app_router_config_proto_msgTypes[10]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StrategyLeastPingConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StrategyLeastPingConfig) ProtoMessage() {}

func (x *StrategyLeastPingConfig) ProtoReflect() protoreflect.Message {
	mi := &file_app_router_config_proto_msgTypes[10]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StrategyLeastPingConfig.ProtoReflect.Descriptor instead.
func (*StrategyLeastPingConfig) Descriptor() ([]byte, []int) {
	return file_app_router_config_proto_rawDescGZIP(), []int{10}
}

func (x *StrategyLeastPingConfig) GetObserverTag() string {
	if x != nil {
		return x.ObserverTag
	}
	return ""
}

type StrategyLeastLoadConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// weight settings
	Costs []*StrategyWeight `protobuf:"bytes,2,rep,name=costs,proto3" json:"costs,omitempty"`
	// RTT baselines for selecting, int64 values of time.Duration
	Baselines []int64 `protobuf:"varint,3,rep,packed,name=baselines,proto3" json:"baselines,omitempty"`
	// expected nodes count to select
	Expected int32 `protobuf:"varint,4,opt,name=expected,proto3" json:"expected,omitempty"`
	// max acceptable rtt, filter away high delay nodes. defalut 0
	MaxRTT int64 `protobuf:"varint,5,opt,name=maxRTT,proto3" json:"maxRTT,omitempty"`
	// acceptable failure rate
	Tolerance   float32 `protobuf:"fixed32,6,opt,name=tolerance,proto3" json:"tolerance,omitempty"`
	ObserverTag string  `protobuf:"bytes,7,opt,name=observer_tag,json=observerTag,proto3" json:"observer_tag,omitempty"`
}

func (x *StrategyLeastLoadConfig) Reset() {
	*x = StrategyLeastLoadConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_app_router_config_proto_msgTypes[11]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StrategyLeastLoadConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StrategyLeastLoadConfig) ProtoMessage() {}

func (x *StrategyLeastLoadConfig) ProtoReflect() protoreflect.Message {
	mi := &file_app_router_config_proto_msgTypes[11]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StrategyLeastLoadConfig.ProtoReflect.Descriptor instead.
func (*StrategyLeastLoadConfig) Descriptor() ([]byte, []int) {
	return file_app_router_config_proto_rawDescGZIP(), []int{11}
}

func (x *StrategyLeastLoadConfig) GetCosts() []*StrategyWeight {
	if x != nil {
		return x.Costs
	}
	return nil
}

func (x *StrategyLeastLoadConfig) GetBaselines() []int64 {
	if x != nil {
		return x.Baselines
	}
	return nil
}

func (x *StrategyLeastLoadConfig) GetExpected() int32 {
	if x != nil {
		return x.Expected
	}
	return 0
}

func (x *StrategyLeastLoadConfig) GetMaxRTT() int64 {
	if x != nil {
		return x.MaxRTT
	}
	return 0
}

func (x *StrategyLeastLoadConfig) GetTolerance() float32 {
	if x != nil {
		return x.Tolerance
	}
	return 0
}

func (x *StrategyLeastLoadConfig) GetObserverTag() string {
	if x != nil {
		return x.ObserverTag
	}
	return ""
}

type Config struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	DomainStrategy Config_DomainStrategy `protobuf:"varint,1,opt,name=domain_strategy,json=domainStrategy,proto3,enum=v2ray.core.app.router.Config_DomainStrategy" json:"domain_strategy,omitempty"`
	Rule           []*RoutingRule        `protobuf:"bytes,2,rep,name=rule,proto3" json:"rule,omitempty"`
	BalancingRule  []*BalancingRule      `protobuf:"bytes,3,rep,name=balancing_rule,json=balancingRule,proto3" json:"balancing_rule,omitempty"`
}

func (x *Config) Reset() {
	*x = Config{}
	if protoimpl.UnsafeEnabled {
		mi := &file_app_router_config_proto_msgTypes[12]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Config) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Config) ProtoMessage() {}

func (x *Config) ProtoReflect() protoreflect.Message {
	mi := &file_app_router_config_proto_msgTypes[12]
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
	return file_app_router_config_proto_rawDescGZIP(), []int{12}
}

func (x *Config) GetDomainStrategy() Config_DomainStrategy {
	if x != nil {
		return x.DomainStrategy
	}
	return Config_AsIs
}

func (x *Config) GetRule() []*RoutingRule {
	if x != nil {
		return x.Rule
	}
	return nil
}

func (x *Config) GetBalancingRule() []*BalancingRule {
	if x != nil {
		return x.BalancingRule
	}
	return nil
}

type Domain_Attribute struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Key string `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	// Types that are assignable to TypedValue:
	//
	//	*Domain_Attribute_BoolValue
	//	*Domain_Attribute_IntValue
	TypedValue isDomain_Attribute_TypedValue `protobuf_oneof:"typed_value"`
}

func (x *Domain_Attribute) Reset() {
	*x = Domain_Attribute{}
	if protoimpl.UnsafeEnabled {
		mi := &file_app_router_config_proto_msgTypes[13]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Domain_Attribute) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Domain_Attribute) ProtoMessage() {}

func (x *Domain_Attribute) ProtoReflect() protoreflect.Message {
	mi := &file_app_router_config_proto_msgTypes[13]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Domain_Attribute.ProtoReflect.Descriptor instead.
func (*Domain_Attribute) Descriptor() ([]byte, []int) {
	return file_app_router_config_proto_rawDescGZIP(), []int{0, 0}
}

func (x *Domain_Attribute) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (m *Domain_Attribute) GetTypedValue() isDomain_Attribute_TypedValue {
	if m != nil {
		return m.TypedValue
	}
	return nil
}

func (x *Domain_Attribute) GetBoolValue() bool {
	if x, ok := x.GetTypedValue().(*Domain_Attribute_BoolValue); ok {
		return x.BoolValue
	}
	return false
}

func (x *Domain_Attribute) GetIntValue() int64 {
	if x, ok := x.GetTypedValue().(*Domain_Attribute_IntValue); ok {
		return x.IntValue
	}
	return 0
}

type isDomain_Attribute_TypedValue interface {
	isDomain_Attribute_TypedValue()
}

type Domain_Attribute_BoolValue struct {
	BoolValue bool `protobuf:"varint,2,opt,name=bool_value,json=boolValue,proto3,oneof"`
}

type Domain_Attribute_IntValue struct {
	IntValue int64 `protobuf:"varint,3,opt,name=int_value,json=intValue,proto3,oneof"`
}

func (*Domain_Attribute_BoolValue) isDomain_Attribute_TypedValue() {}

func (*Domain_Attribute_IntValue) isDomain_Attribute_TypedValue() {}

var File_app_router_config_proto protoreflect.FileDescriptor

var file_app_router_config_proto_rawDesc = []byte{
	0x0a, 0x17, 0x61, 0x70, 0x70, 0x2f, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x2f, 0x63, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x15, 0x76, 0x32, 0x72, 0x61, 0x79,
	0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x61, 0x70, 0x70, 0x2e, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72,
	0x1a, 0x21, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x73, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x2f,
	0x74, 0x79, 0x70, 0x65, 0x64, 0x5f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x15, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x6e, 0x65, 0x74, 0x2f,
	0x70, 0x6f, 0x72, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x18, 0x63, 0x6f, 0x6d, 0x6d,
	0x6f, 0x6e, 0x2f, 0x6e, 0x65, 0x74, 0x2f, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0xbf, 0x02, 0x0a, 0x06, 0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x12,
	0x36, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x22, 0x2e,
	0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x61, 0x70, 0x70, 0x2e, 0x72,
	0x6f, 0x75, 0x74, 0x65, 0x72, 0x2e, 0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x2e, 0x54, 0x79, 0x70,
	0x65, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x45, 0x0a,
	0x09, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x27, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x61, 0x70,
	0x70, 0x2e, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x2e, 0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x2e,
	0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x52, 0x09, 0x61, 0x74, 0x74, 0x72, 0x69,
	0x62, 0x75, 0x74, 0x65, 0x1a, 0x6c, 0x0a, 0x09, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74,
	0x65, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03,
	0x6b, 0x65, 0x79, 0x12, 0x1f, 0x0a, 0x0a, 0x62, 0x6f, 0x6f, 0x6c, 0x5f, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x48, 0x00, 0x52, 0x09, 0x62, 0x6f, 0x6f, 0x6c, 0x56,
	0x61, 0x6c, 0x75, 0x65, 0x12, 0x1d, 0x0a, 0x09, 0x69, 0x6e, 0x74, 0x5f, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x03, 0x48, 0x00, 0x52, 0x08, 0x69, 0x6e, 0x74, 0x56, 0x61,
	0x6c, 0x75, 0x65, 0x42, 0x0d, 0x0a, 0x0b, 0x74, 0x79, 0x70, 0x65, 0x64, 0x5f, 0x76, 0x61, 0x6c,
	0x75, 0x65, 0x22, 0x32, 0x0a, 0x04, 0x54, 0x79, 0x70, 0x65, 0x12, 0x09, 0x0a, 0x05, 0x50, 0x6c,
	0x61, 0x69, 0x6e, 0x10, 0x00, 0x12, 0x09, 0x0a, 0x05, 0x52, 0x65, 0x67, 0x65, 0x78, 0x10, 0x01,
	0x12, 0x0a, 0x0a, 0x06, 0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x10, 0x02, 0x12, 0x08, 0x0a, 0x04,
	0x46, 0x75, 0x6c, 0x6c, 0x10, 0x03, 0x22, 0x2e, 0x0a, 0x04, 0x43, 0x49, 0x44, 0x52, 0x12, 0x0e,
	0x0a, 0x02, 0x69, 0x70, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x69, 0x70, 0x12, 0x16,
	0x0a, 0x06, 0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x06,
	0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x22, 0x80, 0x01, 0x0a, 0x05, 0x47, 0x65, 0x6f, 0x49, 0x50,
	0x12, 0x21, 0x0a, 0x0c, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x72, 0x79, 0x5f, 0x63, 0x6f, 0x64, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x72, 0x79, 0x43,
	0x6f, 0x64, 0x65, 0x12, 0x2f, 0x0a, 0x04, 0x63, 0x69, 0x64, 0x72, 0x18, 0x02, 0x20, 0x03, 0x28,
	0x0b, 0x32, 0x1b, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x61,
	0x70, 0x70, 0x2e, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x2e, 0x43, 0x49, 0x44, 0x52, 0x52, 0x04,
	0x63, 0x69, 0x64, 0x72, 0x12, 0x23, 0x0a, 0x0d, 0x72, 0x65, 0x76, 0x65, 0x72, 0x73, 0x65, 0x5f,
	0x6d, 0x61, 0x74, 0x63, 0x68, 0x18, 0x03, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0c, 0x72, 0x65, 0x76,
	0x65, 0x72, 0x73, 0x65, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x22, 0x3f, 0x0a, 0x09, 0x47, 0x65, 0x6f,
	0x49, 0x50, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x32, 0x0a, 0x05, 0x65, 0x6e, 0x74, 0x72, 0x79, 0x18,
	0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f,
	0x72, 0x65, 0x2e, 0x61, 0x70, 0x70, 0x2e, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x2e, 0x47, 0x65,
	0x6f, 0x49, 0x50, 0x52, 0x05, 0x65, 0x6e, 0x74, 0x72, 0x79, 0x22, 0x63, 0x0a, 0x07, 0x47, 0x65,
	0x6f, 0x53, 0x69, 0x74, 0x65, 0x12, 0x21, 0x0a, 0x0c, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x72, 0x79,
	0x5f, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x63, 0x6f, 0x75,
	0x6e, 0x74, 0x72, 0x79, 0x43, 0x6f, 0x64, 0x65, 0x12, 0x35, 0x0a, 0x06, 0x64, 0x6f, 0x6d, 0x61,
	0x69, 0x6e, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1d, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79,
	0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x61, 0x70, 0x70, 0x2e, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72,
	0x2e, 0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x52, 0x06, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x22,
	0x43, 0x0a, 0x0b, 0x47, 0x65, 0x6f, 0x53, 0x69, 0x74, 0x65, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x34,
	0x0a, 0x05, 0x65, 0x6e, 0x74, 0x72, 0x79, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1e, 0x2e,
	0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x61, 0x70, 0x70, 0x2e, 0x72,
	0x6f, 0x75, 0x74, 0x65, 0x72, 0x2e, 0x47, 0x65, 0x6f, 0x53, 0x69, 0x74, 0x65, 0x52, 0x05, 0x65,
	0x6e, 0x74, 0x72, 0x79, 0x22, 0xf1, 0x06, 0x0a, 0x0b, 0x52, 0x6f, 0x75, 0x74, 0x69, 0x6e, 0x67,
	0x52, 0x75, 0x6c, 0x65, 0x12, 0x12, 0x0a, 0x03, 0x74, 0x61, 0x67, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x48, 0x00, 0x52, 0x03, 0x74, 0x61, 0x67, 0x12, 0x25, 0x0a, 0x0d, 0x62, 0x61, 0x6c, 0x61,
	0x6e, 0x63, 0x69, 0x6e, 0x67, 0x5f, 0x74, 0x61, 0x67, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x09, 0x48,
	0x00, 0x52, 0x0c, 0x62, 0x61, 0x6c, 0x61, 0x6e, 0x63, 0x69, 0x6e, 0x67, 0x54, 0x61, 0x67, 0x12,
	0x35, 0x0a, 0x06, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x1d, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x61, 0x70, 0x70,
	0x2e, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x2e, 0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x52, 0x06,
	0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x12, 0x33, 0x0a, 0x04, 0x63, 0x69, 0x64, 0x72, 0x18, 0x03,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x1b, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72,
	0x65, 0x2e, 0x61, 0x70, 0x70, 0x2e, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x2e, 0x43, 0x49, 0x44,
	0x52, 0x42, 0x02, 0x18, 0x01, 0x52, 0x04, 0x63, 0x69, 0x64, 0x72, 0x12, 0x32, 0x0a, 0x05, 0x67,
	0x65, 0x6f, 0x69, 0x70, 0x18, 0x0a, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x76, 0x32, 0x72,
	0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x61, 0x70, 0x70, 0x2e, 0x72, 0x6f, 0x75, 0x74,
	0x65, 0x72, 0x2e, 0x47, 0x65, 0x6f, 0x49, 0x50, 0x52, 0x05, 0x67, 0x65, 0x6f, 0x69, 0x70, 0x12,
	0x43, 0x0a, 0x0a, 0x70, 0x6f, 0x72, 0x74, 0x5f, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65,
	0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x6e, 0x65, 0x74, 0x2e, 0x50, 0x6f, 0x72, 0x74,
	0x52, 0x61, 0x6e, 0x67, 0x65, 0x42, 0x02, 0x18, 0x01, 0x52, 0x09, 0x70, 0x6f, 0x72, 0x74, 0x52,
	0x61, 0x6e, 0x67, 0x65, 0x12, 0x3c, 0x0a, 0x09, 0x70, 0x6f, 0x72, 0x74, 0x5f, 0x6c, 0x69, 0x73,
	0x74, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e,
	0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x6e, 0x65, 0x74, 0x2e,
	0x50, 0x6f, 0x72, 0x74, 0x4c, 0x69, 0x73, 0x74, 0x52, 0x08, 0x70, 0x6f, 0x72, 0x74, 0x4c, 0x69,
	0x73, 0x74, 0x12, 0x49, 0x0a, 0x0c, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x5f, 0x6c, 0x69,
	0x73, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x22, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79,
	0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x6e, 0x65, 0x74,
	0x2e, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x4c, 0x69, 0x73, 0x74, 0x42, 0x02, 0x18, 0x01,
	0x52, 0x0b, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x3a, 0x0a,
	0x08, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x73, 0x18, 0x0d, 0x20, 0x03, 0x28, 0x0e, 0x32,
	0x1e, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
	0x6d, 0x6f, 0x6e, 0x2e, 0x6e, 0x65, 0x74, 0x2e, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x52,
	0x08, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x73, 0x12, 0x40, 0x0a, 0x0b, 0x73, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x5f, 0x63, 0x69, 0x64, 0x72, 0x18, 0x06, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1b,
	0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x61, 0x70, 0x70, 0x2e,
	0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x2e, 0x43, 0x49, 0x44, 0x52, 0x42, 0x02, 0x18, 0x01, 0x52,
	0x0a, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x43, 0x69, 0x64, 0x72, 0x12, 0x3f, 0x0a, 0x0c, 0x73,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x67, 0x65, 0x6f, 0x69, 0x70, 0x18, 0x0b, 0x20, 0x03, 0x28,
	0x0b, 0x32, 0x1c, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x61,
	0x70, 0x70, 0x2e, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x2e, 0x47, 0x65, 0x6f, 0x49, 0x50, 0x52,
	0x0b, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x47, 0x65, 0x6f, 0x69, 0x70, 0x12, 0x49, 0x0a, 0x10,
	0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x70, 0x6f, 0x72, 0x74, 0x5f, 0x6c, 0x69, 0x73, 0x74,
	0x18, 0x10, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63,
	0x6f, 0x72, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x6e, 0x65, 0x74, 0x2e, 0x50,
	0x6f, 0x72, 0x74, 0x4c, 0x69, 0x73, 0x74, 0x52, 0x0e, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x50,
	0x6f, 0x72, 0x74, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x1d, 0x0a, 0x0a, 0x75, 0x73, 0x65, 0x72, 0x5f,
	0x65, 0x6d, 0x61, 0x69, 0x6c, 0x18, 0x07, 0x20, 0x03, 0x28, 0x09, 0x52, 0x09, 0x75, 0x73, 0x65,
	0x72, 0x45, 0x6d, 0x61, 0x69, 0x6c, 0x12, 0x1f, 0x0a, 0x0b, 0x69, 0x6e, 0x62, 0x6f, 0x75, 0x6e,
	0x64, 0x5f, 0x74, 0x61, 0x67, 0x18, 0x08, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0a, 0x69, 0x6e, 0x62,
	0x6f, 0x75, 0x6e, 0x64, 0x54, 0x61, 0x67, 0x12, 0x1a, 0x0a, 0x08, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x63, 0x6f, 0x6c, 0x18, 0x09, 0x20, 0x03, 0x28, 0x09, 0x52, 0x08, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x63, 0x6f, 0x6c, 0x12, 0x1e, 0x0a, 0x0a, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65,
	0x73, 0x18, 0x0f, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75,
	0x74, 0x65, 0x73, 0x12, 0x25, 0x0a, 0x0e, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x5f, 0x6d, 0x61,
	0x74, 0x63, 0x68, 0x65, 0x72, 0x18, 0x11, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x64, 0x6f, 0x6d,
	0x61, 0x69, 0x6e, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x42, 0x0c, 0x0a, 0x0a, 0x74, 0x61,
	0x72, 0x67, 0x65, 0x74, 0x5f, 0x74, 0x61, 0x67, 0x22, 0xe2, 0x01, 0x0a, 0x0d, 0x42, 0x61, 0x6c,
	0x61, 0x6e, 0x63, 0x69, 0x6e, 0x67, 0x52, 0x75, 0x6c, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x74, 0x61,
	0x67, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x74, 0x61, 0x67, 0x12, 0x2b, 0x0a, 0x11,
	0x6f, 0x75, 0x74, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x5f, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x6f,
	0x72, 0x18, 0x02, 0x20, 0x03, 0x28, 0x09, 0x52, 0x10, 0x6f, 0x75, 0x74, 0x62, 0x6f, 0x75, 0x6e,
	0x64, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x12, 0x1a, 0x0a, 0x08, 0x73, 0x74, 0x72,
	0x61, 0x74, 0x65, 0x67, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x73, 0x74, 0x72,
	0x61, 0x74, 0x65, 0x67, 0x79, 0x12, 0x53, 0x0a, 0x11, 0x73, 0x74, 0x72, 0x61, 0x74, 0x65, 0x67,
	0x79, 0x5f, 0x73, 0x65, 0x74, 0x74, 0x69, 0x6e, 0x67, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x26, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63, 0x6f,
	0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x73, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x2e, 0x54, 0x79, 0x70, 0x65,
	0x64, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x52, 0x10, 0x73, 0x74, 0x72, 0x61, 0x74, 0x65,
	0x67, 0x79, 0x53, 0x65, 0x74, 0x74, 0x69, 0x6e, 0x67, 0x73, 0x12, 0x21, 0x0a, 0x0c, 0x66, 0x61,
	0x6c, 0x6c, 0x62, 0x61, 0x63, 0x6b, 0x5f, 0x74, 0x61, 0x67, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x0b, 0x66, 0x61, 0x6c, 0x6c, 0x62, 0x61, 0x63, 0x6b, 0x54, 0x61, 0x67, 0x22, 0x54, 0x0a,
	0x0e, 0x53, 0x74, 0x72, 0x61, 0x74, 0x65, 0x67, 0x79, 0x57, 0x65, 0x69, 0x67, 0x68, 0x74, 0x12,
	0x16, 0x0a, 0x06, 0x72, 0x65, 0x67, 0x65, 0x78, 0x70, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52,
	0x06, 0x72, 0x65, 0x67, 0x65, 0x78, 0x70, 0x12, 0x14, 0x0a, 0x05, 0x6d, 0x61, 0x74, 0x63, 0x68,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x12, 0x14, 0x0a,
	0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x02, 0x52, 0x05, 0x76, 0x61,
	0x6c, 0x75, 0x65, 0x22, 0x58, 0x0a, 0x14, 0x53, 0x74, 0x72, 0x61, 0x74, 0x65, 0x67, 0x79, 0x52,
	0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x21, 0x0a, 0x0c, 0x6f,
	0x62, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x5f, 0x74, 0x61, 0x67, 0x18, 0x07, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x0b, 0x6f, 0x62, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x54, 0x61, 0x67, 0x12, 0x1d,
	0x0a, 0x0a, 0x61, 0x6c, 0x69, 0x76, 0x65, 0x5f, 0x6f, 0x6e, 0x6c, 0x79, 0x18, 0x08, 0x20, 0x01,
	0x28, 0x08, 0x52, 0x09, 0x61, 0x6c, 0x69, 0x76, 0x65, 0x4f, 0x6e, 0x6c, 0x79, 0x22, 0x3c, 0x0a,
	0x17, 0x53, 0x74, 0x72, 0x61, 0x74, 0x65, 0x67, 0x79, 0x4c, 0x65, 0x61, 0x73, 0x74, 0x50, 0x69,
	0x6e, 0x67, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x21, 0x0a, 0x0c, 0x6f, 0x62, 0x73, 0x65,
	0x72, 0x76, 0x65, 0x72, 0x5f, 0x74, 0x61, 0x67, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b,
	0x6f, 0x62, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x54, 0x61, 0x67, 0x22, 0xe9, 0x01, 0x0a, 0x17,
	0x53, 0x74, 0x72, 0x61, 0x74, 0x65, 0x67, 0x79, 0x4c, 0x65, 0x61, 0x73, 0x74, 0x4c, 0x6f, 0x61,
	0x64, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x3b, 0x0a, 0x05, 0x63, 0x6f, 0x73, 0x74, 0x73,
	0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x25, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63,
	0x6f, 0x72, 0x65, 0x2e, 0x61, 0x70, 0x70, 0x2e, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x2e, 0x53,
	0x74, 0x72, 0x61, 0x74, 0x65, 0x67, 0x79, 0x57, 0x65, 0x69, 0x67, 0x68, 0x74, 0x52, 0x05, 0x63,
	0x6f, 0x73, 0x74, 0x73, 0x12, 0x1c, 0x0a, 0x09, 0x62, 0x61, 0x73, 0x65, 0x6c, 0x69, 0x6e, 0x65,
	0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x03, 0x52, 0x09, 0x62, 0x61, 0x73, 0x65, 0x6c, 0x69, 0x6e,
	0x65, 0x73, 0x12, 0x1a, 0x0a, 0x08, 0x65, 0x78, 0x70, 0x65, 0x63, 0x74, 0x65, 0x64, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x05, 0x52, 0x08, 0x65, 0x78, 0x70, 0x65, 0x63, 0x74, 0x65, 0x64, 0x12, 0x16,
	0x0a, 0x06, 0x6d, 0x61, 0x78, 0x52, 0x54, 0x54, 0x18, 0x05, 0x20, 0x01, 0x28, 0x03, 0x52, 0x06,
	0x6d, 0x61, 0x78, 0x52, 0x54, 0x54, 0x12, 0x1c, 0x0a, 0x09, 0x74, 0x6f, 0x6c, 0x65, 0x72, 0x61,
	0x6e, 0x63, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x02, 0x52, 0x09, 0x74, 0x6f, 0x6c, 0x65, 0x72,
	0x61, 0x6e, 0x63, 0x65, 0x12, 0x21, 0x0a, 0x0c, 0x6f, 0x62, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72,
	0x5f, 0x74, 0x61, 0x67, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x6f, 0x62, 0x73, 0x65,
	0x72, 0x76, 0x65, 0x72, 0x54, 0x61, 0x67, 0x22, 0xad, 0x02, 0x0a, 0x06, 0x43, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x12, 0x55, 0x0a, 0x0f, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x5f, 0x73, 0x74, 0x72,
	0x61, 0x74, 0x65, 0x67, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x2c, 0x2e, 0x76, 0x32,
	0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x61, 0x70, 0x70, 0x2e, 0x72, 0x6f, 0x75,
	0x74, 0x65, 0x72, 0x2e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x44, 0x6f, 0x6d, 0x61, 0x69,
	0x6e, 0x53, 0x74, 0x72, 0x61, 0x74, 0x65, 0x67, 0x79, 0x52, 0x0e, 0x64, 0x6f, 0x6d, 0x61, 0x69,
	0x6e, 0x53, 0x74, 0x72, 0x61, 0x74, 0x65, 0x67, 0x79, 0x12, 0x36, 0x0a, 0x04, 0x72, 0x75, 0x6c,
	0x65, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x22, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e,
	0x63, 0x6f, 0x72, 0x65, 0x2e, 0x61, 0x70, 0x70, 0x2e, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x2e,
	0x52, 0x6f, 0x75, 0x74, 0x69, 0x6e, 0x67, 0x52, 0x75, 0x6c, 0x65, 0x52, 0x04, 0x72, 0x75, 0x6c,
	0x65, 0x12, 0x4b, 0x0a, 0x0e, 0x62, 0x61, 0x6c, 0x61, 0x6e, 0x63, 0x69, 0x6e, 0x67, 0x5f, 0x72,
	0x75, 0x6c, 0x65, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x24, 0x2e, 0x76, 0x32, 0x72, 0x61,
	0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x61, 0x70, 0x70, 0x2e, 0x72, 0x6f, 0x75, 0x74, 0x65,
	0x72, 0x2e, 0x42, 0x61, 0x6c, 0x61, 0x6e, 0x63, 0x69, 0x6e, 0x67, 0x52, 0x75, 0x6c, 0x65, 0x52,
	0x0d, 0x62, 0x61, 0x6c, 0x61, 0x6e, 0x63, 0x69, 0x6e, 0x67, 0x52, 0x75, 0x6c, 0x65, 0x22, 0x47,
	0x0a, 0x0e, 0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x53, 0x74, 0x72, 0x61, 0x74, 0x65, 0x67, 0x79,
	0x12, 0x08, 0x0a, 0x04, 0x41, 0x73, 0x49, 0x73, 0x10, 0x00, 0x12, 0x09, 0x0a, 0x05, 0x55, 0x73,
	0x65, 0x49, 0x70, 0x10, 0x01, 0x12, 0x10, 0x0a, 0x0c, 0x49, 0x70, 0x49, 0x66, 0x4e, 0x6f, 0x6e,
	0x4d, 0x61, 0x74, 0x63, 0x68, 0x10, 0x02, 0x12, 0x0e, 0x0a, 0x0a, 0x49, 0x70, 0x4f, 0x6e, 0x44,
	0x65, 0x6d, 0x61, 0x6e, 0x64, 0x10, 0x03, 0x42, 0x60, 0x0a, 0x19, 0x63, 0x6f, 0x6d, 0x2e, 0x76,
	0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x61, 0x70, 0x70, 0x2e, 0x72, 0x6f,
	0x75, 0x74, 0x65, 0x72, 0x50, 0x01, 0x5a, 0x29, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63,
	0x6f, 0x6d, 0x2f, 0x76, 0x32, 0x66, 0x6c, 0x79, 0x2f, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2d, 0x63,
	0x6f, 0x72, 0x65, 0x2f, 0x76, 0x34, 0x2f, 0x61, 0x70, 0x70, 0x2f, 0x72, 0x6f, 0x75, 0x74, 0x65,
	0x72, 0xaa, 0x02, 0x15, 0x56, 0x32, 0x52, 0x61, 0x79, 0x2e, 0x43, 0x6f, 0x72, 0x65, 0x2e, 0x41,
	0x70, 0x70, 0x2e, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_app_router_config_proto_rawDescOnce sync.Once
	file_app_router_config_proto_rawDescData = file_app_router_config_proto_rawDesc
)

func file_app_router_config_proto_rawDescGZIP() []byte {
	file_app_router_config_proto_rawDescOnce.Do(func() {
		file_app_router_config_proto_rawDescData = protoimpl.X.CompressGZIP(file_app_router_config_proto_rawDescData)
	})
	return file_app_router_config_proto_rawDescData
}

var file_app_router_config_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_app_router_config_proto_msgTypes = make([]protoimpl.MessageInfo, 14)
var file_app_router_config_proto_goTypes = []interface{}{
	(Domain_Type)(0),                // 0: v2ray.core.app.router.Domain.Type
	(Config_DomainStrategy)(0),      // 1: v2ray.core.app.router.Config.DomainStrategy
	(*Domain)(nil),                  // 2: v2ray.core.app.router.Domain
	(*CIDR)(nil),                    // 3: v2ray.core.app.router.CIDR
	(*GeoIP)(nil),                   // 4: v2ray.core.app.router.GeoIP
	(*GeoIPList)(nil),               // 5: v2ray.core.app.router.GeoIPList
	(*GeoSite)(nil),                 // 6: v2ray.core.app.router.GeoSite
	(*GeoSiteList)(nil),             // 7: v2ray.core.app.router.GeoSiteList
	(*RoutingRule)(nil),             // 8: v2ray.core.app.router.RoutingRule
	(*BalancingRule)(nil),           // 9: v2ray.core.app.router.BalancingRule
	(*StrategyWeight)(nil),          // 10: v2ray.core.app.router.StrategyWeight
	(*StrategyRandomConfig)(nil),    // 11: v2ray.core.app.router.StrategyRandomConfig
	(*StrategyLeastPingConfig)(nil), // 12: v2ray.core.app.router.StrategyLeastPingConfig
	(*StrategyLeastLoadConfig)(nil), // 13: v2ray.core.app.router.StrategyLeastLoadConfig
	(*Config)(nil),                  // 14: v2ray.core.app.router.Config
	(*Domain_Attribute)(nil),        // 15: v2ray.core.app.router.Domain.Attribute
	(*net.PortRange)(nil),           // 16: v2ray.core.common.net.PortRange
	(*net.PortList)(nil),            // 17: v2ray.core.common.net.PortList
	(*net.NetworkList)(nil),         // 18: v2ray.core.common.net.NetworkList
	(net.Network)(0),                // 19: v2ray.core.common.net.Network
	(*serial.TypedMessage)(nil),     // 20: v2ray.core.common.serial.TypedMessage
}
var file_app_router_config_proto_depIdxs = []int32{
	0,  // 0: v2ray.core.app.router.Domain.type:type_name -> v2ray.core.app.router.Domain.Type
	15, // 1: v2ray.core.app.router.Domain.attribute:type_name -> v2ray.core.app.router.Domain.Attribute
	3,  // 2: v2ray.core.app.router.GeoIP.cidr:type_name -> v2ray.core.app.router.CIDR
	4,  // 3: v2ray.core.app.router.GeoIPList.entry:type_name -> v2ray.core.app.router.GeoIP
	2,  // 4: v2ray.core.app.router.GeoSite.domain:type_name -> v2ray.core.app.router.Domain
	6,  // 5: v2ray.core.app.router.GeoSiteList.entry:type_name -> v2ray.core.app.router.GeoSite
	2,  // 6: v2ray.core.app.router.RoutingRule.domain:type_name -> v2ray.core.app.router.Domain
	3,  // 7: v2ray.core.app.router.RoutingRule.cidr:type_name -> v2ray.core.app.router.CIDR
	4,  // 8: v2ray.core.app.router.RoutingRule.geoip:type_name -> v2ray.core.app.router.GeoIP
	16, // 9: v2ray.core.app.router.RoutingRule.port_range:type_name -> v2ray.core.common.net.PortRange
	17, // 10: v2ray.core.app.router.RoutingRule.port_list:type_name -> v2ray.core.common.net.PortList
	18, // 11: v2ray.core.app.router.RoutingRule.network_list:type_name -> v2ray.core.common.net.NetworkList
	19, // 12: v2ray.core.app.router.RoutingRule.networks:type_name -> v2ray.core.common.net.Network
	3,  // 13: v2ray.core.app.router.RoutingRule.source_cidr:type_name -> v2ray.core.app.router.CIDR
	4,  // 14: v2ray.core.app.router.RoutingRule.source_geoip:type_name -> v2ray.core.app.router.GeoIP
	17, // 15: v2ray.core.app.router.RoutingRule.source_port_list:type_name -> v2ray.core.common.net.PortList
	20, // 16: v2ray.core.app.router.BalancingRule.strategy_settings:type_name -> v2ray.core.common.serial.TypedMessage
	10, // 17: v2ray.core.app.router.StrategyLeastLoadConfig.costs:type_name -> v2ray.core.app.router.StrategyWeight
	1,  // 18: v2ray.core.app.router.Config.domain_strategy:type_name -> v2ray.core.app.router.Config.DomainStrategy
	8,  // 19: v2ray.core.app.router.Config.rule:type_name -> v2ray.core.app.router.RoutingRule
	9,  // 20: v2ray.core.app.router.Config.balancing_rule:type_name -> v2ray.core.app.router.BalancingRule
	21, // [21:21] is the sub-list for method output_type
	21, // [21:21] is the sub-list for method input_type
	21, // [21:21] is the sub-list for extension type_name
	21, // [21:21] is the sub-list for extension extendee
	0,  // [0:21] is the sub-list for field type_name
}

func init() { file_app_router_config_proto_init() }
func file_app_router_config_proto_init() {
	if File_app_router_config_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_app_router_config_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Domain); i {
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
		file_app_router_config_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CIDR); i {
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
		file_app_router_config_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GeoIP); i {
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
		file_app_router_config_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GeoIPList); i {
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
		file_app_router_config_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GeoSite); i {
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
		file_app_router_config_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GeoSiteList); i {
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
		file_app_router_config_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RoutingRule); i {
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
		file_app_router_config_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*BalancingRule); i {
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
		file_app_router_config_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*StrategyWeight); i {
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
		file_app_router_config_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*StrategyRandomConfig); i {
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
		file_app_router_config_proto_msgTypes[10].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*StrategyLeastPingConfig); i {
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
		file_app_router_config_proto_msgTypes[11].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*StrategyLeastLoadConfig); i {
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
		file_app_router_config_proto_msgTypes[12].Exporter = func(v interface{}, i int) interface{} {
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
		file_app_router_config_proto_msgTypes[13].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Domain_Attribute); i {
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
	file_app_router_config_proto_msgTypes[6].OneofWrappers = []interface{}{
		(*RoutingRule_Tag)(nil),
		(*RoutingRule_BalancingTag)(nil),
	}
	file_app_router_config_proto_msgTypes[13].OneofWrappers = []interface{}{
		(*Domain_Attribute_BoolValue)(nil),
		(*Domain_Attribute_IntValue)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_app_router_config_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   14,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_app_router_config_proto_goTypes,
		DependencyIndexes: file_app_router_config_proto_depIdxs,
		EnumInfos:         file_app_router_config_proto_enumTypes,
		MessageInfos:      file_app_router_config_proto_msgTypes,
	}.Build()
	File_app_router_config_proto = out.File
	file_app_router_config_proto_rawDesc = nil
	file_app_router_config_proto_goTypes = nil
	file_app_router_config_proto_depIdxs = nil
}
