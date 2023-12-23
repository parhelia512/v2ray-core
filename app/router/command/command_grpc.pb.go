package command

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	RoutingService_SubscribeRoutingStats_FullMethodName  = "/v2ray.core.app.router.command.RoutingService/SubscribeRoutingStats"
	RoutingService_TestRoute_FullMethodName              = "/v2ray.core.app.router.command.RoutingService/TestRoute"
	RoutingService_GetBalancerInfo_FullMethodName        = "/v2ray.core.app.router.command.RoutingService/GetBalancerInfo"
	RoutingService_OverrideBalancerTarget_FullMethodName = "/v2ray.core.app.router.command.RoutingService/OverrideBalancerTarget"
)

// RoutingServiceClient is the client API for RoutingService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type RoutingServiceClient interface {
	SubscribeRoutingStats(ctx context.Context, in *SubscribeRoutingStatsRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[RoutingContext], error)
	TestRoute(ctx context.Context, in *TestRouteRequest, opts ...grpc.CallOption) (*RoutingContext, error)
	GetBalancerInfo(ctx context.Context, in *GetBalancerInfoRequest, opts ...grpc.CallOption) (*GetBalancerInfoResponse, error)
	OverrideBalancerTarget(ctx context.Context, in *OverrideBalancerTargetRequest, opts ...grpc.CallOption) (*OverrideBalancerTargetResponse, error)
}

type routingServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewRoutingServiceClient(cc grpc.ClientConnInterface) RoutingServiceClient {
	return &routingServiceClient{cc}
}

func (c *routingServiceClient) SubscribeRoutingStats(ctx context.Context, in *SubscribeRoutingStatsRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[RoutingContext], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &RoutingService_ServiceDesc.Streams[0], RoutingService_SubscribeRoutingStats_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[SubscribeRoutingStatsRequest, RoutingContext]{ClientStream: stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type RoutingService_SubscribeRoutingStatsClient = grpc.ServerStreamingClient[RoutingContext]

func (c *routingServiceClient) TestRoute(ctx context.Context, in *TestRouteRequest, opts ...grpc.CallOption) (*RoutingContext, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(RoutingContext)
	err := c.cc.Invoke(ctx, RoutingService_TestRoute_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *routingServiceClient) GetBalancerInfo(ctx context.Context, in *GetBalancerInfoRequest, opts ...grpc.CallOption) (*GetBalancerInfoResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(GetBalancerInfoResponse)
	err := c.cc.Invoke(ctx, RoutingService_GetBalancerInfo_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *routingServiceClient) OverrideBalancerTarget(ctx context.Context, in *OverrideBalancerTargetRequest, opts ...grpc.CallOption) (*OverrideBalancerTargetResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(OverrideBalancerTargetResponse)
	err := c.cc.Invoke(ctx, RoutingService_OverrideBalancerTarget_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RoutingServiceServer is the server API for RoutingService service.
// All implementations must embed UnimplementedRoutingServiceServer
// for forward compatibility.
type RoutingServiceServer interface {
	SubscribeRoutingStats(*SubscribeRoutingStatsRequest, grpc.ServerStreamingServer[RoutingContext]) error
	TestRoute(context.Context, *TestRouteRequest) (*RoutingContext, error)
	GetBalancerInfo(context.Context, *GetBalancerInfoRequest) (*GetBalancerInfoResponse, error)
	OverrideBalancerTarget(context.Context, *OverrideBalancerTargetRequest) (*OverrideBalancerTargetResponse, error)
	mustEmbedUnimplementedRoutingServiceServer()
}

// UnimplementedRoutingServiceServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedRoutingServiceServer struct{}

func (UnimplementedRoutingServiceServer) SubscribeRoutingStats(*SubscribeRoutingStatsRequest, grpc.ServerStreamingServer[RoutingContext]) error {
	return status.Errorf(codes.Unimplemented, "method SubscribeRoutingStats not implemented")
}
func (UnimplementedRoutingServiceServer) TestRoute(context.Context, *TestRouteRequest) (*RoutingContext, error) {
	return nil, status.Errorf(codes.Unimplemented, "method TestRoute not implemented")
}
func (UnimplementedRoutingServiceServer) GetBalancerInfo(context.Context, *GetBalancerInfoRequest) (*GetBalancerInfoResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetBalancerInfo not implemented")
}
func (UnimplementedRoutingServiceServer) OverrideBalancerTarget(context.Context, *OverrideBalancerTargetRequest) (*OverrideBalancerTargetResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method OverrideBalancerTarget not implemented")
}
func (UnimplementedRoutingServiceServer) mustEmbedUnimplementedRoutingServiceServer() {}
func (UnimplementedRoutingServiceServer) testEmbeddedByValue()                        {}

// UnsafeRoutingServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to RoutingServiceServer will
// result in compilation errors.
type UnsafeRoutingServiceServer interface {
	mustEmbedUnimplementedRoutingServiceServer()
}

func RegisterRoutingServiceServer(s grpc.ServiceRegistrar, srv RoutingServiceServer) {
	// If the following call pancis, it indicates UnimplementedRoutingServiceServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&RoutingService_ServiceDesc, srv)
}

func _RoutingService_SubscribeRoutingStats_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(SubscribeRoutingStatsRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(RoutingServiceServer).SubscribeRoutingStats(m, &grpc.GenericServerStream[SubscribeRoutingStatsRequest, RoutingContext]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type RoutingService_SubscribeRoutingStatsServer = grpc.ServerStreamingServer[RoutingContext]

func _RoutingService_TestRoute_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(TestRouteRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RoutingServiceServer).TestRoute(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: RoutingService_TestRoute_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RoutingServiceServer).TestRoute(ctx, req.(*TestRouteRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _RoutingService_GetBalancerInfo_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetBalancerInfoRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RoutingServiceServer).GetBalancerInfo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: RoutingService_GetBalancerInfo_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RoutingServiceServer).GetBalancerInfo(ctx, req.(*GetBalancerInfoRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _RoutingService_OverrideBalancerTarget_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(OverrideBalancerTargetRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RoutingServiceServer).OverrideBalancerTarget(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: RoutingService_OverrideBalancerTarget_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RoutingServiceServer).OverrideBalancerTarget(ctx, req.(*OverrideBalancerTargetRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// RoutingService_ServiceDesc is the grpc.ServiceDesc for RoutingService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var RoutingService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "v2ray.core.app.router.command.RoutingService",
	HandlerType: (*RoutingServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "TestRoute",
			Handler:    _RoutingService_TestRoute_Handler,
		},
		{
			MethodName: "GetBalancerInfo",
			Handler:    _RoutingService_GetBalancerInfo_Handler,
		},
		{
			MethodName: "OverrideBalancerTarget",
			Handler:    _RoutingService_OverrideBalancerTarget_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "SubscribeRoutingStats",
			Handler:       _RoutingService_SubscribeRoutingStats_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "app/router/command/command.proto",
}
