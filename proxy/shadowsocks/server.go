package shadowsocks

import (
	"context"
	"time"

	core "github.com/v2fly/v2ray-core/v5"
	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/buf"
	"github.com/v2fly/v2ray-core/v5/common/log"
	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/net/packetaddr"
	"github.com/v2fly/v2ray-core/v5/common/protocol"
	udp_proto "github.com/v2fly/v2ray-core/v5/common/protocol/udp"
	"github.com/v2fly/v2ray-core/v5/common/session"
	"github.com/v2fly/v2ray-core/v5/common/signal"
	"github.com/v2fly/v2ray-core/v5/common/task"
	"github.com/v2fly/v2ray-core/v5/features/policy"
	"github.com/v2fly/v2ray-core/v5/features/routing"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
	"github.com/v2fly/v2ray-core/v5/transport/internet/udp"
)

type Server struct {
	config        *ServerConfig
	validator     Validator
	policyManager policy.Manager
}

// NewServer create a new Shadowsocks server.
func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	if len(config.GetUser()) == 0 {
		return nil, newError("user is not specified")
	}

	validatorConstructor := NewAEADValidator
	if user, err := config.User[0].ToMemoryUser(); err == nil {
		if !user.Account.(*MemoryAccount).Cipher.IsAEAD() {
			validatorConstructor = NewStreamValidator
		}
	} else {
		return nil, newError("failed to parse user account").Base(err)
	}

	validator := validatorConstructor()
	for _, user := range config.User {
		mUser, err := user.ToMemoryUser()
		if err != nil {
			return nil, newError("failed to parse user account").Base(err)
		}

		if err := validator.Add(mUser); err != nil {
			return nil, newError("failed to add user").Base(err)
		}
	}

	v := core.MustFromContext(ctx)
	s := &Server{
		config:        config,
		validator:     validator,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
	}

	return s, nil
}

func (s *Server) Network() []net.Network {
	list := s.config.Network
	if len(list) == 0 {
		list = append(list, net.Network_TCP)
	}
	if s.config.UdpEnabled {
		list = append(list, net.Network_UDP)
	}
	return list
}

// AddUser implements proxy.UserManager.AddUser().
func (s *Server) AddUser(ctx context.Context, user *protocol.MemoryUser) error {
	return s.validator.Add(user)
}

// RemoveUser implements proxy.UserManager.RemoveUser().
func (s *Server) RemoveUser(ctx context.Context, email string) error {
	return s.validator.Delete(email)
}

func (s *Server) Process(ctx context.Context, network net.Network, conn internet.Connection, dispatcher routing.Dispatcher) error {
	switch network {
	case net.Network_TCP:
		return s.handleConnection(ctx, conn, dispatcher)
	case net.Network_UDP:
		return s.handleUDPPayload(ctx, conn, dispatcher)
	default:
		return newError("unknown network: ", network)
	}
}

func (s *Server) handleUDPPayload(ctx context.Context, conn internet.Connection, dispatcher routing.Dispatcher) error {
	udpDispatcherConstructor := udp.NewSplitDispatcher
	switch s.config.PacketEncoding {
	case packetaddr.PacketAddrType_None:
		break
	case packetaddr.PacketAddrType_Packet:
		packetAddrDispatcherFactory := udp.NewPacketAddrDispatcherCreator(ctx)
		udpDispatcherConstructor = packetAddrDispatcherFactory.NewPacketAddrDispatcher
	}

	udpServer := udpDispatcherConstructor(dispatcher, func(ctx context.Context, packet *udp_proto.Packet) {
		var request *protocol.RequestHeader
		if packet.Source.IsValid() {
			request = &protocol.RequestHeader{
				Port:    packet.Source.Port,
				Address: packet.Source.Address,
			}
		} else {
			request = protocol.RequestHeaderFromContext(ctx)
			if request == nil {
				request = &protocol.RequestHeader{}
			}
		}

		payload := packet.Payload
		data, err := EncodeUDPPacket(request, payload.Bytes())
		payload.Release()
		if err != nil {
			newError("failed to encode UDP packet").Base(err).AtWarning().WriteToLog(session.ExportIDToError(ctx))
			return
		}
		defer data.Release()

		conn.Write(data.Bytes())
	})

	reader := buf.NewPacketReader(conn)
	for {
		mpayload, err := reader.ReadMultiBuffer()
		if err != nil {
			break
		}

		for _, payload := range mpayload {
			request, data, err := DecodeUDPPacket(s.validator, payload)
			if err != nil {
				if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.Source.IsValid() {
					newError("dropping invalid UDP packet from: ", inbound.Source).Base(err).WriteToLog(session.ExportIDToError(ctx))
					log.Record(&log.AccessMessage{
						From:   inbound.Source,
						To:     "",
						Status: log.AccessRejected,
						Reason: err,
					})
				}
				payload.Release()
				continue
			}

			inbound := session.InboundFromContext(ctx)
			if inbound == nil {
				panic("no inbound metadata")
			}
			inbound.User = request.User

			currentPacketCtx := ctx
			dest := request.Destination()
			if inbound.Source.IsValid() {
				currentPacketCtx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
					From:   inbound.Source,
					To:     dest,
					Status: log.AccessAccepted,
					Reason: "",
					Email:  request.User.Email,
				})
			}
			newError("tunnelling request to ", dest).WriteToLog(session.ExportIDToError(currentPacketCtx))

			currentPacketCtx = protocol.ContextWithRequestHeader(currentPacketCtx, request)
			udpServer.Dispatch(currentPacketCtx, dest, data)
		}
	}

	return nil
}

func (s *Server) handleConnection(ctx context.Context, conn internet.Connection, dispatcher routing.Dispatcher) error {
	sessionPolicy := s.policyManager.ForLevel(0)
	conn.SetReadDeadline(time.Now().Add(sessionPolicy.Timeouts.Handshake))

	bufferedReader := buf.BufferedReader{Reader: buf.NewReader(conn)}
	request, bodyReader, err := ReadTCPSession(s.validator, &bufferedReader)
	if err != nil {
		log.Record(&log.AccessMessage{
			From:   conn.RemoteAddr(),
			To:     "",
			Status: log.AccessRejected,
			Reason: err,
		})
		return newError("failed to create request from: ", conn.RemoteAddr()).Base(err)
	}
	conn.SetReadDeadline(time.Time{})

	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		panic("no inbound metadata")
	}
	inbound.User = request.User

	dest := request.Destination()
	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     dest,
		Status: log.AccessAccepted,
		Reason: "",
		Email:  request.User.Email,
	})
	newError("tunnelling request to ", dest).WriteToLog(session.ExportIDToError(ctx))

	sessionPolicy = s.policyManager.ForLevel(request.User.Level)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)

	ctx = policy.ContextWithBufferPolicy(ctx, sessionPolicy.Buffer)
	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return err
	}

	responseDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)

		bufferedWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
		responseWriter, err := WriteTCPResponse(request, bufferedWriter)
		if err != nil {
			return newError("failed to write response").Base(err)
		}

		{
			payload, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				return err
			}
			if err := responseWriter.WriteMultiBuffer(payload); err != nil {
				return err
			}
		}

		if err := bufferedWriter.SetBuffered(false); err != nil {
			return err
		}

		if err := buf.Copy(link.Reader, responseWriter, buf.UpdateActivity(timer)); err != nil {
			return newError("failed to transport all TCP response").Base(err)
		}

		return nil
	}

	requestDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)

		if err := buf.Copy(bodyReader, link.Writer, buf.UpdateActivity(timer)); err != nil {
			return newError("failed to transport all TCP request").Base(err)
		}

		return nil
	}

	requestDoneAndCloseWriter := task.OnSuccess(requestDone, task.Close(link.Writer))
	if err := task.Run(ctx, requestDoneAndCloseWriter, responseDone); err != nil {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		return newError("connection ends").Base(err)
	}

	return nil
}

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}
