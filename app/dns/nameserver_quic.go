package dns

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/url"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/buf"
	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/net/cnc"
	"github.com/v2fly/v2ray-core/v5/common/protocol/dns"
	"github.com/v2fly/v2ray-core/v5/common/session"
	"github.com/v2fly/v2ray-core/v5/common/signal/pubsub"
	"github.com/v2fly/v2ray-core/v5/common/task"
	dns_feature "github.com/v2fly/v2ray-core/v5/features/dns"
	"github.com/v2fly/v2ray-core/v5/features/routing"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
	"github.com/v2fly/v2ray-core/v5/transport/internet/tls"
)

// NextProtoDQ - During connection establishment, DNS/QUIC support is indicated
// by selecting the ALPN token "doq" in the crypto handshake.
const NextProtoDQ = "doq"

const handshakeIdleTimeout = time.Second * 8

// QUICNameServer implemented DNS over QUIC
type QUICNameServer struct {
	sync.RWMutex
	ips         map[string]record
	pub         *pubsub.Service
	cleanup     *task.Periodic
	name        string
	destination net.Destination
	connection  quic.EarlyConnection
	dispatcher  routing.Dispatcher
}

// NewQUICRemoteNameServer creates DNS-over-QUIC client object for remote resolving
func NewQUICRemoteNameServer(url *url.URL, dispatcher routing.Dispatcher) (*QUICNameServer, error) {
	newError("DNS: created Remote DNS-over-QUIC client for ", url.String()).AtInfo().WriteToLog()

	var err error
	port := net.Port(853)
	if url.Port() != "" {
		port, err = net.PortFromString(url.Port())
		if err != nil {
			return nil, err
		}
	}
	dest := net.UDPDestination(net.ParseAddress(url.Hostname()), port)

	s := &QUICNameServer{
		ips:         make(map[string]record),
		pub:         pubsub.NewService(),
		name:        url.String(),
		destination: dest,
		dispatcher:  dispatcher,
	}
	s.cleanup = &task.Periodic{
		Interval: time.Minute,
		Execute:  s.Cleanup,
	}

	return s, nil
}

// NewQUICNameServer creates DNS-over-QUIC client object for local resolving
func NewQUICNameServer(url *url.URL) (*QUICNameServer, error) {
	newError("DNS: created Local DNS-over-QUIC client for ", url.String()).AtInfo().WriteToLog()

	var err error
	port := net.Port(853)
	if url.Port() != "" {
		port, err = net.PortFromString(url.Port())
		if err != nil {
			return nil, err
		}
	}
	dest := net.UDPDestination(net.ParseAddress(url.Hostname()), port)

	s := &QUICNameServer{
		ips:         make(map[string]record),
		pub:         pubsub.NewService(),
		name:        url.String(),
		destination: dest,
	}
	s.cleanup = &task.Periodic{
		Interval: time.Minute,
		Execute:  s.Cleanup,
	}

	return s, nil
}

// Name returns client name
func (s *QUICNameServer) Name() string {
	return s.name
}

// Cleanup clears expired items from cache
func (s *QUICNameServer) Cleanup() error {
	now := time.Now()
	s.Lock()
	defer s.Unlock()

	if len(s.ips) == 0 {
		return newError("nothing to do. stopping...")
	}

	for domain, record := range s.ips {
		if record.A != nil && record.A.Expire.Before(now) {
			record.A = nil
		}
		if record.AAAA != nil && record.AAAA.Expire.Before(now) {
			record.AAAA = nil
		}

		if record.A == nil && record.AAAA == nil {
			newError(s.name, " cleanup ", domain).AtDebug().WriteToLog()
			delete(s.ips, domain)
		} else {
			s.ips[domain] = record
		}
	}

	if len(s.ips) == 0 {
		s.ips = make(map[string]record)
	}

	return nil
}

func (s *QUICNameServer) updateIP(req *dnsRequest, ipRec *IPRecord) {
	elapsed := time.Since(req.start)

	s.Lock()
	rec := s.ips[req.domain]
	updated := false

	switch req.reqType {
	case dnsmessage.TypeA:
		if isNewer(rec.A, ipRec) {
			rec.A = ipRec
			updated = true
		}
	case dnsmessage.TypeAAAA:
		addr := make([]net.Address, 0)
		for _, ip := range ipRec.IP {
			if len(ip.IP()) == net.IPv6len {
				addr = append(addr, ip)
			}
		}
		ipRec.IP = addr
		if isNewer(rec.AAAA, ipRec) {
			rec.AAAA = ipRec
			updated = true
		}
	}
	newError(s.name, " got answer: ", req.domain, " ", req.reqType, " -> ", ipRec.IP, " ", elapsed).AtInfo().WriteToLog()

	if updated {
		s.ips[req.domain] = rec
	}
	switch req.reqType {
	case dnsmessage.TypeA:
		s.pub.Publish(req.domain+"4", nil)
	case dnsmessage.TypeAAAA:
		s.pub.Publish(req.domain+"6", nil)
	}
	s.Unlock()
	common.Must(s.cleanup.Start())
}

func (s *QUICNameServer) NewReqID() uint16 {
	return 0
}

func (s *QUICNameServer) sendQuery(ctx context.Context, domain string, clientIP net.IP, option dns_feature.IPOption) {
	newError(s.name, " querying: ", domain).AtInfo().WriteToLog(session.ExportIDToError(ctx))

	reqs := buildReqMsgs(domain, option, s.NewReqID, genEDNS0Options(clientIP))

	var deadline time.Time
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	} else {
		deadline = time.Now().Add(time.Second * 5)
	}

	for _, req := range reqs {
		go func(r *dnsRequest) {
			// generate new context for each req, using same context
			// may cause reqs all aborted if any one encounter an error
			dnsCtx := ctx

			// reserve internal dns server requested Inbound
			if inbound := session.InboundFromContext(ctx); inbound != nil {
				dnsCtx = session.ContextWithInbound(dnsCtx, inbound)
			}

			dnsCtx = session.ContextWithContent(dnsCtx, &session.Content{
				Protocol:       "quic",
				SkipDNSResolve: true,
			})

			var cancel context.CancelFunc
			dnsCtx, cancel = context.WithDeadline(dnsCtx, deadline)
			defer cancel()

			b, err := dns.PackMessage(r.msg)
			if err != nil {
				newError("failed to pack dns query").Base(err).AtError().WriteToLog()
				return
			}

			dnsReqBuf := buf.New()
			binary.Write(dnsReqBuf, binary.BigEndian, uint16(b.Len()))
			dnsReqBuf.Write(b.Bytes())
			b.Release()

			conn, err := s.openStream(dnsCtx)
			if err != nil {
				newError("failed to open quic connection").Base(err).AtError().WriteToLog()
				return
			}

			_, err = conn.Write(dnsReqBuf.Bytes())
			if err != nil {
				newError("failed to send query").Base(err).AtError().WriteToLog()
				return
			}

			_ = conn.Close()

			respBuf := buf.New()
			defer respBuf.Release()
			n, err := respBuf.ReadFullFrom(conn, 2)
			if err != nil && n == 0 {
				newError("failed to read response length").Base(err).AtError().WriteToLog()
				return
			}
			var length int16
			err = binary.Read(bytes.NewReader(respBuf.Bytes()), binary.BigEndian, &length)
			if err != nil {
				newError("failed to parse response length").Base(err).AtError().WriteToLog()
				return
			}
			respBuf.Clear()
			n, err = respBuf.ReadFullFrom(conn, int32(length))
			if err != nil && n == 0 {
				newError("failed to read response length").Base(err).AtError().WriteToLog()
				return
			}

			rec, err := parseResponse(respBuf.Bytes())
			if err != nil {
				newError("failed to handle response").Base(err).AtError().WriteToLog()
				return
			}
			s.updateIP(r, rec)
		}(req)
	}
}

func (s *QUICNameServer) QueryRaw(ctx context.Context, request []byte) ([]byte, error) {
	var deadline time.Time
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	} else {
		deadline = time.Now().Add(time.Second * 5)
	}
	dnsCtx := ctx
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		dnsCtx = session.ContextWithInbound(dnsCtx, inbound)
	}
	dnsCtx = session.ContextWithContent(dnsCtx, &session.Content{
		Protocol:       "quic",
		SkipDNSResolve: true,
	})
	var cancel context.CancelFunc
	dnsCtx, cancel = context.WithDeadline(dnsCtx, deadline)
	defer cancel()
	requestBuf := buf.New()
	defer requestBuf.Release()
	binary.Write(requestBuf, binary.BigEndian, uint16(len(request)))
	requestBuf.Write(request)
	responseBuf := buf.New()
	defer responseBuf.Release()
	done := make(chan interface{})
	var retErr error
	go func() {
		defer close(done)
		conn, err := s.openStream(dnsCtx)
		if err != nil {
			retErr = newError("failed to open quic connection")
			return
		}
		_, err = conn.Write(requestBuf.Bytes())
		if err != nil {
			retErr = newError("failed to send query")
			return
		}
		_ = conn.Close()
		n, err := responseBuf.ReadFullFrom(conn, 2)
		if err != nil && n == 0 {
			retErr = newError("failed to read response length").Base(err)
			return
		}
		var length int16
		err = binary.Read(bytes.NewReader(responseBuf.Bytes()), binary.BigEndian, &length)
		if err != nil {
			retErr = newError("failed to parse response length").Base(err)
			return
		}
		responseBuf.Clear()
		n, err = responseBuf.ReadFullFrom(conn, int32(length))
		if err != nil && n == 0 {
			retErr = newError("failed to read response length").Base(err)
			return
		}
	}()
	select {
	case <-dnsCtx.Done():
		return nil, dnsCtx.Err()
	case <-done:
		return responseBuf.Bytes(), retErr
	}
}

func (s *QUICNameServer) findIPsForDomain(domain string, option dns_feature.IPOption) ([]net.IP, uint32, time.Time, error) {
	s.RLock()
	record, found := s.ips[domain]
	s.RUnlock()

	if !found {
		return nil, 0, time.Time{}, errRecordNotFound
	}

	var ips, a, aaaa []net.Address
	var ttl uint32
	var expireAt time.Time
	var err, lastErr error
	updated := false
	if option.IPv4Enable {
		a, ttl, expireAt, err = record.A.getIPsAndTTL()
		if ttl == 0 {
			record.A = nil
			updated = true
		}
		if err != nil {
			lastErr = err
		}
		ips = append(ips, a...)
	}

	if option.IPv6Enable {
		aaaa, ttl, expireAt, err = record.AAAA.getIPsAndTTL()
		if ttl == 0 {
			record.AAAA = nil
			updated = true
		}
		if err != nil {
			lastErr = err
		}
		ips = append(ips, aaaa...)
	}

	if updated {
		s.Lock()
		s.ips[domain] = record
		s.Unlock()
	}

	if len(ips) > 0 {
		ips, err := toNetIP(ips)
		return ips, ttl, expireAt, err
	}

	if lastErr != nil {
		return nil, ttl, expireAt, lastErr
	}

	return nil, ttl, expireAt, dns_feature.ErrEmptyResponse
}

// QueryIPWithTTL is called from dns.ServerWithTTL->queryIPTimeout
func (s *QUICNameServer) QueryIPWithTTL(ctx context.Context, domain string, clientIP net.IP, option dns_feature.IPOption, disableCache bool) ([]net.IP, uint32, time.Time, error) {
	fqdn := Fqdn(domain)

	if disableCache {
		newError("DNS cache is disabled. Querying IP for ", domain, " at ", s.name).AtDebug().WriteToLog()
	} else {
		ips, ttl, expireAt, err := s.findIPsForDomain(fqdn, option)
		if err != errRecordNotFound {
			newError(s.name, " cache HIT ", domain, " -> ", ips).Base(err).AtDebug().WriteToLog()
			return ips, ttl, expireAt, err
		}
	}

	// ipv4 and ipv6 belong to different subscription groups
	var sub4, sub6 *pubsub.Subscriber
	if option.IPv4Enable {
		sub4 = s.pub.Subscribe(fqdn + "4")
		defer sub4.Close()
	}
	if option.IPv6Enable {
		sub6 = s.pub.Subscribe(fqdn + "6")
		defer sub6.Close()
	}
	done := make(chan interface{})
	go func() {
		if sub4 != nil {
			select {
			case <-sub4.Wait():
			case <-ctx.Done():
			}
		}
		if sub6 != nil {
			select {
			case <-sub6.Wait():
			case <-ctx.Done():
			}
		}
		close(done)
	}()
	s.sendQuery(ctx, fqdn, clientIP, option)

	for {
		ips, ttl, expireAt, err := s.findIPsForDomain(fqdn, option)
		if err != errRecordNotFound {
			return ips, ttl, expireAt, err
		}

		select {
		case <-ctx.Done():
			return nil, ttl, expireAt, ctx.Err()
		case <-done:
		}
	}
}

// QueryIP is called from dns.Server->queryIPTimeout
func (s *QUICNameServer) QueryIP(ctx context.Context, domain string, clientIP net.IP, option dns_feature.IPOption, disableCache bool) ([]net.IP, error) {
	ips, _, _, err := s.QueryIPWithTTL(ctx, domain, clientIP, option, disableCache)
	return ips, err
}

func isActive(s quic.EarlyConnection) bool {
	select {
	case <-s.Context().Done():
		return false
	default:
		return true
	}
}

func (s *QUICNameServer) getConnection(ctx context.Context) (quic.EarlyConnection, error) {
	var conn quic.EarlyConnection
	s.RLock()
	conn = s.connection
	if conn != nil && isActive(conn) {
		s.RUnlock()
		return conn, nil
	}
	if conn != nil {
		// we're recreating the connection, let's create a new one
		_ = conn.CloseWithError(0, "")
	}
	s.RUnlock()

	s.Lock()
	defer s.Unlock()

	var err error
	conn, err = s.openConnection(ctx)
	if err != nil {
		// This does not look too nice, but QUIC (or maybe quic-go)
		// doesn't seem stable enough.
		// Maybe retransmissions aren't fully implemented in quic-go?
		// Anyways, the simple solution is to make a second try when
		// it fails to open the QUIC connection.
		conn, err = s.openConnection(ctx)
		if err != nil {
			return nil, err
		}
	}
	s.connection = conn
	return conn, nil
}

func (s *QUICNameServer) openConnection(ctx context.Context) (quic.EarlyConnection, error) {
	tlsConfig := tls.Config{
		ServerName: func() string {
			switch s.destination.Address.Family() {
			case net.AddressFamilyIPv4, net.AddressFamilyIPv6:
				return s.destination.Address.IP().String()
			case net.AddressFamilyDomain:
				return s.destination.Address.Domain()
			default:
				panic("unknown address family")
			}
		}(),
	}
	quicConfig := &quic.Config{
		HandshakeIdleTimeout: handshakeIdleTimeout,
	}

	if s.dispatcher != nil {
		link, err := s.dispatcher.Dispatch(ctx, s.destination)
		if err != nil {
			return nil, err
		}
		rawConn := cnc.NewConnection(
			cnc.ConnectionInputMulti(link.Writer),
			cnc.ConnectionOutputMultiUDP(link.Reader),
		)

		return quic.DialEarly(ctx, internet.NewConnWrapper(rawConn), rawConn.RemoteAddr(), tlsConfig.GetTLSConfig(tls.WithNextProto(NextProtoDQ)), quicConfig)
	}

	rawConn, err := internet.DialSystem(ctx, s.destination, nil)
	if err != nil {
		return nil, err
	}
	var pc net.PacketConn
	switch rc := rawConn.(type) {
	case *internet.PacketConnWrapper:
		pc = rc.Conn
	case net.PacketConn:
		pc = rc
	default:
		pc = internet.NewConnWrapper(rc)
	}
	return quic.DialEarly(ctx, pc, rawConn.RemoteAddr(), tlsConfig.GetTLSConfig(tls.WithNextProto(NextProtoDQ)), quicConfig)
}

func (s *QUICNameServer) openStream(ctx context.Context) (quic.Stream, error) {
	conn, err := s.getConnection(ctx)
	if err != nil {
		return nil, err
	}

	// open a new stream
	return conn.OpenStreamSync(ctx)
}
