package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/dns/dnsmessage"

	core "github.com/v2fly/v2ray-core/v5"
	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/net/cnc"
	"github.com/v2fly/v2ray-core/v5/common/protocol/dns"
	"github.com/v2fly/v2ray-core/v5/common/session"
	"github.com/v2fly/v2ray-core/v5/common/signal/pubsub"
	"github.com/v2fly/v2ray-core/v5/common/task"
	"github.com/v2fly/v2ray-core/v5/common/uuid"
	dns_feature "github.com/v2fly/v2ray-core/v5/features/dns"
	"github.com/v2fly/v2ray-core/v5/features/routing"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
)

type H3NameServer struct {
	sync.RWMutex
	ips        map[string]record
	pub        *pubsub.Service
	cleanup    *task.Periodic
	dispatcher routing.Dispatcher
	httpClient *http.Client
	dohURL     string
	name       string
}

// NewH3NameServer creates H3 server object for remote resolving.
func NewH3NameServer(url *url.URL, dispatcher routing.Dispatcher) (*H3NameServer, error) {
	url.Scheme = "https"
	s := &H3NameServer{
		ips:        make(map[string]record),
		pub:        pubsub.NewService(),
		name:       "H3//" + url.Host,
		dohURL:     url.String(),
		dispatcher: dispatcher,
	}
	s.cleanup = &task.Periodic{
		Interval: time.Minute,
		Execute:  s.Cleanup,
	}
	s.httpClient = s.setupH3Client()
	newError("DNS: created Remote H3 client for ", url.String()).AtInfo().WriteToLog()
	return s, nil
}

// NewH3LocalNameServer creates H3 client object for local resolving
func NewH3LocalNameServer(url *url.URL) *H3NameServer {
	url.Scheme = "https"
	s := &H3NameServer{
		ips:    make(map[string]record),
		pub:    pubsub.NewService(),
		name:   "H3L//" + url.Host,
		dohURL: url.String(),
	}
	s.cleanup = &task.Periodic{
		Interval: time.Minute,
		Execute:  s.Cleanup,
	}
	s.httpClient = s.setupH3Client()
	newError("DNS: created Local H3 client for ", url.String()).AtInfo().WriteToLog()
	return s
}

// Name implements Server.
func (s *H3NameServer) Name() string {
	return s.name
}

// Cleanup clears expired items from cache
func (s *H3NameServer) Cleanup() error {
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

func (s *H3NameServer) updateIP(req *dnsRequest, ipRec *IPRecord) {
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

func (s *H3NameServer) newReqID() uint16 {
	return 0
}

func (s *H3NameServer) sendQuery(ctx context.Context, domain string, clientIP net.IP, option dns_feature.IPOption) {
	newError(s.name, " querying: ", domain).AtInfo().WriteToLog(session.ExportIDToError(ctx))

	reqs := buildReqMsgs(domain, option, s.newReqID, genEDNS0Options(clientIP))

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
			resp, err := s.dohHTTPSContext(dnsCtx, b.Bytes())
			if err != nil {
				newError("failed to retrieve response").Base(err).AtError().WriteToLog()
				return
			}
			rec, err := parseResponse(resp)
			if err != nil {
				newError("failed to handle H3 response").Base(err).AtError().WriteToLog()
				return
			}
			s.updateIP(r, rec)
		}(req)
	}
}

func (s *H3NameServer) dohHTTPSContext(dnsCtx context.Context, b []byte) ([]byte, error) {
	body := bytes.NewBuffer(b)
	req, err := http.NewRequest("POST", s.dohURL, body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Accept", "application/dns-message")
	req.Header.Add("Content-Type", "application/dns-message")

	resp, err := s.httpClient.Do(req.WithContext(dnsCtx))
	if err != nil {
		// quic-go issue?
		if !errors.Is(err, context.Canceled) {
			s.Lock()
			s.httpClient = s.setupH3Client()
			s.Unlock()
		}
		resp, err = s.httpClient.Do(req.WithContext(dnsCtx))
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body) // flush resp.Body so that the conn is reusable
		return nil, fmt.Errorf("H3 server returned code %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

func (s *H3NameServer) setupH3Client() *http.Client {
	return &http.Client{
		Transport: &http3.RoundTripper{
			Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
				dest, err := net.ParseDestination("udp:" + addr)
				if err != nil {
					return nil, err
				}
				var conn net.Conn
				if s.dispatcher != nil {
					ctx = core.ToBackgroundDetachedContext(ctx)
					link, err := s.dispatcher.Dispatch(ctx, dest)
					if err != nil {
						return nil, err
					}
					conn = cnc.NewConnection(
						cnc.ConnectionInputMulti(link.Writer),
						cnc.ConnectionOutputMultiUDP(link.Reader),
					)
				} else {
					conn, err = internet.DialSystemDNS(ctx, dest, nil)
					if err != nil {
						return nil, err
					}
				}
				tr := quic.Transport{
					Conn: NewConnWrapper(conn),
				}
				return tr.DialEarly(ctx, conn.RemoteAddr(), tlsCfg, cfg)
			},
		},
	}
}

func (s *H3NameServer) findIPsForDomain(domain string, option dns_feature.IPOption) ([]net.IP, uint32, time.Time, error) {
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
	if option.IPv4Enable {
		a, ttl, expireAt, err = record.A.getIPsAndTTL()
		if err != nil {
			lastErr = err
		}
		ips = append(ips, a...)
	}

	if option.IPv6Enable {
		aaaa, ttl, expireAt, err = record.AAAA.getIPsAndTTL()
		if err != nil {
			lastErr = err
		}
		ips = append(ips, aaaa...)
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

// QueryIPWithTTL implements ServerWithTTL.
func (s *H3NameServer) QueryIPWithTTL(ctx context.Context, domain string, clientIP net.IP, option dns_feature.IPOption, disableCache bool) ([]net.IP, uint32, time.Time, error) { // nolint: dupl
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

// QueryIP implements Server.
func (s *H3NameServer) QueryIP(ctx context.Context, domain string, clientIP net.IP, option dns_feature.IPOption, disableCache bool) ([]net.IP, error) { // nolint: dupl
	ips, _, _, err := s.QueryIPWithTTL(ctx, domain, clientIP, option, disableCache)
	return ips, err
}

type connWrapper struct {
	net.Conn
	localAddr net.Addr
}

func (c *connWrapper) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = c.Read(p)
	return n, c.RemoteAddr(), err
}

func (c *connWrapper) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	return c.Write(p)
}

func NewConnWrapper(conn net.Conn) net.PacketConn {
	// https://github.com/quic-go/quic-go/commit/8189e75be6121fdc31dc1d6085f17015e9154667#diff-4c6aaadced390f3ce9bec0a9c9bb5203d5fa85df79023e3e0eec423dc9baa946R48-R62
	uuid := uuid.New()
	return &connWrapper{
		Conn:      conn,
		localAddr: &net.UnixAddr{Name: uuid.String()},
	}
}

func (c *connWrapper) LocalAddr() net.Addr {
	return c.localAddr
}
