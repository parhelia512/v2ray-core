//go:build go1.23

package tls

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/v2fly/v2ray-core/v4/common/net"
	"github.com/v2fly/v2ray-core/v4/transport/internet"
)

func applyECH(c *Config, config *tls.Config) error {
	if len(c.EchConfig) > 0 {
		config.EncryptedClientHelloConfigList = c.EchConfig
		newError("applied ECH config: ", base64.StdEncoding.EncodeToString(c.EchConfig)).AtDebug().WriteToLog()
		return nil
	}
	if len(c.EchDnsServer) > 0 {
		if len(config.ServerName) == 0 {
			return newError("missing server name")
		}
		echConfig, err := lookupECHConfig(config.ServerName, c.EchDnsServer)
		if err != nil {
			return err
		}
		if echConfig == nil {
			return newError("no ECH config found")
		}
		config.EncryptedClientHelloConfigList = echConfig
		newError("applied ECH config: ", base64.StdEncoding.EncodeToString(echConfig)).AtDebug().WriteToLog()
		return nil
	}
	return nil
}

type record struct {
	echConfig []byte
	expire    time.Time
}

var (
	echConfigCache = make(map[string]*record)
	mutex          sync.RWMutex
)

func lookupECHConfig(domain string, rawURL string) ([]byte, error) {
	mutex.RLock()
	rec, found := echConfigCache[domain]
	mutex.RUnlock()
	if found {
		if rec.expire.After(time.Now()) {
			return rec.echConfig, nil
		}
		mutex.Lock()
		delete(echConfigCache, domain)
		mutex.Unlock()
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeHTTPS)
	var respMsg *dns.Msg
	if u.Scheme == "tls" {
		port := net.Port(853)
		if len(u.Port()) > 0 {
			port, err = net.PortFromString(u.Port())
			if err != nil {
				return nil, err
			}
		}
		respMsg, err = dotExchange(msg, net.TCPDestination(net.ParseAddress(u.Hostname()), port))
	} else {
		msg.Id = 0
		respMsg, err = dohExchange(msg, u.String())
	}
	if err != nil {
		return nil, err
	}

	echConfig, ttl, err := parseMessage(respMsg, domain)
	if err != nil {
		return nil, err
	}
	if ttl > 0 {
		mutex.Lock()
		echConfigCache[domain] = &record{
			echConfig: echConfig,
			expire:    time.Now().Add(time.Second * time.Duration(ttl)),
		}
		mutex.Unlock()
	}
	return echConfig, nil
}

func dohExchange(msg *dns.Msg, url string) (*dns.Msg, error) {
	b, err := msg.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Accept", "application/dns-message")
	req.Header.Add("Content-Type", "application/dns-message")
	client := &http.Client{
		Timeout: 180 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        30,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 30 * time.Second,
			ForceAttemptHTTP2:   true,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dest, err := net.ParseDestination(network + ":" + addr)
				if err != nil {
					return nil, err
				}
				return internet.DialSystem(ctx, dest, nil) // FIXME: Use correct ctx
			},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return nil, newError("query failed with response code:", resp.StatusCode)
	}
	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(respBody); err != nil {
		return nil, err
	}
	return respMsg, nil
}

func dotExchange(msg *dns.Msg, dest net.Destination) (*dns.Msg, error) {
	conn, err := internet.DialSystem(context.Background(), dest, nil) // FIXME: Use correct ctx
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	dnsConn := &dns.Conn{
		Conn: tls.Client(conn, &tls.Config{
			NextProtos: []string{"dot"},
			ServerName: func() string {
				switch dest.Address.Family() {
				case net.AddressFamilyIPv4, net.AddressFamilyIPv6:
					return dest.Address.IP().String()
				case net.AddressFamilyDomain:
					return dest.Address.Domain()
				default:
					panic("unknown address family")
				}
			}(),
		}),
	}
	if err := dnsConn.WriteMsg(msg); err != nil {
		return nil, err
	}
	return dnsConn.ReadMsg()
}

func parseMessage(msg *dns.Msg, domain string) ([]byte, uint32, error) {
	for _, answer := range msg.Answer {
		if https, ok := answer.(*dns.HTTPS); ok && https.Hdr.Name == dns.Fqdn(domain) {
			for _, v := range https.Value {
				if echConfig, ok := v.(*dns.SVCBECHConfig); ok {
					return echConfig.ECH, answer.Header().Ttl, nil
				}
			}
		}
	}
	if len(msg.Answer) == 0 && msg.Rcode == dns.RcodeSuccess || msg.Rcode == dns.RcodeNameError {
		for _, ns := range msg.Ns {
			if soa, ok := ns.(*dns.SOA); ok {
				return nil, min(ns.Header().Ttl, soa.Minttl), nil
			}
		}
	}
	return nil, 0, newError("no ECH config found")
}
