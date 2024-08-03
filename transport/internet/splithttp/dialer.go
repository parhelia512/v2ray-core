package splithttp

import (
	"context"
	gotls "crypto/tls"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"

	core "github.com/v2fly/v2ray-core/v5"
	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/buf"
	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/session"
	"github.com/v2fly/v2ray-core/v5/common/signal/semaphore"
	"github.com/v2fly/v2ray-core/v5/common/uuid"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
	"github.com/v2fly/v2ray-core/v5/transport/internet/security"
	"github.com/v2fly/v2ray-core/v5/transport/internet/tls"
	"github.com/v2fly/v2ray-core/v5/transport/internet/tls/utls"
	"github.com/v2fly/v2ray-core/v5/transport/internet/transportcommon"
	"github.com/v2fly/v2ray-core/v5/transport/pipe"
)

type dialerConf struct {
	net.Destination
	*internet.MemoryStreamConfig
}

var (
	globalDialerMap    map[dialerConf]DialerClient
	globalDialerAccess sync.Mutex
)

func getHTTPClient(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) DialerClient {
	var tlsConfig *tls.Config
	switch cfg := streamSettings.SecuritySettings.(type) {
	case *tls.Config:
		tlsConfig = cfg
	case *utls.Config:
		tlsConfig = cfg.GetTlsConfig()
	}

	isH2 := tlsConfig != nil && !(len(tlsConfig.NextProtocol) == 1 && tlsConfig.NextProtocol[0] == "http/1.1")
	isH3 := tlsConfig != nil && len(tlsConfig.NextProtocol) == 1 && tlsConfig.NextProtocol[0] == "h3"

	globalDialerAccess.Lock()
	defer globalDialerAccess.Unlock()

	if globalDialerMap == nil {
		globalDialerMap = make(map[dialerConf]DialerClient)
	}

	if isH3 {
		dest.Network = net.Network_UDP
	}
	if client, found := globalDialerMap[dialerConf{dest, streamSettings}]; found {
		return client
	}

	dialContext := func(_ context.Context) (net.Conn, error) {
		return transportcommon.DialWithSecuritySettings(core.ToBackgroundDetachedContext(ctx), dest, streamSettings)
	}

	var uploadTransport http.RoundTripper
	var downloadTransport http.RoundTripper

	if isH3 {
		roundTripper := &http3.RoundTripper{
			TLSClientConfig: tlsConfig.GetTLSConfig(tls.WithDestination(dest)),
			Dial: func(_ context.Context, addr string, tlsCfg *gotls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
				conn, err := internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
				if err != nil {
					return nil, err
				}
				var udpConn net.PacketConn
				switch c := conn.(type) {
				case *net.UDPConn:
					udpConn = c
				case *internet.PacketConnWrapper:
					udpConn = c.Conn.(*net.UDPConn)
				default:
					udpConn = NewConnWrapper(conn)
				}
				tr := quic.Transport{
					Conn: udpConn,
				}
				return tr.DialEarly(ctx, conn.RemoteAddr(), tlsCfg, cfg)
			},
		}
		downloadTransport = roundTripper
		uploadTransport = roundTripper
	} else if isH2 {
		downloadTransport = &http2.Transport{
			DialTLSContext: func(ctxInner context.Context, network string, addr string, cfg *gotls.Config) (net.Conn, error) {
				return dialContext(ctxInner)
			},
			IdleConnTimeout: 90 * time.Second,
		}
		uploadTransport = downloadTransport
	} else {
		httpDialContext := func(ctxInner context.Context, network string, addr string) (net.Conn, error) {
			return dialContext(ctxInner)
		}

		downloadTransport = &http.Transport{
			DialTLSContext:  httpDialContext,
			DialContext:     httpDialContext,
			IdleConnTimeout: 90 * time.Second,
			// chunked transfer download with keepalives is buggy with
			// http.Client and our custom dial context.
			DisableKeepAlives: true,
		}

		// we use uploadRawPool for that
		uploadTransport = nil
	}

	client := &DefaultDialerClient{
		transportConfig: streamSettings.ProtocolSettings.(*Config),
		download: &http.Client{
			Transport: downloadTransport,
		},
		upload: &http.Client{
			Transport: uploadTransport,
		},
		isH2:           isH2,
		isH3:           isH3,
		uploadRawPool:  &sync.Pool{},
		dialUploadConn: dialContext,
	}

	if !isH3 {
		// XTLS/Xray-core@22535d8 introduced h3 dialer reuse but it is broken for trojan and vless. vmess is ok.
		globalDialerMap[dialerConf{dest, streamSettings}] = client
	}

	return client
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

func (c *connWrapper) LocalAddr() net.Addr {
	return c.localAddr
}

func NewConnWrapper(conn net.Conn) net.PacketConn {
	// https://github.com/quic-go/quic-go/commit/8189e75be6121fdc31dc1d6085f17015e9154667#diff-4c6aaadced390f3ce9bec0a9c9bb5203d5fa85df79023e3e0eec423dc9baa946R48-R62
	uuid := uuid.New()
	return &connWrapper{
		Conn:      conn,
		localAddr: &net.UnixAddr{Name: uuid.String()},
	}
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}

func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (internet.Connection, error) {
	newError("dialing splithttp to ", dest).WriteToLog(session.ExportIDToError(ctx))

	var requestURL url.URL

	transportConfiguration := streamSettings.ProtocolSettings.(*Config)

	if securityEngine, _ := security.CreateSecurityEngineFromSettings(ctx, streamSettings); securityEngine != nil {
		requestURL.Scheme = "https"
	} else {
		requestURL.Scheme = "http"
	}
	requestURL.Host = transportConfiguration.Host
	if requestURL.Host == "" {
		requestURL.Host = dest.NetAddr()
	}

	sessionIdUuid := uuid.New()
	requestURL.Path = transportConfiguration.GetNormalizedPath(sessionIdUuid.String(), true)
	baseURL := requestURL.String()

	httpClient := getHTTPClient(ctx, dest, streamSettings)

	uploadPipeReader, uploadPipeWriter := pipe.New(pipe.WithSizeLimit(scMaxEachPostBytes))

	go func() {
		requestsLimiter := semaphore.New(scMaxConcurrentPosts)
		var requestCounter int64

		lastWrite := time.Now()

		// by offloading the uploads into a buffered pipe, multiple conn.Write
		// calls get automatically batched together into larger POST requests.
		// without batching, bandwidth is extremely limited.
		for {
			chunk, err := uploadPipeReader.ReadMultiBuffer()
			if err != nil {
				break
			}

			<-requestsLimiter.Wait()

			seq := requestCounter
			requestCounter += 1

			go func() {
				defer requestsLimiter.Signal()

				err := httpClient.SendUploadRequest(
					context.WithoutCancel(ctx),
					baseURL+"/"+strconv.FormatInt(seq, 10),
					&buf.MultiBufferContainer{MultiBuffer: chunk},
					int64(chunk.Len()),
				)

				if err != nil {
					newError("failed to send upload").Base(err).WriteToLog(session.ExportIDToError(ctx))
					uploadPipeReader.Interrupt()
				}
			}()

			if time.Since(lastWrite) < time.Duration(scMinPostsIntervalMs)*time.Millisecond {
				time.Sleep(time.Duration(scMinPostsIntervalMs) * time.Millisecond)
			}

			lastWrite = time.Now()
		}
	}()

	lazyRawDownload, remoteAddr, localAddr, err := httpClient.OpenDownload(context.WithoutCancel(ctx), baseURL)
	if err != nil {
		return nil, err
	}

	lazyDownload := &LazyReader{
		CreateReader: func() (io.ReadCloser, error) {
			// skip "ooooooooook" response
			trashHeader := []byte{0}
			for {
				_, err := io.ReadFull(lazyRawDownload, trashHeader)
				if err != nil {
					return nil, newError("failed to read initial response").Base(err)
				}
				if trashHeader[0] == 'k' {
					break
				}
			}
			return lazyRawDownload, nil
		},
	}

	// necessary in order to send larger chunks in upload
	bufferedUploadPipeWriter := buf.NewBufferedWriter(uploadPipeWriter)
	bufferedUploadPipeWriter.SetBuffered(false)

	conn := &splitConn{
		writer:     bufferedUploadPipeWriter,
		reader:     lazyDownload,
		remoteAddr: remoteAddr,
		localAddr:  localAddr,
	}

	return internet.Connection(conn), nil
}
