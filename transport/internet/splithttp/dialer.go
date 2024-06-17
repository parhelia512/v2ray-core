package splithttp

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/http2"

	core "github.com/v2fly/v2ray-core/v5"
	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/buf"
	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/session"
	"github.com/v2fly/v2ray-core/v5/common/signal/done"
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

type reusedClient struct {
	download *http.Client
	upload   *http.Client
	isH2     bool
	// pool of net.Conn, created using dialUploadConn
	uploadRawPool  *sync.Pool
	dialUploadConn func(ctxInner context.Context) (net.Conn, error)
}

var (
	globalDialerMap    map[dialerConf]*reusedClient
	globalDialerAccess sync.Mutex
)

func getHTTPClient(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (*reusedClient, error) {
	globalDialerAccess.Lock()
	defer globalDialerAccess.Unlock()

	if globalDialerMap == nil {
		globalDialerMap = make(map[dialerConf]*reusedClient)
	}

	if client, found := globalDialerMap[dialerConf{dest, streamSettings}]; found {
		return client, nil
	}

	var tlsConfig *tls.Config
	switch cfg := streamSettings.SecuritySettings.(type) {
	case *tls.Config:
		tlsConfig = cfg
	case *utls.Config:
		tlsConfig = cfg.GetTlsConfig()
	}

	isH2 := tlsConfig != nil && !(len(tlsConfig.NextProtocol) == 1 && tlsConfig.NextProtocol[0] == "http/1.1")
	dialContext := func(_ context.Context) (net.Conn, error) {
		return transportcommon.DialWithSecuritySettings(core.ToBackgroundDetachedContext(ctx), dest, streamSettings)
	}

	var uploadTransport http.RoundTripper
	var downloadTransport http.RoundTripper

	if isH2 {
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

	client := &reusedClient{
		download: &http.Client{
			Transport: downloadTransport,
		},
		upload: &http.Client{
			Transport: uploadTransport,
		},
		isH2:           isH2,
		uploadRawPool:  &sync.Pool{},
		dialUploadConn: dialContext,
	}

	globalDialerMap[dialerConf{dest, streamSettings}] = client
	return client, nil
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}

func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (internet.Connection, error) {
	newError("dialing splithttp to ", dest).WriteToLog(session.ExportIDToError(ctx))

	var requestURL url.URL

	transportConfiguration := streamSettings.ProtocolSettings.(*Config)

	maxConcurrentUploads := transportConfiguration.GetNormalizedMaxConcurrentUploads()
	maxUploadSize := transportConfiguration.GetNormalizedMaxUploadSize()

	if securityEngine, _ := security.CreateSecurityEngineFromSettings(ctx, streamSettings); securityEngine != nil {
		requestURL.Scheme = "https"
	} else {
		requestURL.Scheme = "http"
	}
	requestURL.Host = transportConfiguration.Host
	if requestURL.Host == "" {
		requestURL.Host = dest.NetAddr()
	}
	requestURL.Path = transportConfiguration.GetNormalizedPath()

	httpClient, err := getHTTPClient(ctx, dest, streamSettings)
	if err != nil {
		return nil, err
	}

	var remoteAddr net.Addr
	var localAddr net.Addr
	// this is done when the TCP/UDP connection to the server was established,
	// and we can unblock the Dial function and print correct net addresses in
	// logs
	gotConn := done.New()

	var downResponse io.ReadCloser
	gotDownResponse := done.New()

	sessionIdUuid := uuid.New()
	sessionId := sessionIdUuid.String()

	go func() {
		trace := &httptrace.ClientTrace{
			GotConn: func(connInfo httptrace.GotConnInfo) {
				remoteAddr = connInfo.Conn.RemoteAddr()
				localAddr = connInfo.Conn.LocalAddr()
				gotConn.Close()
			},
		}

		// in case we hit an error, we want to unblock this part
		defer gotConn.Close()

		req, err := http.NewRequestWithContext(
			httptrace.WithClientTrace(context.WithoutCancel(ctx), trace),
			"GET",
			requestURL.String()+sessionId,
			nil,
		)
		if err != nil {
			newError("failed to construct download http request").Base(err).WriteToLog()
			gotDownResponse.Close()
			return
		}

		req.Header = transportConfiguration.GetRequestHeader()

		response, err := httpClient.download.Do(req)
		gotConn.Close()
		if err != nil {
			newError("failed to send download http request").Base(err).WriteToLog()
			gotDownResponse.Close()
			return
		}

		if response.StatusCode != 200 {
			response.Body.Close()
			newError("invalid status code on download:", response.Status).WriteToLog()
			gotDownResponse.Close()
			return
		}

		// skip "ooooooooook" response
		trashHeader := []byte{0}
		for {
			_, err = io.ReadFull(response.Body, trashHeader)
			if err != nil {
				response.Body.Close()
				newError("failed to read initial response").Base(err).WriteToLog()
				gotDownResponse.Close()
				return
			}
			if trashHeader[0] == 'k' {
				break
			}
		}

		downResponse = response.Body
		gotDownResponse.Close()
	}()

	uploadUrl := requestURL.String() + sessionId + "/"

	uploadPipeReader, uploadPipeWriter := pipe.New(pipe.WithSizeLimit(maxUploadSize))

	go func() {
		requestsLimiter := semaphore.New(int(maxConcurrentUploads))
		var requestCounter int64

		// by offloading the uploads into a buffered pipe, multiple conn.Write
		// calls get automatically batched together into larger POST requests.
		// without batching, bandwidth is extremely limited.
		for {
			chunk, err := uploadPipeReader.ReadMultiBuffer()
			if err != nil {
				break
			}

			<-requestsLimiter.Wait()

			url := uploadUrl + strconv.FormatInt(requestCounter, 10)
			requestCounter += 1

			go func() {
				defer requestsLimiter.Signal()
				req, err := http.NewRequest("POST", url, &buf.MultiBufferContainer{MultiBuffer: chunk})
				if err != nil {
					newError("failed to send upload").Base(err).WriteToLog()
					uploadPipeReader.Interrupt()
					return
				}

				req.ContentLength = int64(chunk.Len())
				req.Header = transportConfiguration.GetRequestHeader()

				if httpClient.isH2 {
					resp, err := httpClient.upload.Do(req)
					if err != nil {
						newError("failed to send upload").Base(err).WriteToLog()
						uploadPipeReader.Interrupt()
						return
					}
					defer resp.Body.Close()

					if resp.StatusCode != 200 {
						newError("failed to send upload, bad status code:", resp.Status).WriteToLog()
						uploadPipeReader.Interrupt()
						return
					}
				} else {
					var uploadConn any

					// stringify the entire HTTP/1.1 request so it can be
					// safely retried. if instead req.Write is called multiple
					// times, the body is already drained after the first
					// request
					requestBytes := new(bytes.Buffer)
					common.Must(req.Write(requestBytes))

					for {
						uploadConn = httpClient.uploadRawPool.Get()
						newConnection := uploadConn == nil
						if newConnection {
							uploadConn, err = httpClient.dialUploadConn(context.WithoutCancel(ctx))
							if err != nil {
								newError("failed to connect upload").Base(err).WriteToLog()
								uploadPipeReader.Interrupt()
								return
							}
						}

						_, err = uploadConn.(net.Conn).Write(requestBytes.Bytes())

						// if the write failed, we try another connection from
						// the pool, until the write on a new connection fails.
						// failed writes to a pooled connection are normal when
						// the connection has been closed in the meantime.
						if err == nil {
							break
						} else if newConnection {
							newError("failed to send upload").Base(err).WriteToLog()
							uploadPipeReader.Interrupt()
							return
						}
					}

					httpClient.uploadRawPool.Put(uploadConn)
				}
			}()

		}
	}()

	// we want to block Dial until we know the remote address of the server,
	// for logging purposes
	<-gotConn.Wait()

	// necessary in order to send larger chunks in upload
	bufferedUploadPipeWriter := buf.NewBufferedWriter(uploadPipeWriter)
	bufferedUploadPipeWriter.SetBuffered(false)

	lazyDownload := &LazyReader{
		CreateReader: func() (io.ReadCloser, error) {
			<-gotDownResponse.Wait()
			if downResponse == nil {
				return nil, newError("downResponse failed")
			}
			return downResponse, nil
		},
	}

	conn := splitConn{
		writer:     bufferedUploadPipeWriter,
		reader:     lazyDownload,
		remoteAddr: remoteAddr,
		localAddr:  localAddr,
	}

	return internet.Connection(&conn), nil
}
