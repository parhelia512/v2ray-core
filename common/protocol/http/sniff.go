package http

import (
	"bytes"
	"errors"
	"net/url"
	"strings"

	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/net"
)

type SniffHeader struct {
	domain string
}

func (h *SniffHeader) Protocol() string {
	return "http1"
}

func (h *SniffHeader) Domain() string {
	return h.domain
}

var (
	// refer to https://pkg.go.dev/net/http@master#pkg-constants
	methods = [...]string{"get", "post", "head", "put", "delete", "options", "connect", "patch", "trace"}

	errNotHTTPMethod = errors.New("not an HTTP method")
)

func beginWithHTTPMethod(b []byte) error {
	for _, m := range &methods {
		if len(b) >= len(m) && strings.EqualFold(string(b[:len(m)]), m) {
			return nil
		}

		if len(b) < len(m) {
			return common.ErrNoClue
		}
	}

	return errNotHTTPMethod
}

func parseRequestLine(b []byte) (string, bool) {
	_, rest, ok1 := strings.Cut(string(b), " ")
	requestURI, _, ok2 := strings.Cut(rest, " ")
	if !ok1 || !ok2 {
		return "", false
	}
	return requestURI, true
}

func SniffHTTP(b []byte) (*SniffHeader, error) {
	if err := beginWithHTTPMethod(b); err != nil {
		return nil, err
	}

	headers := bytes.Split(b, []byte{'\n'})

	var host string

	requestURI, ok := parseRequestLine(headers[0])
	if !ok {
		return nil, common.ErrNoClue
	}
	u, err := url.ParseRequestURI(requestURI)
	if err != nil {
		return nil, err
	}
	host = u.Host

	for i := 1; i < len(headers); i++ {
		header := headers[i]
		if len(header) == 0 {
			break
		}
		parts := bytes.SplitN(header, []byte{':'}, 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(string(parts[0]))
		if key == "host" && host == "" {
			host = string(bytes.TrimSpace(parts[1]))
		}
	}

	if len(host) > 0 {
		dest, err := ParseHost(host, net.Port(80))
		if err != nil {
			return nil, err
		}
		if dest.Address.Family().IsDomain() {
			return &SniffHeader{domain: dest.Address.String()}, nil
		}
	}

	return nil, common.ErrNoClue
}
