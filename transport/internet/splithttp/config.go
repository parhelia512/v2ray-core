package splithttp

import (
	"net/http"
	"strings"

	"github.com/v2fly/v2ray-core/v5/common/net"
)

const (
	scMaxEachPostBytes     = 1000000
	scMaxConcurrentPosts   = 100
	scMinPostsIntervalMs   = 30
	scMinResponseOkPadding = 100
	scMaxResponseOkPadding = 1000
)

func IsValidHTTPHost(request string, config string) bool {
	r := strings.ToLower(request)
	c := strings.ToLower(config)
	if strings.Contains(r, ":") {
		h, _, _ := net.SplitHostPort(r)
		return h == c
	}
	return r == c
}

func (c *Config) GetNormalizedPath(addPath string, addQuery bool) string {
	pathAndQuery := strings.SplitN(c.Path, "?", 2)
	path := pathAndQuery[0]
	query := ""
	if len(pathAndQuery) > 1 && addQuery {
		query = "?" + pathAndQuery[1]
	}

	if path == "" || path[0] != '/' {
		path = "/" + path
	}
	if path[len(path)-1] != '/' {
		path = path + "/"
	}

	return path + addPath + query
}

func (c *Config) GetRequestHeader() http.Header {
	header := http.Header{}
	for k, v := range c.Header {
		header.Add(k, v)
	}
	return header
}
