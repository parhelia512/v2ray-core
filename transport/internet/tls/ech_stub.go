//go:build !go1.23

package tls

import (
	"crypto/tls"
)

func applyECH(c *Config, config *tls.Config) error {
	return newError("ECH requires go 1.23 or higher")
}
