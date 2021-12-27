//go:build !linux && !windows && !darwin

package tun

func createDevice(base *baseDevice, name string, mtu int) (Device, error) {
	return nil, newError("unsupported platform")
}
