package internet

import (
	"crypto/rand"
	"net"
	"strconv"
	"strings"
	"time"
)

func newNoiseConfig(packet, delayString string) ([]byte, int64, error) {
	var err, err2 error
	p := strings.Split(strings.ToLower(packet), ":")
	if len(p) != 2 {
		return nil, 0, newError("invalid type for packet")
	}
	var lengthMin, lengthMax uint64
	var noise []byte
	switch p[0] {
	case "rand":
		randValue := strings.Split(p[1], "-")
		if len(randValue) > 2 {
			return nil, 0, newError("Only 2 values are allowed for rand")
		}
		if len(randValue) == 2 {
			lengthMin, err = strconv.ParseUint(randValue[0], 10, 64)
			lengthMax, err2 = strconv.ParseUint(randValue[1], 10, 64)
		}
		if len(randValue) == 1 {
			lengthMin, err = strconv.ParseUint(randValue[0], 10, 64)
			lengthMax = lengthMin
		}
		if err != nil {
			return nil, 0, newError("invalid value for rand lengthMin").Base(err)
		}
		if err2 != nil {
			return nil, 0, newError("invalid value for rand lengthMax").Base(err2)
		}
		if lengthMin > lengthMax {
			lengthMin, lengthMax = lengthMax, lengthMin
		}
		if lengthMin == 0 {
			return nil, 0, newError("rand lengthMin or lengthMax cannot be 0")
		}
		noise, err = GenerateRandomBytes(randBetween(int64(lengthMin), int64(lengthMax)))
		if err != nil {
			return nil, 0, err
		}
	case "str":
		noise = []byte(strings.TrimSpace(p[1]))
	default:
		return nil, 0, newError("Invalid packet,only rand and str are supported")
	}
	var delayMin, delayMax uint64
	var delay int64
	if len(delayString) > 0 {
		d := strings.Split(strings.ToLower(delayString), "-")
		if len(d) > 2 {
			return nil, 0, newError("Invalid delay value")
		}
		if len(d) == 2 {
			delayMin, err = strconv.ParseUint(d[0], 10, 64)
			delayMax, err2 = strconv.ParseUint(d[1], 10, 64)
		} else {
			delayMin, err = strconv.ParseUint(d[0], 10, 64)
			delayMax = delayMin
		}
		if err != nil {
			return nil, 0, newError("Invalid value for delayMin").Base(err)
		}
		if err2 != nil {
			return nil, 0, newError("Invalid value for delayMax").Base(err2)
		}
		if delayMin > delayMax {
			delayMin, delayMax = delayMax, delayMin
		}
		if delayMin == 0 {
			return nil, 0, newError("delayMin or delayMax cannot be 0")
		}
		delay = randBetween(int64(delayMin), int64(delayMax))
	}
	newError("NOISE", string(noise), lengthMin, lengthMax, delayMin, delayMax).AtDebug().WriteToLog()
	return noise, delay, nil
}

func NewNoisePacketConn(conn net.PacketConn, packet, delayString string) (net.PacketConn, error) {
	noise, delay, err := newNoiseConfig(packet, delayString)
	if err != nil {
		return nil, err
	}
	return &noisePacketConn{
		PacketConn: conn,
		firstWrite: true,
		noise:      noise,
		delay:      delay,
	}, nil
}

type noisePacketConn struct {
	net.PacketConn
	firstWrite bool
	noise      []byte
	delay      int64
}

func (c *noisePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if c.firstWrite {
		c.firstWrite = false
		_, _ = c.PacketConn.WriteTo(c.noise, addr)
		if c.delay != 0 {
			time.Sleep(time.Duration(c.delay) * time.Millisecond)
		}
	}
	return c.PacketConn.WriteTo(b, addr)
}

func NewNoiseConn(conn net.Conn, packet, delayString string) (net.Conn, error) {
	noise, delay, err := newNoiseConfig(packet, delayString)
	if err != nil {
		return nil, err
	}
	return &noiseConn{
		Conn:       conn,
		firstWrite: true,
		noise:      noise,
		delay:      delay,
	}, nil
}

type noiseConn struct {
	net.Conn
	firstWrite bool
	noise      []byte
	delay      int64
}

func (c *noiseConn) Write(b []byte) (int, error) {
	if c.firstWrite {
		c.firstWrite = false
		_, _ = c.Conn.Write(c.noise)
		if c.delay != 0 {
			time.Sleep(time.Duration(c.delay) * time.Millisecond)
		}
	}
	return c.Conn.Write(b)
}

func GenerateRandomBytes(n int64) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
