package internet

import (
	"crypto/rand"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

func NewFragmentConn(conn net.Conn, packets, length, interval string) (net.Conn, error) {
	fragmentConn := &fragmentConn{
		Conn: conn,
	}
	var err, err2 error
	switch strings.ToLower(packets) {
	case "tlshello":
		// TLS Hello Fragmentation (into multiple handshake messages)
		fragmentConn.packetsFrom = 0
		fragmentConn.packetsTo = 1
	case "":
		// TCP Segmentation (all packets)
		fragmentConn.packetsFrom = 0
		fragmentConn.packetsTo = 0
	default:
		// TCP Segmentation (range)
		packetsFromTo := strings.Split(packets, "-")
		if len(packetsFromTo) == 2 {
			fragmentConn.packetsFrom, err = strconv.ParseUint(packetsFromTo[0], 10, 64)
			fragmentConn.packetsTo, err2 = strconv.ParseUint(packetsFromTo[1], 10, 64)
		} else {
			fragmentConn.packetsFrom, err = strconv.ParseUint(packetsFromTo[0], 10, 64)
			fragmentConn.packetsTo = fragmentConn.packetsFrom
		}
		if err != nil {
			return nil, newError("Invalid packetsFrom").Base(err)
		}
		if err2 != nil {
			return nil, newError("Invalid packetsTo").Base(err2)
		}
		if fragmentConn.packetsFrom > fragmentConn.packetsTo {
			fragmentConn.packetsFrom, fragmentConn.packetsTo = fragmentConn.packetsTo, fragmentConn.packetsFrom
		}
		if fragmentConn.packetsFrom == 0 {
			return nil, newError("packetsFrom can't be 0")
		}
	}

	if length == "" {
		return nil, newError("length can't be empty")
	}
	lengthMinMax := strings.Split(length, "-")
	if len(lengthMinMax) == 2 {
		fragmentConn.lengthMin, err = strconv.ParseUint(lengthMinMax[0], 10, 64)
		fragmentConn.lengthMax, err2 = strconv.ParseUint(lengthMinMax[1], 10, 64)
	} else {
		fragmentConn.lengthMin, err = strconv.ParseUint(lengthMinMax[0], 10, 64)
		fragmentConn.lengthMax = fragmentConn.lengthMin
	}
	if err != nil {
		return nil, newError("Invalid lengthMin").Base(err)
	}
	if err2 != nil {
		return nil, newError("Invalid lengthMax").Base(err2)
	}
	if fragmentConn.lengthMin > fragmentConn.lengthMax {
		fragmentConn.lengthMin, fragmentConn.lengthMax = fragmentConn.lengthMax, fragmentConn.lengthMin
	}
	if fragmentConn.lengthMin == 0 {
		return nil, newError("lengthMin can't be 0")
	}

	if interval == "" {
		return nil, newError("interval can't be empty")
	}
	intervalMinMax := strings.Split(interval, "-")
	if len(intervalMinMax) == 2 {
		fragmentConn.intervalMin, err = strconv.ParseUint(intervalMinMax[0], 10, 64)
		fragmentConn.intervalMax, err2 = strconv.ParseUint(intervalMinMax[1], 10, 64)
	} else {
		fragmentConn.intervalMin, err = strconv.ParseUint(intervalMinMax[0], 10, 64)
		fragmentConn.intervalMax = fragmentConn.intervalMin
	}
	if err != nil {
		return nil, newError("Invalid intervalMin").Base(err)
	}
	if err2 != nil {
		return nil, newError("Invalid intervalMax").Base(err2)
	}
	if fragmentConn.intervalMin > fragmentConn.intervalMax {
		fragmentConn.intervalMin, fragmentConn.intervalMax = fragmentConn.intervalMax, fragmentConn.intervalMin
	}

	newError("FRAGMENT",
		fragmentConn.packetsFrom, fragmentConn.packetsTo,
		fragmentConn.lengthMin, fragmentConn.lengthMax,
		fragmentConn.intervalMin, fragmentConn.intervalMax).AtDebug().WriteToLog()
	return fragmentConn, nil
}

type fragmentConn struct {
	net.Conn
	count       uint64
	packetsFrom uint64
	packetsTo   uint64
	lengthMin   uint64
	lengthMax   uint64
	intervalMin uint64
	intervalMax uint64
}

func (f *fragmentConn) Write(b []byte) (int, error) {
	count := atomic.AddUint64(&f.count, 1)

	if f.packetsFrom == 0 && f.packetsTo == 1 {
		if count != 1 || len(b) <= 5 || b[0] != 22 {
			return f.Conn.Write(b)
		}
		recordLen := 5 + ((int(b[3]) << 8) | int(b[4]))
		if len(b) < recordLen { // maybe already fragmented somehow
			return f.Conn.Write(b)
		}
		data := b[5:recordLen]
		buf := make([]byte, 1024)
		queue := make([]byte, 2048)
		n_queue := int(randBetween(int64(1), int64(4)))
		L_queue := 0
		c_queue := 0
		for from := 0; ; {
			to := from + int(randBetween(int64(f.lengthMin), int64(f.lengthMax)))
			if to > len(data) {
				to = len(data)
			}
			copy(buf[:3], b)
			copy(buf[5:], data[from:to])
			l := to - from
			from = to
			buf[3] = byte(l >> 8)
			buf[4] = byte(l)
			if c_queue < n_queue {
				if l > 0 {
					copy(queue[L_queue:], buf[:5+l])
					L_queue = L_queue + 5 + l
				}
				c_queue = c_queue + 1
			} else {
				if l > 0 {
					copy(queue[L_queue:], buf[:5+l])
					L_queue = L_queue + 5 + l
				}
				if L_queue > 0 {
					_, err := f.Conn.Write(queue[:L_queue])
					time.Sleep(time.Duration(randBetween(int64(f.intervalMin), int64(f.intervalMax))) * time.Millisecond)
					if err != nil {
						return 0, err
					}
				}
				L_queue = 0
				c_queue = 0
			}
			if from == len(data) {
				if L_queue > 0 {
					_, err := f.Conn.Write(queue[:L_queue])
					time.Sleep(time.Duration(randBetween(int64(f.intervalMin), int64(f.intervalMax))) * time.Millisecond)
					L_queue = 0
					c_queue = 0
					if err != nil {
						return 0, err
					}
				}
				if len(b) > recordLen {
					n, err := f.Conn.Write(b[recordLen:])
					if err != nil {
						return recordLen + n, err
					}
				}
				return len(b), nil
			}
		}
	}

	if f.packetsFrom != 0 && (count < f.packetsFrom || count > f.packetsTo) {
		return f.Conn.Write(b)
	}
	for from := 0; ; {
		to := from + int(randBetween(int64(f.lengthMin), int64(f.lengthMax)))
		if to > len(b) {
			to = len(b)
		}
		n, err := f.Conn.Write(b[from:to])
		from += n
		time.Sleep(time.Duration(randBetween(int64(f.intervalMin), int64(f.intervalMax))) * time.Millisecond)
		if err != nil {
			return from, err
		}
		if from >= len(b) {
			return from, nil
		}
	}
}

func randBetween(left int64, right int64) int64 {
	if left == right {
		return left
	}
	bigInt, _ := rand.Int(rand.Reader, big.NewInt(right-left))
	return left + bigInt.Int64()
}
