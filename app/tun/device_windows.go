package tun

import (
	"crypto"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
	tcpipbuffer "gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	core "github.com/v2fly/v2ray-core/v4"
	"github.com/v2fly/v2ray-core/v4/app/tun/winipcfg"
)

var _ Device = (*WindowsDevice)(nil)

type WindowsDevice struct {
	*baseDevice
	name      string
	adapter   *wintun.Adapter
	session   *wintun.Session
	guid      *windows.GUID
	forcedMTU int
	handle    windows.Handle
	readWait  windows.Handle
	running   sync.WaitGroup
	closeOnce sync.Once
	close     int32
	rate      rateJuggler
}

func createDevice(base *baseDevice, name string, mtu int) (Device, error) {
	guid, err := generateGUIDByDeviceName(name)
	if err != nil {
		return nil, newError("failed to generate uuid").Base(err)
	}
	wt, err := wintun.CreateAdapter(name, "V2Ray", guid)
	if err != nil {
		return nil, newError("error creating interface: ", name).Base(err)
	}
	session, err := wt.StartSession(0x800000)
	if err != nil {
		wt.Close()
		return nil, newError("error opening wintun session: ", name).Base(err)
	}
	dev := &WindowsDevice{
		baseDevice: base,
		name:       name,
		adapter:    wt,
		session:    &session,
		guid:       guid,
		forcedMTU:  mtu,
		handle:     windows.InvalidHandle,
	}
	if err = dev.SetMTU(dev.forcedMTU); err != nil {
		return nil, err
	}

	dev.readWait = session.ReadWaitEvent()
	return dev, nil
}

func generateGUIDByDeviceName(name string) (*windows.GUID, error) {
	crypto.MD5.New().Sum([]byte("V2Ray " + core.Version() + "\n" + name))
	// GUID is 128 bit
	hash := crypto.MD5.New()
	_, err := hash.Write([]byte("V2Ray " + core.Version()))
	if err != nil {
		return nil, err
	}
	_, err = hash.Write([]byte(name))
	if err != nil {
		return nil, err
	}
	sum := hash.Sum(nil)
	return (*windows.GUID)(unsafe.Pointer(&sum[0])), nil
}

func (t *WindowsDevice) Name() (string, error) {
	return t.name, nil
}

func (t *WindowsDevice) SetAddress() error {
	luid := winipcfg.LUID(t.adapter.LUID())
	err := luid.SetIPAddresses(t.ranges)
	if err != nil {
		return newError("failed to set address for wintun").Base(err)
	}
	return nil
}

func (t *WindowsDevice) MTU() (int, error) {
	return t.forcedMTU, nil
}

func (t *WindowsDevice) SetMTU(mtu int) error {
	t.forcedMTU = mtu
	if mtu <= 0 {
		return nil
	}

	luid := winipcfg.LUID(t.adapter.LUID())
	ipif, err := luid.IPInterface(windows.AF_INET)
	if err != nil {
		return err
	}

	ipif.NLMTU = uint32(mtu)
	if err := ipif.Set(); err != nil {
		return newError("failed to set mtu for wintun").Base(err)
	}

	return nil
}

func (t *WindowsDevice) Read(p []byte) (n int, err error) {
	t.running.Add(1)
	defer t.running.Done()
retry:
	if atomic.LoadInt32(&t.close) == 1 {
		return 0, os.ErrClosed
	}
	start := nanotime()
	shouldSpin := atomic.LoadUint64(&t.rate.current) >= spinloopRateThreshold && uint64(start-atomic.LoadInt64(&t.rate.nextStartTime)) <= rateMeasurementGranularity*2
	for {
		if atomic.LoadInt32(&t.close) == 1 {
			return 0, os.ErrClosed
		}
		packet, err := t.session.ReceivePacket()
		switch err {
		case nil:
			packetSize := len(packet)
			copy(p, packet)
			t.session.ReleaseReceivePacket(packet)
			t.rate.update(uint64(packetSize))
			return packetSize, nil
		case windows.ERROR_NO_MORE_ITEMS:
			if !shouldSpin || uint64(nanotime()-start) >= spinloopDuration {
				windows.WaitForSingleObject(t.readWait, windows.INFINITE)
				goto retry
			}
			procyield(1)
			continue
		case windows.ERROR_HANDLE_EOF:
			return 0, os.ErrClosed
		case windows.ERROR_INVALID_DATA:
			return 0, newError("send ring corrupt")
		}
		return 0, newError("read failed").Base(err)
	}
}

func (t *WindowsDevice) ReadBuffer() (*stack.PacketBuffer, error) {
	t.running.Add(1)
	defer t.running.Done()
retry:
	if atomic.LoadInt32(&t.close) == 1 {
		return nil, os.ErrClosed
	}
	start := nanotime()
	shouldSpin := atomic.LoadUint64(&t.rate.current) >= spinloopRateThreshold && uint64(start-atomic.LoadInt64(&t.rate.nextStartTime)) <= rateMeasurementGranularity*2
	for {
		if atomic.LoadInt32(&t.close) == 1 {
			return nil, os.ErrClosed
		}
		packet, err := t.session.ReceivePacket()
		switch err {
		case nil:
			packetSize := len(packet)
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Data: tcpipbuffer.NewViewFromBytes(packet).ToVectorisedView(),
			})
			t.session.ReleaseReceivePacket(packet)
			t.rate.update(uint64(packetSize))
			return pkt, nil
		case windows.ERROR_NO_MORE_ITEMS:
			if !shouldSpin || uint64(nanotime()-start) >= spinloopDuration {
				windows.WaitForSingleObject(t.readWait, windows.INFINITE)
				goto retry
			}
			procyield(1)
			continue
		case windows.ERROR_HANDLE_EOF:
			return nil, os.ErrClosed
		case windows.ERROR_INVALID_DATA:
			return nil, newError("send ring corrupt")
		}
		return nil, newError("read failed").Base(err)
	}
}

func (t *WindowsDevice) StopRead() {
	windows.SetEvent(t.readWait)
	t.running.Wait()
	t.session.End()
}

func (t *WindowsDevice) Write(p []byte) (n int, err error) {
	t.running.Add(1)
	defer t.running.Done()
	if atomic.LoadInt32(&t.close) == 1 {
		return 0, os.ErrClosed
	}

	packetSize := len(p)
	t.rate.update(uint64(packetSize))

	packet, err := t.session.AllocateSendPacket(packetSize)
	if err == nil {
		copy(packet, p)
		t.session.SendPacket(packet)
		return packetSize, nil
	}
	switch err {
	case windows.ERROR_HANDLE_EOF:
		return 0, os.ErrClosed
	case windows.ERROR_BUFFER_OVERFLOW:
		return 0, nil // Dropping when ring is full.
	}
	return 0, newError("write failed").Base(err)
}

func (t *WindowsDevice) WriteBuffer(buffer *stack.PacketBuffer) error {
	t.running.Add(1)
	defer t.running.Done()
	if atomic.LoadInt32(&t.close) == 1 {
		return io.EOF
	}
	views := buffer.Views()
	data := views[0]
	if len(views) > 1 {
		for _, view := range views[1:] {
			data = append(data, view...)
		}
	}
	size := len(data)
	packet, err := t.session.AllocateSendPacket(size)
	if err == nil {
		copy(packet, data)
		t.session.SendPacket(packet)
	} else {
		switch err {
		case windows.ERROR_HANDLE_EOF:
			return io.EOF
		case windows.ERROR_BUFFER_OVERFLOW:
			return nil // Dropping when ring is full.
		}
		return err
	}

	return nil
}

func (t *WindowsDevice) WriteBuffers(buffers []*stack.PacketBuffer) (int, error) {
	t.running.Add(1)
	defer t.running.Done()
	if atomic.LoadInt32(&t.close) == 1 {
		return 0, io.EOF
	}
	var packets [][]byte
	var packetSize int
	for _, pkt := range buffers {
		views := pkt.Views()
		data := views[0]
		if len(views) > 1 {
			for _, view := range views[1:] {
				data = append(data, view...)
			}
		}
		size := len(data)
		packetSize += size
		packet, err := t.session.AllocateSendPacket(size)
		if err == nil {
			copy(packet, data)
			packets = append(packets, packet)
		} else {
			switch err {
			case windows.ERROR_HANDLE_EOF:
				return 0, io.EOF
			case windows.ERROR_BUFFER_OVERFLOW:
				return 0, nil // Dropping when ring is full.
			}
			return 0, err
		}
	}
	for _, packet := range packets {
		t.session.SendPacket(packet)
	}
	return 0, nil
}

func (t *WindowsDevice) Close() error {
	var err error
	t.closeOnce.Do(func() {
		atomic.StoreInt32(&t.close, 1)
		t.StopRead()
		if t.adapter != nil {
			t.adapter.Close()
		}
	})
	return err
}

const (
	rateMeasurementGranularity = uint64((time.Second / 2) / time.Nanosecond)
	spinloopRateThreshold      = 800000000 / 8                                   // 800mbps
	spinloopDuration           = uint64(time.Millisecond / 80 / time.Nanosecond) // ~1gbit/s
)

type rateJuggler struct {
	current       uint64
	nextByteCount uint64
	nextStartTime int64
	changing      int32
}

func (rate *rateJuggler) update(packetLen uint64) {
	now := nanotime()
	total := atomic.AddUint64(&rate.nextByteCount, packetLen)
	period := uint64(now - atomic.LoadInt64(&rate.nextStartTime))
	if period >= rateMeasurementGranularity {
		if !atomic.CompareAndSwapInt32(&rate.changing, 0, 1) {
			return
		}
		atomic.StoreInt64(&rate.nextStartTime, now)
		atomic.StoreUint64(&rate.current, total*uint64(time.Second/time.Nanosecond)/period)
		atomic.StoreUint64(&rate.nextByteCount, 0)
		atomic.StoreInt32(&rate.changing, 0)
	}
}

//go:linkname procyield runtime.procyield
func procyield(cycles uint32)

//go:linkname nanotime runtime.nanotime
func nanotime() int64
