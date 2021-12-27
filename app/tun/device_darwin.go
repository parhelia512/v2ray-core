package tun

import (
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var _ Device = (*DarwinDevice)(nil)

type DarwinDevice struct {
	*baseDevice
	osFile *os.File
	tunFd  int

	readEventFd int
	readEvent   []unix.Kevent_t
	readHdr     unix.Iovec
	readBuf     *iovecBuffer

	nameOnce  sync.Once
	nameCache string
	nameErr   error
}

func createDevice(base *baseDevice, name string, mtu int) (Device, error) {
	ifIndex := -1
	if name != "utun" {
		_, err := fmt.Sscanf(name, "utun%d", &ifIndex)
		if err != nil || ifIndex < 0 {
			return nil, newError("interface name must starts with utun").Base(err)
		}
	}

	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, 2)
	if err != nil {
		return nil, newError("failed to create AF_SYSTEM socket").Base(err)
	}
	ctlInfo := &unix.CtlInfo{}
	copy(ctlInfo.Name[:], "com.apple.net.utun_control")
	err = unix.IoctlCtlInfo(fd, ctlInfo)
	if err != nil {
		unix.Close(fd)
		return nil, newError("ioctlGetCtlInfo failed").Base(err)
	}

	sc := &unix.SockaddrCtl{
		ID:   ctlInfo.Id,
		Unit: uint32(ifIndex) + 1,
	}

	err = unix.Connect(fd, sc)
	if err != nil {
		unix.Close(fd)
		return nil, newError("failed to connect to addrctl").Base(err)
	}

	err = unix.SetNonblock(fd, true)
	if err != nil {
		unix.Close(fd)
		return nil, newError("failed to set nonblock").Base(err)
	}
	device := &DarwinDevice{
		baseDevice: base,
		osFile:     os.NewFile(uintptr(fd), ""),
		tunFd:      fd,
		readHdr:    IovecFromBytes(make([]byte, 4)),
	}
	device.readBuf = newIovecBuffer(bufConfig, &device.readHdr)
	err = device.SetMTU(mtu)
	if err != nil {
		return nil, newError("failed to setup mtu").Base(err)
	}
	device.readEvent = []unix.Kevent_t{{
		Ident:  uint64(fd),
		Filter: unix.EVFILT_READ,
		Flags:  unix.EV_ADD | unix.EV_ENABLE,
	}}
	return device, nil
}

func (t *DarwinDevice) Name() (string, error) {
	t.nameOnce.Do(func() {
		t.nameCache, t.nameErr = unix.GetsockoptString(
			int(t.tunFd),
			2, /* #define SYSPROTO_CONTROL 2 */
			2, /* #define UTUN_OPT_IFNAME 2 */
		)
	})
	return t.nameCache, t.nameErr
}

type ifAliasReq struct {
	Name    [unix.IFNAMSIZ]byte
	Addr    unix.RawSockaddrInet4
	Dstaddr unix.RawSockaddrInet4
	Mask    unix.RawSockaddrInet4
}

type ifAliasReq6 struct {
	Name    [unix.IFNAMSIZ]byte
	Addr    unix.RawSockaddrInet6
	Dstaddr unix.RawSockaddrInet6
	Mask    unix.RawSockaddrInet6
}

func (t *DarwinDevice) SetAddress() error {
	name, err := t.Name()
	if err != nil {
		return err
	}
	for _, prefix := range t.ranges {
		if prefix.Addr().Is4() {
			err = execShell("ifconfig", name, "inet", prefix.String(), prefix.Addr().String())
		} else {
			err = execShell("ifconfig", name, "inet6", prefix.String())
		}
	}
	return err
}

func (t *DarwinDevice) MTU() (int, error) {
	name, err := t.Name()
	if err != nil {
		return 0, err
	}
	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM,
		0,
	)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	ifr, err := unix.IoctlGetIfreqMTU(fd, name)
	if err != nil {
		return 0, err
	}
	return int(ifr.MTU), nil
}

func (t *DarwinDevice) SetMTU(mtu int) error {
	name, err := t.Name()
	if err != nil {
		return err
	}
	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM,
		0,
	)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var ifr unix.IfreqMTU
	copy(ifr.Name[:], name)
	ifr.MTU = int32(mtu)
	return unix.IoctlSetIfreqMTU(fd, &ifr)
}

func (t *DarwinDevice) Read(p []byte) (n int, err error) {
	iovecs := []unix.Iovec{
		t.readHdr,
		IovecFromBytes(p),
	}
	np, _, err := syscall.Syscall(syscall.SYS_READV, uintptr(t.tunFd), uintptr(unsafe.Pointer(&iovecs[0])), uintptr(2))
	if err != nil {
		return 0, err
	}
	if np <= 0 {
		return 0, io.EOF
	}
	return int(np), nil
}

var kWaitTimeout = unix.NsecToTimespec((100 * time.Millisecond).Nanoseconds())

func (t *DarwinDevice) ReadBuffer() (*stack.PacketBuffer, error) {
	iovecs := t.readBuf.nextIovecs()
	var n int
	var err error

	if t.readEventFd == 0 {
		t.readEventFd, err = unix.Kqueue()
		if err != nil {
			return nil, newError("failed to create kqueue").Base(err)
		}
		_, err = unix.Kevent(t.readEventFd, t.readEvent, nil, nil)
		if err != nil {
			return nil, newError("failed to register kqueue").Base(err)
		}
	}

	events := make([]unix.Kevent_t, 1)
	for {
		n, err = unix.Kevent(t.readEventFd, nil, events, &kWaitTimeout)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return nil, newError("failed to wait kevent").Base(err)
		}
		if n > 0 && events[0].Filter == unix.EVFILT_READ {
			break
		}
	}

	np, _, errno := syscall.Syscall(syscall.SYS_READV, uintptr(t.tunFd), uintptr(unsafe.Pointer(&iovecs[0])), uintptr(len(iovecs)))
	if errno == 0 {
		n = int(np)
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: t.readBuf.pullViews(n),
	})
	return pkt, nil
}

func (t *DarwinDevice) StopRead() {
	if t.readEventFd != 0 {
		unix.Close(t.readEventFd)
		t.readEventFd = 0
	}
}

func (t *DarwinDevice) Write(p []byte) (n int, err error) {
	header := make([]byte, 4)
	iovecs := []unix.Iovec{
		IovecFromBytes(header),
		IovecFromBytes(p),
	}
	if p[0]>>4 == ipv6.Version {
		header[3] = unix.AF_INET6
	} else {
		header[3] = unix.AF_INET
	}
	return NonBlockingWriteIovec(t.tunFd, iovecs)
}

func (t *DarwinDevice) WriteBuffer(buffer *stack.PacketBuffer) error {
	views := buffer.Views()
	var iovecs []unix.Iovec
	var firstByte byte
	for _, view := range views {
		if !view.IsEmpty() {
			firstByte = view[0]
			break
		}
	}
	header := make([]byte, 4)
	if firstByte == ipv6.Version {
		header[3] = unix.AF_INET6
	} else {
		header[3] = unix.AF_INET
	}
	numIovecs := len(views) + 1
	iovecs = make([]unix.Iovec, 0, numIovecs)
	iovecs = AppendIovecFromBytes(iovecs, header, numIovecs)
	for _, v := range views {
		iovecs = AppendIovecFromBytes(iovecs, v, numIovecs)
	}
	_, err := NonBlockingWriteIovec(t.tunFd, iovecs)
	return err
}

func (t *DarwinDevice) WriteBuffers(buffers []*stack.PacketBuffer) (int, error) {
	for _, buffer := range buffers {
		err := t.WriteBuffer(buffer)
		if err != nil {
			return 0, err
		}
	}
	return len(buffers), nil
}

func (t *DarwinDevice) Close() error {
	t.StopRead()
	return t.osFile.Close()
}
