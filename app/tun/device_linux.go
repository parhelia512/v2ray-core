package tun

import (
	"bytes"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/link/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip/link/tun"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var _ Device = (*LinuxDevice)(nil)

const ifReqSize = unix.IFNAMSIZ + 64

type LinuxDevice struct {
	*baseDevice

	osFile *os.File
	tunFd  int

	nameOnce  sync.Once
	nameCache string
	nameErr   error

	readEvent stopFd
	readBuf   *iovecBuffer
}

func createDevice(base *baseDevice, name string, mtu int) (Device, error) {
	tunFd, err := tun.Open(name)
	if err != nil {
		return nil, err
	}
	stopFd, err := newStopFd()
	if err != nil {
		return nil, newError("failed to create event fd").Base(err)
	}
	device := &LinuxDevice{
		baseDevice: base,
		osFile:     os.NewFile(uintptr(tunFd), ""),
		tunFd:      tunFd,
		readEvent:  stopFd,
		readBuf:    newIovecBuffer(bufConfig, nil),
	}
	err = device.SetMTU(mtu)
	if err != nil {
		return nil, newError("failed to set mtu").Base(err)
	}
	return device, nil
}

func (t *LinuxDevice) Name() (string, error) {
	t.nameOnce.Do(t.initNameCache)
	return t.nameCache, t.nameErr
}

func (t *LinuxDevice) SetAddress() error {
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
	ifreq, err := unix.NewIfreq(name)
	if err != nil {
		return newError("failed to create ifreq for name ", name).Base(err)
	}
	for _, prefix := range t.ranges {
		if prefix.Addr().Is4() {
			addr := prefix.Addr().As4()
			ifreq.SetInet4Addr(addr[:])
			err = unix.IoctlIfreq(fd, syscall.SIOCSIFADDR, ifreq)
			if err == nil {
				ifreq, _ = unix.NewIfreq(name)
				ifreq.SetInet4Addr(net.CIDRMask(prefix.Bits(), 32))
				err = unix.IoctlIfreq(fd, syscall.SIOCSIFNETMASK, ifreq)
			}
			if err != nil {
				return newError("failed to set ipv4 address on ", name)
			}
		} else {
			ifreq, _ = unix.NewIfreq(name)
			err = unix.IoctlIfreq(fd, syscall.SIOCGIFINDEX, ifreq)
			if err != nil {
				return newError("failed to get interface index for ", prefix.String()).Base(err)
			}

			ifreq6 := in6_ifreq{
				ifr6_addr: in6_addr{
					addr: prefix.Addr().As16(),
				},
				ifr6_prefixlen: uint32(prefix.Bits()),
				ifr6_ifindex:   ifreq.Uint32(),
			}

			fd6, err := unix.Socket(
				unix.AF_INET6,
				unix.SOCK_DGRAM,
				0,
			)
			if err != nil {
				return err
			}
			defer unix.Close(fd6)

			if _, _, errno := syscall.Syscall(
				syscall.SYS_IOCTL,
				uintptr(fd6),
				uintptr(syscall.SIOCSIFADDR),
				uintptr(unsafe.Pointer(&ifreq6)),
			); errno != 0 {
				return newError("failed to set ipv6 address on ", name).Base(errno)
			}
		}
	}

	ifreq, _ = unix.NewIfreq(name)
	err = unix.IoctlIfreq(fd, syscall.SIOCGIFFLAGS, ifreq)
	if err == nil {
		ifreq.SetUint16(ifreq.Uint16() | syscall.IFF_UP | syscall.IFF_RUNNING)
		err = unix.IoctlIfreq(fd, syscall.SIOCSIFFLAGS, ifreq)
	}
	if err != nil {
		return newError("failed to bring tun device up").Base(err)
	}

	return nil
}

func (t *LinuxDevice) initNameCache() {
	t.nameCache, t.nameErr = t.nameSlow()
}

func (t *LinuxDevice) nameSlow() (string, error) {
	var ifr [ifReqSize]byte
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(t.tunFd), uintptr(unix.TUNGETIFF), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return "", errno
	}
	name := ifr[:]
	if i := bytes.IndexByte(name, 0); i != -1 {
		name = name[:i]
	}
	return string(name), nil
}

func (t *LinuxDevice) MTU() (int, error) {
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
	var ifr [ifReqSize]byte
	copy(ifr[:], name)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.SIOCGIFMTU), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return 0, errno
	}
	return int(*(*int32)(unsafe.Pointer(&ifr[unix.IFNAMSIZ]))), nil
}

func (t *LinuxDevice) SetMTU(mtu int) error {
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
	var ifr [ifReqSize]byte
	copy(ifr[:], name)
	*(*uint32)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = uint32(mtu)
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCSIFMTU),
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func (t *LinuxDevice) Write(p []byte) (n int, err error) {
	return NonBlockingWrite(t.tunFd, p)
}

func (t *LinuxDevice) WriteBuffer(buffer *stack.PacketBuffer) error {
	views := buffer.Views()
	numIovecs := len(views)
	iovecs := make([]unix.Iovec, 0, numIovecs)
	for _, v := range views {
		iovecs = AppendIovecFromBytes(iovecs, v, numIovecs)
	}
	_, err := NonBlockingWriteIovec(t.tunFd, iovecs)
	return err
}

func (t *LinuxDevice) WriteBuffers(buffers []*stack.PacketBuffer) (int, error) {
	// Send a batch of packets through batchFD.
	mmsgHdrsStorage := make([]rawfile.MMsgHdr, 0, len(buffers))
	packets := 0
	for packets < len(buffers) {
		mmsgHdrs := mmsgHdrsStorage
		batch := buffers[packets:]
		for _, pkt := range batch {
			views := pkt.Views()
			numIovecs := len(views)
			if numIovecs > rawfile.MaxIovs {
				numIovecs = rawfile.MaxIovs
			}

			// We can't easily allocate iovec arrays on the stack here since
			// they will escape this loop iteration via mmsgHdrs.
			iovecs := make([]unix.Iovec, 0, numIovecs)
			for _, v := range views {
				iovecs = rawfile.AppendIovecFromBytes(iovecs, v, numIovecs)
			}

			var mmsgHdr rawfile.MMsgHdr
			mmsgHdr.Msg.Iov = &iovecs[0]
			mmsgHdr.Msg.SetIovlen(len(iovecs))
			mmsgHdrs = append(mmsgHdrs, mmsgHdr)
		}

		if len(mmsgHdrs) == 0 {
			// We can't fit batch[0] into a mmsghdr while staying under
			// e.maxSyscallHeaderBytes. Use WritePacket, which will avoid the
			// mmsghdr (by using writev) and re-buffer iovecs more aggressively
			// if necessary (by using e.writevMaxIovs instead of
			// rawfile.MaxIovs).
			pkt := batch[0]
			if err := t.WriteBuffer(pkt); err != nil {
				return packets, err
			}
			packets++
		} else {
			for len(mmsgHdrs) > 0 {
				sent, err := rawfile.NonBlockingSendMMsg(t.tunFd, mmsgHdrs)
				if err != nil {
					return packets, tcpipErr(err)
				}
				packets += sent
				mmsgHdrs = mmsgHdrs[sent:]
			}
		}
	}

	return packets, nil
}

func (t *LinuxDevice) StopRead() {
	t.readEvent.stop()
}

func (t *LinuxDevice) Close() error {
	t.StopRead()
	return t.osFile.Close()
}

func (t *LinuxDevice) Read(p []byte) (n int, err error) {
	return t.osFile.Read(p)
}

func (t *LinuxDevice) ReadBuffer() (*stack.PacketBuffer, error) {
	n, err := rawfile.BlockingReadvUntilStopped(t.readEvent.efd, t.tunFd, t.readBuf.nextIovecs())
	if err != nil {
		return nil, tcpipErr(err)
	}
	if n <= 0 {
		return nil, io.EOF
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: t.readBuf.pullViews(n),
	})
	return pkt, nil
}
