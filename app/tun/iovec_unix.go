//go:build linux || darwin

package tun

import (
	"reflect"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
)

// bufConfig defines the shape of the vectorised view used to read packets from the NIC.
var bufConfig = []int{128, 256, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768}

type iovecBuffer struct {
	hdr    bool
	views  []buffer.View
	iovecs []unix.Iovec
	sizes  []int
}

func newIovecBuffer(sizes []int, hdr *unix.Iovec) *iovecBuffer {
	b := &iovecBuffer{
		views: make([]buffer.View, len(sizes)),
		sizes: sizes,
	}
	if hdr == nil {
		b.iovecs = make([]unix.Iovec, len(b.views))
	} else {
		b.iovecs = make([]unix.Iovec, len(b.views)+1)
		b.iovecs[0] = *hdr
		b.hdr = true
	}
	return b
}

func (b *iovecBuffer) nextIovecs() []unix.Iovec {
	var vnetHdrOff int
	if b.hdr {
		vnetHdrOff = 1
	}
	for i := range b.views {
		if b.views[i] != nil {
			break
		}
		v := buffer.NewView(b.sizes[i])
		b.views[i] = v
		b.iovecs[i+vnetHdrOff] = unix.Iovec{Base: &v[0]}
		b.iovecs[i+vnetHdrOff].SetLen(len(v))
	}
	return b.iovecs
}

func (b *iovecBuffer) pullViews(n int) buffer.VectorisedView {
	var views []buffer.View
	c := 0
	for i, v := range b.views {
		c += len(v)
		if c >= n {
			b.views[i].CapLength(len(v) - (c - n))
			views = append([]buffer.View(nil), b.views[:i+1]...)
			break
		}
	}
	// Remove the first len(views) used views from the state.
	for i := range views {
		b.views[i] = nil
	}
	return buffer.NewVectorisedView(n, views)
}

func IovecFromBytes(bs []byte) unix.Iovec {
	iov := unix.Iovec{
		Base: &bs[0],
	}
	iov.SetLen(len(bs))
	return iov
}

func bytesFromIovec(iov unix.Iovec) (bs []byte) {
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&bs))
	sh.Data = uintptr(unsafe.Pointer(iov.Base))
	sh.Len = int(iov.Len)
	sh.Cap = int(iov.Len)
	return
}

// AppendIovecFromBytes returns append(iovs, IovecFromBytes(bs)). If len(bs) ==
// 0, AppendIovecFromBytes returns iovs without modification. If len(iovs) >=
// max, AppendIovecFromBytes replaces the final iovec in iovs with one that
// also includes the contents of bs. Note that this implies that
// AppendIovecFromBytes is only usable when the returned iovec slice is used as
// the source of a write.
func AppendIovecFromBytes(iovs []unix.Iovec, bs []byte, max int) []unix.Iovec {
	if len(bs) == 0 {
		return iovs
	}
	if len(iovs) < max {
		return append(iovs, IovecFromBytes(bs))
	}
	iovs[len(iovs)-1] = IovecFromBytes(append(bytesFromIovec(iovs[len(iovs)-1]), bs...))
	return iovs
}

func NonBlockingWrite(fd int, buf []byte) (int, error) {
	var ptr unsafe.Pointer
	if len(buf) > 0 {
		ptr = unsafe.Pointer(&buf[0])
	}
	np, _, err := unix.RawSyscall(unix.SYS_WRITE, uintptr(fd), uintptr(ptr), uintptr(len(buf)))
	if err != 0 {
		return 0, err
	}
	return int(np), nil
}

// NonBlockingWriteIovec writes iovec to a file descriptor in a single unix.
// It fails if partial data is written.
func NonBlockingWriteIovec(fd int, iovec []unix.Iovec) (int, error) {
	iovecLen := uintptr(len(iovec))
	np, _, err := unix.RawSyscall(unix.SYS_WRITEV, uintptr(fd), uintptr(unsafe.Pointer(&iovec[0])), iovecLen)
	if err != 0 {
		return 0, err
	}
	return int(np), nil
}
