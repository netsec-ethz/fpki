package noallocs

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

func Open(storage []byte, filename string) (int, error) {
	ptr := StringToBytePtr(storage, filename)
	return createFile(
		ptr,
		unix.O_RDWR|unix.O_CREAT|unix.O_APPEND|unix.O_LARGEFILE,
		unix.S_IRWXU|unix.S_IRWXG,
	)
}

func Close(fd int) error {
	return unix.Close(fd)
}

func Write(fd int, data []byte) error {
	n, err := unix.Write(fd, data)
	if n != len(data) {
		return fmt.Errorf("expected to write %d bytes but wrote %d", len(data), n)
	}

	return err
}

func createFile(pathPtr *byte, flags int, perm int) (fd int, err error) {
	dirfd := unix.AT_FDCWD
	r0, _, e1 := unix.Syscall6(
		unix.SYS_OPENAT,
		uintptr(dirfd),
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(flags),
		uintptr(perm),
		0, 0,
	)
	fd = int(r0)
	if e1 != 0 {
		err = e1
	}

	return
}
