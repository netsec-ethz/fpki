package noallocs

import (
	"math/rand"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	charMap             = "0123456789-abcdefghijklmnopqrstuvwxyz"
	numberOfRandomChars = 10 // Number of random chars in the filename.
)

// CreateTempFile creates a named temporary file using prefix as the initial path and prefix.
// The passed storage has to be big enough to hold the prefix + number of random chars (10) + 1.
func CreateTempFile(storage []byte, prefix, suffix string) (filename string, err error) {
	// Copy prefix and suffix.
	copy(storage, []byte(prefix))
	copy(storage[len(prefix)+numberOfRandomChars:], []byte(suffix))

	// Get the *byte from the name.
	pathPtr := StringToBytePtr(storage, prefix)

	// Null terminated string..
	storage[len(prefix)+numberOfRandomChars+len(suffix)] = 0

	// Randomize and try to open.
	var fd int
	for attempts := 0; attempts < 10; attempts++ {
		randomFilenameChars(storage[len(prefix) : len(prefix)+numberOfRandomChars])
		fd, err = createTempFile(pathPtr)
		switch err {
		case nil:
			// Close the file descriptor.
			err = unix.Close(fd)
			filename = unsafe.String(pathPtr, len(prefix)+numberOfRandomChars+len(suffix))
			return
		case unix.EEXIST:
			continue
		default:
			return
		}
	}
	return
}

func createTempFile(pathPtr *byte) (int, error) {
	return createFile(
		pathPtr,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_LARGEFILE,
		0600,
	)
}

func randomFilenameChar() byte {
	return charMap[rand.Intn(len(charMap))]
}

func randomFilenameChars(storage []byte) {
	for i := range storage {
		storage[i] = randomFilenameChar()
	}
}
