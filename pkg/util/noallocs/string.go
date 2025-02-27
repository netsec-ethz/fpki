package noallocs

// StringToBytePtr returns a pointer to a null terminated string. The passed storage will be used
// to store the bytes of the name, and has to be at least len(str) +1 in size.
func StringToBytePtr(storage []byte, str string) *byte {
	// If they point to the same place, return that pointer.
	if &storage[0] != &([]byte(str)[0]) {
		// If they don't point to the same place, modify the storage.
		storage[len(str)] = 0 // Null terminated string.
		copy(storage, str)    // Bytes of the string.
	}
	return &storage[0]
}
