package p11sign

import "encoding/binary"

func readP11CKUlong(b []byte) uint32 {
	b = append(b, 0, 0, 0, 0)
	return binary.LittleEndian.Uint32(b)
}
