package smaead

import _ "unsafe"

type PartialAEAD interface {
	OpenWithoutCheck(dst, nonce, ciphertext []byte) []byte
}

//go:linkname inexactOverlap crypto/internal/subtle.InexactOverlap
func inexactOverlap(x, y []byte) bool

//go:linkname xorBytes crypto/cipher.xorBytes
func xorBytes(dst, a, b []byte) int

//go:linkname xorWords crypto/cipher.xorWords
func xorWords(dst, a, b []byte)

//go:linkname sliceForAppend crypto/cipher.sliceForAppend
func sliceForAppend(in []byte, n int) (head, tail []byte)
