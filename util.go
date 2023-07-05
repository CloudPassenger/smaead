package smaead

import _ "unsafe"

type PartialAEAD interface {
	OpenWithoutCheck(dst, nonce, ciphertext []byte) []byte
}

//go:linkname inexactOverlap crypto/internal/alias.InexactOverlap
//goland:noinspection GoUnusedParameter
func inexactOverlap(x, y []byte) bool

//go:linkname XORBytes crypto/subtle.XORBytes
//goland:noinspection GoUnusedParameter
func XORBytes(dst, a, b []byte) int

//go:linkname sliceForAppend crypto/cipher.sliceForAppend
//goland:noinspection GoUnusedParameter
func sliceForAppend(in []byte, n int) (head, tail []byte)

//go:linkname reverseBits crypto/cipher.reverseBits
//goland:noinspection GoUnusedParameter
func reverseBits(i int) int

type gcmFieldElement struct {
	low, high uint64
}

//go:linkname gcmAdd crypto/cipher.gcmAdd
//goland:noinspection GoUnusedParameter
func gcmAdd(x, y *gcmFieldElement) gcmFieldElement

//go:linkname gcmDouble crypto/cipher.gcmDouble
//goland:noinspection GoUnusedParameter
func gcmDouble(x *gcmFieldElement) (double gcmFieldElement)

//go:linkname gcmInc32 crypto/cipher.gcmInc32
//goland:noinspection GoUnusedParameter
func gcmInc32(counterBlock *[16]byte)
