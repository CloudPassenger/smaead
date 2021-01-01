package smaead

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

// gcmFieldElement represents a value in GF(2¹²⁸). In order to reflect the GCM
// standard and make binary.BigEndian suitable for marshaling these values, the
// bits are stored in big endian order. For example:
//   the coefficient of x⁰ can be obtained by v.low >> 63.
//   the coefficient of x⁶³ can be obtained by v.low & 1.
//   the coefficient of x⁶⁴ can be obtained by v.high >> 63.
//   the coefficient of x¹²⁷ can be obtained by v.high & 1.
type gcmFieldElement struct {
	low, high uint64
}

// Gcm represents a Galois Counter Mode with a specific key. See
// https://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
type Gcm struct {
	cipher    cipher.Block
	// productTable contains the first sixteen powers of the key, H.
	// However, they are in bit reversed order. See NewGCMWithNonceSize.
	productTable [16]gcmFieldElement
}

func NewPartialGCM(cipher cipher.Block) (*Gcm, error) {
	if cipher.BlockSize() != gcmBlockSize {
		return nil, errors.New("cipher: NewGCM requires 128-bit block cipher")
	}
	var key [gcmBlockSize]byte
	cipher.Encrypt(key[:], key[:])
	g := &Gcm{cipher: cipher}
	// We precompute 16 multiples of |key|. However, when we do lookups
	// into this table we'll be using bits from a field element and
	// therefore the bits will be in the reverse order. So normally one
	// would expect, say, 4*key to be in index 4 of the table but due to
	// this bit ordering it will actually be in index 0010 (base 2) = 2.
	x := gcmFieldElement{
		binary.BigEndian.Uint64(key[:8]),
		binary.BigEndian.Uint64(key[8:]),
	}
	g.productTable[reverseBits(1)] = x
	for i := 2; i < 16; i += 2 {
		g.productTable[reverseBits(i)] = gcmDouble(&g.productTable[reverseBits(i/2)])
		g.productTable[reverseBits(i+1)] = gcmAdd(&g.productTable[reverseBits(i)], &x)
	}
	return g, nil
}

const (
	gcmBlockSize         = 16
	gcmStandardNonceSize = 12
)

func (g *Gcm) OpenWithoutCheck(dst, nonce, ciphertext []byte) []byte {
	if len(nonce) != gcmStandardNonceSize {
		panic("smaead.gcm: incorrect nonce length given to GCM")
	}
	var counter [gcmBlockSize]byte
	// set ctr
	g.deriveCounter(&counter, nonce)
	gcmInc32(&counter)
	ret, out := sliceForAppend(dst, len(ciphertext))
	if inexactOverlap(out, ciphertext) {
		panic("smaead.gcm: invalid buffer overlap")
	}
	g.counterCrypt(out, ciphertext, &counter)
	return ret
}

// reverseBits reverses the order of the bits of 4-bit number in i.
func reverseBits(i int) int {
	i = ((i << 2) & 0xc) | ((i >> 2) & 0x3)
	i = ((i << 1) & 0xa) | ((i >> 1) & 0x5)
	return i
}

// gcmAdd adds two elements of GF(2¹²⁸) and returns the sum.
func gcmAdd(x, y *gcmFieldElement) gcmFieldElement {
	// Addition in a characteristic 2 field is just XOR.
	return gcmFieldElement{x.low ^ y.low, x.high ^ y.high}
}

// gcmDouble returns the result of doubling an element of GF(2¹²⁸).
func gcmDouble(x *gcmFieldElement) (double gcmFieldElement) {
	msbSet := x.high&1 == 1
	// Because of the bit-ordering, doubling is actually a right shift.
	double.high = x.high >> 1
	double.high |= x.low << 63
	double.low = x.low >> 1
	// If the most-significant bit was set before shifting then it,
	// conceptually, becomes a term of x^128. This is greater than the
	// irreducible polynomial so the result has to be reduced. The
	// irreducible polynomial is 1+x+x^2+x^7+x^128. We can subtract that to
	// eliminate the term at x^128 which also means subtracting the other
	// four terms. In characteristic 2 fields, subtraction == addition ==
	// XOR.
	if msbSet {
		double.low ^= 0xe100000000000000
	}
	return
}

// gcmInc32 treats the final four bytes of counterBlock as a big-endian value
// and increments it.
func gcmInc32(counterBlock *[16]byte) {
	ctr := counterBlock[len(counterBlock)-4:]
	binary.BigEndian.PutUint32(ctr, binary.BigEndian.Uint32(ctr)+1)
}

// counterCrypt crypts in to out using g.cipher in counter mode.
func (g *Gcm) counterCrypt(out, in []byte, counter *[gcmBlockSize]byte) {
	var mask [gcmBlockSize]byte
	for len(in) >= gcmBlockSize {
		g.cipher.Encrypt(mask[:], counter[:])
		gcmInc32(counter)
		xorWords(out, in, mask[:])
		out = out[gcmBlockSize:]
		in = in[gcmBlockSize:]
	}
	if len(in) > 0 {
		g.cipher.Encrypt(mask[:], counter[:])
		gcmInc32(counter)
		xorBytes(out, in, mask[:])
	}
}

// deriveCounter computes the initial GCM counter state from the given nonce.
// See NIST SP 800-38D, section 7.1. This assumes that counter is filled with
// zeros on entry.
func (g *Gcm) deriveCounter(counter *[gcmBlockSize]byte, nonce []byte) {
	// GCM has two modes of operation with respect to the initial counter
	// state: a "fast path" for 96-bit (12-byte) nonces, and a "slow path"
	// for nonces of other lengths. For a 96-bit nonce, the nonce, along
	// with a four-byte big-endian counter starting at one, is used
	// directly as the starting counter. For other nonce sizes, the counter
	// is computed by passing it through the GHASH function.
	if len(nonce) == gcmStandardNonceSize {
		copy(counter[:], nonce)
		counter[gcmBlockSize-1] = 1
	} else {
		panic("smaead.gcm: use 12 byte nonce!")
	}
}
