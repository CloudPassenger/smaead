// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package smaead

import (
	"errors"
	"golang.org/x/crypto/chacha20"
)

const (
	// KeySize is the size of the key used by this AEAD, in bytes.
	KeySize = 32

	// NonceSize is the size of the nonce used with the standard variant of this
	// AEAD, in bytes.
	//
	// Note that this is too short to be safely generated at random if the same
	// key is reused more than 2³² times.
	NonceSize = 12

	// NonceSizeX is the size of the nonce used with the XChaCha20-Poly1305
	// variant of this AEAD, in bytes.
	NonceSizeX = 24
)

type Chacha20poly1305 struct {
	key [KeySize]byte
}

// New returns a ChaCha20-Poly1305 AEAD that uses the given 256-bit key.
func NewPartialChacha20Poly1305(key []byte) (*Chacha20poly1305, error) {
	if len(key) != KeySize {
		return nil, errors.New("chacha20poly1305: bad key length")
	}
	ret := new(Chacha20poly1305)
	copy(ret.key[:], key)
	return ret, nil
}

func (c *Chacha20poly1305) NonceSize() int {
	return NonceSize
}

func (c *Chacha20poly1305) Overhead() int {
	return 16
}

func (c *Chacha20poly1305) OpenWithoutCheck(dst, nonce, ciphertext []byte) []byte {
	var polyKey [32]byte
	s, _ := chacha20.NewUnauthenticatedCipher(c.key[:], nonce)
	s.XORKeyStream(polyKey[:], polyKey[:])
	s.SetCounter(1) // set the counter to 1, skipping 32 bytes

	ret, out := sliceForAppend(dst, len(ciphertext))
	if inexactOverlap(out, ciphertext) {
		panic("chacha20poly1305: invalid buffer overlap")
	}

	s.XORKeyStream(out, ciphertext)
	return ret
}
