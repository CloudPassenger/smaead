package smaead_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"math/rand"
	"testing"

	"github.com/CloudPassenger/smaead"
	"golang.org/x/crypto/chacha20poly1305"
)

var key = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf}
var bsseq = []int{1, 2, 3, 4, 7, 8, 8, 16, 17, 17, 64, 128, 256, 4096, 0x3fff}

func partialAeadRun(aead cipher.AEAD, paead smaead.PartialAEAD, bs, count int) bool {
	for n := 0; n < count; n++ {
		pt := make([]byte, bs)
		for p := 0; p < bs; p++ {
			pt[p] = byte(rand.Int() % 256)
		}
		nonce := make([]byte, 12)
		for p := 0; p < 12; p++ {
			nonce[p] = byte(rand.Int() % 256)
		}

		ct := aead.Seal(nil, nonce, pt, nil)
		ct = ct[:len(pt)]
		pt2 := paead.OpenWithoutCheck(nil, nonce, ct)
		if bytes.Compare(pt, pt2) != 0 {
			return false
		}
	}
	return true
}
func partialAeadBench(aead cipher.AEAD, paead smaead.PartialAEAD, bs, count int) bool {
	pt := make([]byte, bs)
	for p := 0; p < bs; p++ {
		pt[p] = byte(rand.Int() % 256)
	}
	nonce := make([]byte, 12)
	for p := 0; p < 12; p++ {
		nonce[p] = byte(rand.Int() % 256)
	}

	ct := aead.Seal(nil, nonce, pt, nil)
	ct = ct[:len(pt)]
	for n := 0; n < count; n++ {
		pt2 := paead.OpenWithoutCheck(nil, nonce, ct)
		if bytes.Compare(pt, pt2) != 0 {
			return false
		}
	}
	return true
}

func TestPartialGCM(t *testing.T) {
	for _, i := range bsseq {
		a1, e := aes.NewCipher(key)
		if e != nil {
			t.Fatal(e)
		}
		a2, e := aes.NewCipher(key)
		if e != nil {
			t.Fatal(e)
		}
		stdgcm, e := cipher.NewGCM(a1)
		if e != nil {
			t.Fatal(e)
		}
		mygcm, e := smaead.NewPartialGCM(a2)
		if e != nil {
			t.Fatal(e)
		}

		if !partialAeadRun(stdgcm, mygcm, i, 100) {
			t.Fail()
		}
	}
}

func TestPartialChacha20Poly1305(t *testing.T) {
	for _, i := range bsseq {
		stdc20p1305, e := chacha20poly1305.New(key)
		if e != nil {
			t.Fatal(e)
		}
		myc20p1305, e := smaead.NewPartialChacha20Poly1305(key)
		if e != nil {
			t.Fatal(e)
		}

		if !partialAeadBench(stdc20p1305, myc20p1305, i, 100) {
			t.Fail()
		}
	}
}

func BenchmarkPartialGCM(b *testing.B) {
	a1, e := aes.NewCipher(key)
	if e != nil {
		b.Fatal(e)
	}
	a2, e := aes.NewCipher(key)
	if e != nil {
		b.Fatal(e)
	}
	stdgcm, e := cipher.NewGCM(a1)
	if e != nil {
		b.Fatal(e)
	}
	mygcm, e := smaead.NewPartialGCM(a2)
	if e != nil {
		b.Fatal(e)
	}
	b.Log(b.N)
	if !partialAeadBench(stdgcm, mygcm, 16, b.N) {
		b.Fail()
	}
}

func BenchmarkPartialChacha20Poly1305(b *testing.B) {
	stdc20p1305, e := chacha20poly1305.New(key)
	if e != nil {
		b.Fatal(e)
	}
	myc20p1305, e := smaead.NewPartialChacha20Poly1305(key)
	if e != nil {
		b.Fatal(e)
	}

	b.Log(b.N)
	if !partialAeadBench(stdc20p1305, myc20p1305, 16, b.N) {
		b.Fail()
	}
}
