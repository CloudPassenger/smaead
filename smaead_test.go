package smaead_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"github.com/studentmain/smaead"
	"golang.org/x/crypto/chacha20poly1305"
	"math/rand"
	"testing"
)
var key = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf}

func TestPartialGCM(t *testing.T) {
	for _, i := range []int{1, 3, 4, 7, 8, 8, 64, 128, 256, 4096} {
		for n := 0; n < 10; n++ {
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

			pt := make([]byte, i)
			for p := 0; p < i; p++ {
				pt[p] = byte(rand.Int() % 256)
			}
			nonce := make([]byte, 12)
			for p := 0; p < 12; p++ {
				nonce[p] = byte(rand.Int() % 256)
			}

			ct := stdgcm.Seal(nil, nonce, pt, nil)
			ct = ct[:len(pt)]
			pt2 := mygcm.OpenWithoutCheck(nil, nonce, ct)
			if bytes.Compare(pt, pt2) != 0 {
				t.Fail()
			}
		}
	}
}

func TestPartialChacha20Poly1305(t *testing.T) {
	for _, i := range []int{1, 3, 4, 7, 8, 8, 64, 128, 256, 4096} {
		for n := 0; n < 10; n++ {
			stdc20p1305, e := chacha20poly1305.New(key)
			if e != nil {
				t.Fatal(e)
			}
			myc20p1305, e := smaead.NewPartialChacha20Poly1305(key)
			if e != nil {
				t.Fatal(e)
			}
			pt := make([]byte, i)
			for p := 0; p < i; p++ {
				pt[p] = byte(rand.Int() % 256)
			}
			nonce := make([]byte, 12)
			for p := 0; p < 12; p++ {
				nonce[p] = byte(rand.Int() % 256)
			}

			ct := stdc20p1305.Seal(nil, nonce, pt, nil)
			ct = ct[:len(pt)]
			pt2 := myc20p1305.OpenWithoutCheck(nil, nonce, ct)
			if bytes.Compare(pt, pt2) != 0 {
				t.Fail()
			}
		}
	}
}
