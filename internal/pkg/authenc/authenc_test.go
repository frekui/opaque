// Copyright (c) 2018 Fredrik Kuivinen, frekui@gmail.com
//
// Use of this source code is governed by the BSD-style license that can be
// found in the LICENSE file.

package authenc

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestPadding(t *testing.T) {
	bs := 16
	for _, tst := range []struct {
		in, expected []byte
	}{
		{[]byte{}, []byte{16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16}},
		{[]byte{7}, []byte{7, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15}},
		{[]byte{7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7},
			[]byte{7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
				16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16}},
		{[]byte{7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7},
			[]byte{7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
				7, 7, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14}},
	} {
		// fmt.Printf("Testing padding %v\n", tst)
		padded := addPadding(bs, tst.in)
		if !bytes.Equal(padded, tst.expected) {
			t.Errorf("Got %v", padded)
		}

		orig := removePadding(bs, padded)
		if !bytes.Equal(orig, tst.in) {
			t.Errorf("Failed to remove padding, got %v", orig)
		}
	}
}

type DevZero int

func (z DevZero) Read(b []byte) (n int, err error) {
	for i := range b {
		b[i] = 0
	}

	return len(b), nil
}

var authEncDecTests = []struct {
	key, plaintext, expected []byte
}{
	{[]byte{7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7},
		[]byte{},
		[]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1a, 0xd6, 0x3e, 0x8c, 0x60, 0xb3, 0xa8, 0xbb, 0x77, 0x33, 0x83, 0x96, 0x67, 0x45, 0x2f, 0x42, 0xe9, 0x85, 0xf2, 0x9b, 0xa8, 0x78, 0xb1, 0x32, 0x74, 0x5, 0xb2, 0xcd, 0x9d, 0xfe, 0xfa, 0x2f, 0xfa, 0xe5, 0xc9, 0x2f, 0xbc, 0x65, 0x7b, 0xd9, 0x40, 0x94, 0xf1, 0xa5, 0xbe, 0x29, 0xe, 0xf}},
	{[]byte{7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7},
		[]byte{1, 2, 3},
		[]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x17, 0xde, 0x41, 0xb, 0x46, 0xeb, 0xb0, 0x14, 0xd, 0xd7, 0x6b, 0xeb, 0x4e, 0xc0, 0xcb, 0x65, 0xc8, 0x1b, 0xd9, 0x96, 0x1, 0x9, 0xcb, 0x36, 0xb5, 0x23, 0x24, 0x46, 0x56, 0xfd, 0x30, 0x68, 0x44, 0xec, 0xfd, 0x57, 0x44, 0xa4, 0x81, 0xb6, 0x17, 0x80, 0x0, 0x28, 0xc8, 0xb3, 0x73, 0x62},
	},
}

func TestAuthEncDecDeterministic(t *testing.T) {
	var zeroReader DevZero
	for _, tst := range authEncDecTests {
		// fmt.Printf("Testing deterministic enc/dec %v\n", tst)
		dst, err := AuthEnc(zeroReader, tst.key, tst.plaintext)
		if err != nil {
			t.Errorf("AuthEnc failed: %v", err)
		}
		if !bytes.Equal(dst, tst.expected) {
			t.Errorf("AuthEnc result doesn't match expected value, got\n%#v expected\n%#v", dst, tst.expected)
		}
		actualPlaintext, err := AuthDec(tst.key, dst)
		if err != nil {
			t.Errorf("AuthDec failed: %v", err)
		}
		if !bytes.Equal(tst.plaintext, actualPlaintext) {
			t.Errorf("Failed to decrypt, got %v", actualPlaintext)
		}

		wrongKey := append([]byte{}, tst.key...)
		wrongKey[0] = wrongKey[0] ^ 1
		_, err = AuthDec(wrongKey, dst)
		if err != AuthtagMismatch {
			t.Errorf("AuthDec didn't fail when wrong key was used")
		}

		wrongAuthTag := append([]byte{}, dst...)
		wrongAuthTag[len(wrongAuthTag)-1] ^= 1
		_, err = AuthDec(tst.key, wrongAuthTag)
		if err != AuthtagMismatch {
			t.Errorf("AuthDec didn't fail when wrong auth tag was used")
		}
	}
}

// Test AuthEnc and AuthDec with randomized IV. We run each test a number of
// times and make sure that we never see the same ciphtertext.
func TestAuthEncDec(t *testing.T) {
	for _, tst := range authEncDecTests {
		// fmt.Printf("Testing enc/dec %v\n", tst)
		dsts := map[string]bool{}
		for i := 0; i < 10; i++ {
			dst, err := AuthEnc(rand.Reader, tst.key, tst.plaintext)
			if err != nil {
				t.Errorf("AuthEnc failed: %v", err)
			}
			// fmt.Printf("Got dst %v\n", dst)
			if dsts[string(dst)] {
				t.Errorf("Got same dst twice, %v", dst)
			}
			dsts[string(dst)] = true
			actualPlaintext, err := AuthDec(tst.key, dst)
			if err != nil {
				t.Errorf("AuthDec failed: %v", err)
			}
			if !bytes.Equal(tst.plaintext, actualPlaintext) {
				t.Errorf("Failed to decrypt, got %v", actualPlaintext)
			}

			wrongKey := append([]byte{}, tst.key...)
			wrongKey[0] = wrongKey[0] ^ 1
			_, err = AuthDec(wrongKey, dst)
			if err != AuthtagMismatch {
				t.Errorf("AuthDec didn't fail when wrong key was used")
			}

			wrongAuthTag := append([]byte{}, dst...)
			wrongAuthTag[len(wrongAuthTag)-1] ^= 1
			_, err = AuthDec(tst.key, wrongAuthTag)
			if err != AuthtagMismatch {
				t.Errorf("AuthDec didn't fail when wrong auth tag was used")
			}
		}
	}
}
