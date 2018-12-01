// Copyright (c) 2018 Fredrik Kuivinen, frekui@gmail.com
//
// Use of this source code is governed by the BSD-style license that can be
// found in the LICENSE file.

package dh

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/go-test/deep"
)

func TestDh(t *testing.T) {
	dhGroup := Rfc3526_2048
	privA, err := GeneratePrivateKey(dhGroup)
	if err != nil {
		panic(err)
	}
	pubA := GeneratePublicKey(dhGroup, privA)

	privB, err := GeneratePrivateKey(dhGroup)
	if err != nil {
		panic(err)
	}
	pubB := GeneratePublicKey(dhGroup, privB)

	sharedA := SharedSecret(dhGroup, privA, pubB)
	sharedB := SharedSecret(dhGroup, privB, pubA)
	if !bytes.Equal(sharedA, sharedB) {
		t.Fatalf("sharedA != sharedB")
	}
}

// isSafePrime returns true if x is probably a safe prime (i.e., p is prime and
// (p-1)/2 is prime.).
func isSafePrime(x *big.Int) bool {
	if !x.ProbablyPrime(100) {
		return false
	}
	q := new(big.Int)
	q.Sub(x, big.NewInt(1))
	q.Div(q, big.NewInt(2))
	return q.ProbablyPrime(100)
}

func TestIsSafePrime(t *testing.T) {
	// List from https://oeis.org/A005385
	for _, x := range []int64{5, 7, 11, 23, 47, 59, 83, 107, 167, 179, 227, 263, 347, 359, 383, 467, 479, 503, 563, 587, 719, 839, 863, 887, 983, 1019, 1187, 1283, 1307, 1319, 1367, 1439, 1487, 1523, 1619, 1823, 1907} {
		if !isSafePrime(big.NewInt(x)) {
			t.Fatalf("%v is safe but isSafePrime returned false", x)
		}
	}
	for _, x := range []int64{17} {
		if isSafePrime(big.NewInt(x)) {
			t.Fatalf("%v is not safe but isSafePrime returned false", x)
		}
	}

	if !isSafePrime(Rfc3526_2048.P) {
		t.Fatalf("Rfc3526_2048.P is not safe")
	}
}

func TestIsInSmallSubgroup(t *testing.T) {
	for _, x := range []int64{2, 3, 4, 5, 6, 7, 8, 9} {
		if IsInSmallSubgroup(big.NewInt(x), big.NewInt(11)) {
			t.Fatalf("%v unexpectedly in small subgroup", x)
		}
	}
	for _, x := range []int64{1, 10} {
		if !IsInSmallSubgroup(big.NewInt(x), big.NewInt(11)) {
			t.Fatalf("%v unexpectedly not in small subgroup", x)
		}
	}
}

func TestBytes(t *testing.T) {
	for _, tst := range []struct {
		x int64
		p int64
		b []byte
	}{
		{0, 11, []byte{0}},
		{5, 11, []byte{5}},
		{300, 373, []byte{1, 44}},
		{1, 373, []byte{0, 1}},
	} {
		// Generator doesn't matter for the Bytes function.
		g := Group{G: big.NewInt(2), P: big.NewInt(tst.p)}
		actual := g.Bytes(big.NewInt(tst.x))
		if diff := deep.Equal(actual, tst.b); diff != nil {
			t.Fatalf("diff: %v\n", diff)
		}
	}
}

func TestIsInGroup(t *testing.T) {
	for _, tst := range []struct {
		x        int64
		p        int64
		expected bool
	}{
		{-1, 11, false},
		{0, 11, false},
		{1, 11, true},
		{10, 11, true},
		{11, 11, false},
		{12, 11, false},
	} {
		actual := IsInGroup(big.NewInt(tst.x), big.NewInt(tst.p))
		if actual != tst.expected {
			t.Fatalf("x=%v got %v", tst.x, actual)
		}
	}
}
