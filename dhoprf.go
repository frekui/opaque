// Copyright (c) 2018 Fredrik Kuivinen, frekui@gmail.com
//
// Use of this source code is governed by the BSD-style license that can be
// found in the LICENSE file.

package opaque

// This file contains functions to run the interactive protocol DH-OPRF
// (Diffie-Hellman Oblivious Pseudorandom Function) from the I-D
// https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-00.

import (
	"crypto/rand"
	"errors"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

// hashToGroup is an implementation of the H' hash function from the I-D. It
// hashes byte slices to group elements (i.e., elements in Z^*_p).
func hashToGroup(data []byte) *big.Int {
	kdf := hkdf.New(hasher, data, nil, nil)

	for {
		x, err := rand.Int(kdf, dhGroup.P)
		if err != nil {
			panic(err)
		}
		if x.Sign() != 0 {
			return x
		}
	}
}

// dhOprf1 is the first step in computing DF-OPRF. dhOprf1 is executed on the
// client.
//
// From the I-D:
//     Protocol for computing DH-OPRF, U with input x and S with input k:
//     U: choose random r in [0..q-1], send a=H'(x)*g^r to S
//
// x is typically the password.
func dhOprf1(x string) (a, r *big.Int, err error) {
	for {
		r, err = dhGroup.GeneratePrivateKey()
		if err != nil {
			return nil, nil, err
		}
		hPrime := hashToGroup([]byte(x))
		a = new(big.Int)
		a.Exp(dhGroup.G, r, dhGroup.P)
		a.Mul(hPrime, a)
		a.Mod(a, dhGroup.P)

		// The probability that a is in a two element subgroup of
		// dhGroup is extremely small, but in case it is we try again
		// with a new r.
		if !dhGroup.IsInSmallSubgroup(a) {
			return
		}
	}
}

func generateSalt() (k *big.Int, err error) {
	k, err = dhGroup.GeneratePrivateKey()
	return
}

// dhOprf2 is the second step in computing DH-OPRF. dhOprf2 is executed on the
// server.
//
// From the I-D:
//     S: upon receiving a value a, respond with v=g^k and b=a^k
//
// k is used a salt when the password is hashed.
func dhOprf2(a, k *big.Int) (v *big.Int, b *big.Int, err error) {
	// From I-D: All received values (a, b, v) are checked to be non-unit
	// elements in G.
	//
	// First check that a is in Z^*_p.
	if !dhGroup.IsInGroup(a) {
		return nil, nil, errors.New("a is not in D-H group")
	}
	// Also check that a is not in a two element subgroup of dhGroup.
	if dhGroup.IsInSmallSubgroup(a) {
		return nil, nil, errors.New("a is in a small subgroup")
	}
	// v can be stored in User instead.
	v = new(big.Int)
	v.Exp(dhGroup.G, k, dhGroup.P)
	b = new(big.Int)
	b.Exp(a, k, dhGroup.P)
	return v, b, nil
}

// dhOprf3 is the third and final step in computing DH-OPRF. dhOprf3 is executed
// on the client.
//
// From the I-D:
//     U: upon receiving values b and v, set the PRF output to H(x, v, b*v^{-r})
func dhOprf3(x string, v, b, r *big.Int) ([]byte, error) {
	// From I-D: All received values (a, b, v) are checked to be non-unit
	// elements in G.
	//
	// We check that v and b are in Z^*_p and they aren't in a two element
	// subgroup.
	if !dhGroup.IsInGroup(v) {
		return nil, errors.New("v is not in D-H group")
	}
	if dhGroup.IsInSmallSubgroup(v) {
		return nil, errors.New("v is in a small subgroup")
	}
	if !dhGroup.IsInGroup(b) {
		return nil, errors.New("b is not in D-H group")
	}
	if dhGroup.IsInSmallSubgroup(b) {
		return nil, errors.New("b is in a small subgroup")
	}
	z := new(big.Int)
	z.Exp(v, r, dhGroup.P)
	z.ModInverse(z, dhGroup.P)
	z.Mul(b, z)
	z.Mod(z, dhGroup.P)
	h := hasher()
	// FIXME: User iteration, see Section 3.4.
	h.Write([]byte(x))
	h.Write(dhGroup.Bytes(v))
	h.Write(dhGroup.Bytes(z))
	return h.Sum(nil), nil
}
