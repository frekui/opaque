// Copyright (c) 2018 Fredrik Kuivinen, frekui@gmail.com
//
// Use of this source code is governed by the BSD-style license that can be
// found in the LICENSE file.

package opaque

// This file contains functions to run the interactive protocol DH-OPRF
// (Diffie-Hellman Oblivious Pseudorandom Function) from the I-D
// https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-00.

import (
	"errors"
	"math/big"
)

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
		r, err = generatePrivateKey(dhGroup)
		if err != nil {
			return nil, nil, err
		}
		hPrime := hashToGroup(dhGroup, []byte(x))
		a = new(big.Int)
		a.Exp(dhGroup.g, r, dhGroup.p)
		a.Mul(hPrime, a)
		a.Mod(a, dhGroup.p)

		// The probability that a is in a two element subgroup of
		// dhGroup is extremely small, but in case it is we try again
		// with a new r.
		if !isInSmallSubgroup(a, dhGroup.p) {
			return
		}
	}
}

func generateSalt() (k *big.Int, err error) {
	k, err = generatePrivateKey(dhGroup)
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
	if !isInGroup(a, dhGroup.p) {
		return nil, nil, errors.New("a is not in D-H group")
	}
	// Also check that a is not in a two element subgroup of dhGroup.
	if isInSmallSubgroup(a, dhGroup.p) {
		return nil, nil, errors.New("a is in a small subgroup")
	}
	// v can be stored in User instead.
	v = new(big.Int)
	v.Exp(dhGroup.g, k, dhGroup.p)
	b = new(big.Int)
	b.Exp(a, k, dhGroup.p)
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
	if !isInGroup(v, dhGroup.p) {
		return nil, errors.New("v is not in D-H group")
	}
	if isInSmallSubgroup(v, dhGroup.p) {
		return nil, errors.New("v is in a small subgroup")
	}
	if !isInGroup(b, dhGroup.p) {
		return nil, errors.New("b is not in D-H group")
	}
	if isInSmallSubgroup(b, dhGroup.p) {
		return nil, errors.New("b is in a small subgroup")
	}
	z := new(big.Int)
	z.Exp(v, r, dhGroup.p)
	z.ModInverse(z, dhGroup.p)
	z.Mul(b, z)
	z.Mod(z, dhGroup.p)
	h := hasher()
	// FIXME: User iteration, see Section 3.4.
	h.Write([]byte(x))
	h.Write(dhGroup.Bytes(v))
	h.Write(dhGroup.Bytes(z))
	return h.Sum(nil), nil
}
