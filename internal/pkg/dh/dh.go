// Copyright (c) 2018 Fredrik Kuivinen, frekui@gmail.com
//
// Use of this source code is governed by the BSD-style license that can be
// found in the LICENSE file.
//
// This file contains an implementation of Diffie-Hellman key exchange over the
// group Z^*_p for a prime p.

package dh

import (
	"crypto/rand"
	"crypto/sha256"
	"hash"
	"math"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

func hasher() hash.Hash {
	return sha256.New()
}

// Group represents the group Z^*_p.
type Group struct {
	// Group generator.
	G *big.Int

	// Group order.
	P *big.Int
}

func (g Group) Bytes(x *big.Int) []byte {
	z := new(big.Int)
	z.Mod(x, g.P)
	b := z.Bytes()
	bytelen := int(math.Ceil(float64(g.P.BitLen()) / 8))
	padLen := bytelen - len(b)
	res := make([]byte, bytelen)
	copy(res[padLen:], b)
	return res
}

// HashToGroup is the H' hash function from the I-D. It hashes byte slices to
// group elements (i.e., elements in Z^*_p).
func HashToGroup(g Group, data []byte) *big.Int {
	kdf := hkdf.New(hasher, data, nil, nil)

	for {
		x, err := rand.Int(kdf, g.P)
		if err != nil {
			panic(err)
		}
		if x.Sign() != 0 {
			return x
		}
	}
}

// Rfc3526_2048 is the 2048-bit MODP Group from RFC 3526.
var Rfc3526_2048 Group

func init() {
	p, ok := new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
	if !ok {
		panic("big.Int SetString failed")
	}
	g := new(big.Int).SetInt64(2)
	Rfc3526_2048 = Group{G: g, P: p}
}

// IsInSmallSubgroup returns true if x belongs to a small subgroup of Z^*_p.
//
// Precondition: p is a safe prime (i.e., p is prime and (p-1)/2 is prime.).
//
// As p is a safe prime there are only three sizes of subgroups: one, two, and,
// (p-1)/2 elements. The subgroups containing one and two elements are
// considered to be small.
func IsInSmallSubgroup(x *big.Int, p *big.Int) bool {
	if x.Cmp(big.NewInt(1)) == 0 {
		return true
	}
	sq := new(big.Int)
	sq.Exp(x, big.NewInt(2), p)
	if sq.Cmp(big.NewInt(1)) == 0 {
		return true
	}

	return false
}

// IsInGroup returns true if x is in the group Z^*_p and false otherwise.
func IsInGroup(x *big.Int, p *big.Int) bool {
	if big.NewInt(0).Cmp(x) != -1 || x.Cmp(p) != -1 {
		return false
	}
	return true
}

func GeneratePrivateKey(g Group) (*big.Int, error) {
	for {
		key, err := rand.Int(rand.Reader, g.P)
		if err != nil {
			return nil, err
		}
		if key.Sign() != 0 {
			return key, nil
		}
	}
}

func GeneratePublicKey(g Group, privKey *big.Int) *big.Int {
	ret := new(big.Int)
	return ret.Exp(g.G, privKey, g.P)
}

func SharedSecret(g Group, privKey *big.Int, otherPubKey *big.Int) []byte {
	s := new(big.Int)
	s.Exp(otherPubKey, privKey, g.P)
	h := hasher()
	h.Write(s.Bytes())
	return h.Sum(nil)
}
