// Copyright (c) 2018 Fredrik Kuivinen, frekui@gmail.com
//
// Use of this source code is governed by the BSD-style license that can be
// found in the LICENSE file.

package opaque

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/go-test/deep"
)

// dhoprf runs the DH-OPRF protocol on input x (the password) and k (the salt).
func dhoprf(x string, k int64) (a, r *big.Int, h []byte) {
	// dhOprf1 is computed by the client.
	// func dhOprf1(x string) (a, r *big.Int, err error)
	var err error
	a, r, err = dhOprf1(x)
	if err != nil {
		panic(err)
	}

	// dhOprf2 is computed by the server.
	// func dhOprf2(a, k *big.Int) (v *big.Int, b *big.Int)
	v, b, err := dhOprf2(a, big.NewInt(k))
	if err != nil {
		panic(err)
	}

	// dhOprf3 is computed by the client.
	// func dhOprf3(x string, v, b, r *big.Int) []byte
	h, err = dhOprf3(x, v, b, r)
	if err != nil {
		panic(err)
	}
	return
}

func TestDhOprf(t *testing.T) {
	rs := map[string]bool{}
	as := map[string]bool{}
	var hPrev []byte
	iterations := 10
	for i := 0; i < iterations; i++ {
		a, r, h := dhoprf("password", 123)
		aStr := a.String()
		if as[aStr] {
			t.Fatalf("Already seen a %v", aStr)
		}
		as[aStr] = true

		rStr := r.String()
		if rs[rStr] {
			t.Fatalf("Already seen r %v", rStr)
		}
		rs[rStr] = true

		if hPrev == nil {
			hPrev = h
		}
		if diff := deep.Equal(h, hPrev); diff != nil {
			t.Fatalf("diff: %v", diff)
		}
	}
	if len(rs) < iterations {
		t.Fatalf("rs too small")
	}

	_, _, hNewSalt := dhoprf("password", 789)
	if bytes.Equal(hPrev, hNewSalt) {
		t.Fatalf("hash didn't change with new salt")
	}
	_, _, hNewPassword := dhoprf("new", 123)
	if bytes.Equal(hPrev, hNewPassword) {
		t.Fatalf("hash didn't change with new password")
	}
}
