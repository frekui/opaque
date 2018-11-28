// Copyright (c) 2018 Fredrik Kuivinen, frekui@gmail.com
//
// Use of this source code is governed by the BSD-style license that can be
// found in the LICENSE file.

package opaque

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/go-test/deep"
)

func TestEnvU(t *testing.T) {
	privU, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatalf("Failed to generate privU: %s", err)
	}
	privS, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatalf("Failed to generate privS: %s", err)
	}
	genEnvU := &envU{privU: privU, pubS: &privS.PublicKey}

	encodedEnvU := encodeEnvU(genEnvU)
	decodedEnvU, err := decodeEnvU(encodedEnvU)
	if err != nil {
		t.Fatalf("decoding failed: %s", err)
	}

	if diff := deep.Equal(*genEnvU, decodedEnvU); diff != nil {
		t.Fatalf("envU not equal! %v", diff)
	}
}
