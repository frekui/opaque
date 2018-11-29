// Copyright (c) 2018 Fredrik Kuivinen, frekui@gmail.com
//
// Use of this source code is governed by the BSD-style license that can be
// found in the LICENSE file.

package opaque

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"math/big"
	"testing"
)

func TestAuth(t *testing.T) {
	username := "user"
	password := "password"

	// First create the server's private RSA key.
	privS, err := rsa.GenerateKey(randr, 512)
	if err != nil {
		t.Fatal(err)
	}

	// Register the user.
	clientSession, msg1, err := PwRegInit(username, password, 512)
	if err != nil {
		t.Fatal(err)
	}

	serverSession, msg2, err := PwReg1(privS, msg1)
	if err != nil {
		t.Fatal(err)
	}

	msg3, err := PwReg2(clientSession, msg2)
	if err != nil {
		t.Fatal(err)
	}

	user := PwReg3(serverSession, msg3)

	// User has registered. Test authentication.
	for idx, tst := range []struct {
		password      string
		skipMsg2Error bool
		err           string
	}{
		// Correct password, should succeed.
		{"password", false, ""},
		// Check that client detects a wrong password.
		{"wrong password", false, "client: Authtag mismatch"},
		// Check that server detects a wrong password.
		{"wrong password", true, "server: crypto/rsa: verification error"},
	} {
		fmt.Printf("Test %d: %v\n", idx, tst)
		err = authenticate(privS, user, tst.password, nil, nil, nil, tst.skipMsg2Error)
		if err == nil {
			if tst.err != "" {
				t.Fatalf("Expected error '%s', got nil", tst.err)
			}
		} else {
			if err.Error() != tst.err {
				t.Fatalf("Expected error '%s', got '%s'", tst.err, err)
			}
		}
	}

	// Test that various corrupt messages are detected properly. The
	// corruption might be due to an adversary who has modified messages
	// in-flight.
	for idx, tst := range []struct {
		msg1Mod func(*AuthMsg1)
		msg2Mod func(*AuthMsg2)
		msg3Mod func(*AuthMsg3)
		err     string
	}{
		{func(msg1 *AuthMsg1) { msg1.A.SetInt64(0) }, nil, nil, "server: a is not in D-H group"},
		{func(msg1 *AuthMsg1) { msg1.A.SetInt64(1) }, nil, nil, "server: a is in a small subgroup"},
		{func(msg1 *AuthMsg1) { msg1.DhPubClient = big.NewInt(123) }, nil, nil, "client: crypto/rsa: verification error"},

		{nil, func(msg2 *AuthMsg2) { msg2.V.SetInt64(0) }, nil, "client: v is not in D-H group"},
		{nil, func(msg2 *AuthMsg2) { msg2.V.SetInt64(1) }, nil, "client: v is in a small subgroup"},
		{nil, func(msg2 *AuthMsg2) { msg2.B.SetInt64(0) }, nil, "client: b is not in D-H group"},
		{nil, func(msg2 *AuthMsg2) { msg2.B.SetInt64(1) }, nil, "client: b is in a small subgroup"},
		{nil, func(msg2 *AuthMsg2) { msg2.EnvU = append([]byte(nil), msg2.EnvU...); msg2.EnvU[0] ^= 42 }, nil, "client: Authtag mismatch"},
		{nil, func(msg2 *AuthMsg2) { msg2.DhSig[0] ^= 42 }, nil, "client: crypto/rsa: verification error"},
		{nil, func(msg2 *AuthMsg2) { msg2.DhMac[0] ^= 42 }, nil, "client: MAC mismatch"},
		{nil, func(msg2 *AuthMsg2) { msg2.DhPubServer = big.NewInt(-123) }, nil, "client: crypto/rsa: verification error"},
		{nil, func(msg2 *AuthMsg2) { msg2.DhPubServer = big.NewInt(123) }, nil, "client: crypto/rsa: verification error"},

		{nil, nil, func(msg3 *AuthMsg3) { msg3.DhSig[0] ^= 42 }, "server: crypto/rsa: verification error"},
		{nil, nil, func(msg3 *AuthMsg3) { msg3.DhMac[0] ^= 42 }, "server: MAC mismatch"},
	} {
		fmt.Printf("Test %d: %v\n", idx, tst)
		err = authenticate(privS, user, "password", tst.msg1Mod, tst.msg2Mod, tst.msg3Mod, false)
		if err == nil {
			if tst.err != "" {
				t.Fatalf("Expected error '%s', got nil", tst.err)
			}
		} else {
			if err.Error() != tst.err {
				t.Fatalf("Expected error '%s', got '%s'", tst.err, err)
			}
		}
	}
}

// authenticate attempts to authenticate with the server using the given
// credentials.
func authenticate(privS *rsa.PrivateKey, user *User, password string, msg1Mod func(*AuthMsg1), msg2Mod func(*AuthMsg2), msg3Mod func(*AuthMsg3), skipMsg2Error bool) error {
	cAuthSession, amsg1, err := AuthInit(user.Username, password)
	if err != nil {
		return err
	}
	if msg1Mod != nil {
		msg1Mod(&amsg1)
	}

	sAuthSession, amsg2, err := Auth1(privS, user, amsg1)
	if err != nil {
		return fmt.Errorf("server: %s", err)
	}
	if msg2Mod != nil {
		msg2Mod(&amsg2)
	}

	cSharedSecret, amsg3, err := Auth2(cAuthSession, amsg2)
	if !skipMsg2Error && err != nil {
		return fmt.Errorf("client: %s", err)
	}
	if msg3Mod != nil {
		msg3Mod(&amsg3)
	}

	sSharedSecret, err := Auth3(sAuthSession, amsg3)
	if err != nil {
		return fmt.Errorf("server: %s", err)
	}
	if !bytes.Equal(cSharedSecret, sSharedSecret) {
		return fmt.Errorf("Shared secrets differ")
	}
	return nil
}

func TestDhSecrets(t *testing.T) {
	priv, err := generatePrivateKey(dhGroup)
	if err != nil {
		t.Fatal(err)
	}
	pub := generatePublicKey(dhGroup, priv)
	shared, key, err := dhSecrets(priv, pub)
	if len(shared) < 16 {
		t.Fatalf("len(shared) = %d < 16", len(shared))
	}
	if len(key) < 16 {
		t.Fatalf("len(key) = %d < 16", len(key))
	}
	if bytes.Equal(shared, key) {
		t.Fatalf("shared = key = %v", shared)
	}
}
