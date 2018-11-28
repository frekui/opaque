// Copyright (c) 2018 Fredrik Kuivinen, frekui@gmail.com
//
// Use of this source code is governed by the BSD-style license that can be
// found in the LICENSE file.

package opaque

import (
	"bytes"
	"crypto/rsa"
	"fmt"
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
	// Correct password, should succeed.
	err = authenticate(privS, user, "password", false)
	if err != nil {
		t.Fatal(err)
	}
	// Check that client detects a wrong password.
	err = authenticate(privS, user, "wrong password", false)
	if err.Error() != "client: Authtag mismatch" {
		t.Fatal(err)
	}
	// Check that server detects a wrong password.
	err = authenticate(privS, user, "wrong password", true)
	if err.Error() != "server: crypto/rsa: verification error" {
		t.Fatal(err)
	}
}

// authenticate attempts to authenticate with the server using the given
// credentials.
func authenticate(privS *rsa.PrivateKey, user *User, password string, skipMsg2Error bool) error {
	cAuthSession, amsg1, err := AuthInit(user.Username, password)
	if err != nil {
		return err
	}

	sAuthSession, amsg2, err := Auth1(privS, user, amsg1)
	if err != nil {
		return err
	}

	cSharedSecret, amsg3, err := Auth2(cAuthSession, amsg2)
	if !skipMsg2Error && err != nil {
		return fmt.Errorf("client: %s", err)
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
