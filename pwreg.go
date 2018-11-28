// Copyright (c) 2018 Fredrik Kuivinen, frekui@gmail.com
//
// Use of this source code is governed by the BSD-style license that can be
// found in the LICENSE file.

package opaque

// References:
// OPAQUE: An Asymmetric PAKE Protocol Secure Against Pre-Computation Attacks, https://eprint.iacr.org/2018/163.pdf
// https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-00
// http://webee.technion.ac.il/~hugo/sigma-pdf.pdf

import (
	"crypto/rsa"
	"math/big"

	"github.com/frekui/opaque/internal/pkg/authenc"
)

// The User struct is the state that the server needs to store for each
// registered used. Values of this struct are created by PwReg3.
type User struct {
	// Name of this user.
	Username string

	// OPRF key for this user. This is the salt.
	K *big.Int

	V *big.Int

	// EnvU and PubU are generated by the client during password
	// registration and stored at the server.
	EnvU []byte
	PubU *rsa.PublicKey
}

// PwRegServerSession keeps track of state needed on the server-side during a
// run of the password registration protocol.
type PwRegServerSession struct {
	username string
	k        *big.Int
	v        *big.Int
}

// PwRegClientSession keeps track of state needed on the client-side during a
// run of the password registration protocol.
type PwRegClientSession struct {
	a *big.Int

	// Random integer in [0..q-1]. Used when computing DF-OPRF.
	r *big.Int

	password string

	// Number of bits in RSA private key.
	bits int
}

// PwRegMsg1 is the first message during password registration. It is sent from
// the client to the server.
//
// Users of package opaque does not need to read nor write to any fields in this
// struct except to serialize and deserialize the struct when it's sent between
// the peers in the authentication protocol.
type PwRegMsg1 struct {
	Username string
	R        *big.Int
	A        *big.Int
}

// PwRegMsg2 is the second message in password registration. Sent from server to
// client.
//
// Users of package opaque does not need to read nor write to any fields in this
// struct except to serialize and deserialize the struct when it's sent between
// the peers in the authentication protocol.
type PwRegMsg2 struct {
	V    *big.Int
	B    *big.Int
	PubS *rsa.PublicKey
}

// PwRegMsg3 is the third and final message in password registration. Sent from
// client to server.
//
// Users of package opaque does not need to read nor write to any fields in this
// struct except to serialize and deserialize the struct when it's sent between
// the peers in the authentication protocol.
type PwRegMsg3 struct {
	EnvU []byte
	PubU *rsa.PublicKey
}

// PwRegInit initiates the password registration protocol. It's invoked by the
// client. The bits argument specifies the number of bits that should be used in
// the client-specific RSA key.
//
// On success a nil error is returned together with a client session and a
// PwRegMsg1 struct. The PwRegMsg1 struct should be sent to the server. A
// precondition of the password registration protocol is that it's running over
// an authenticated connection.
//
// A non-nil error is returned on failure.
//
// See also PwReg1, PwReg2, and PwReg3.
func PwRegInit(username, password string, bits int) (*PwRegClientSession, PwRegMsg1, error) {
	// From the I-D:
	//
	//     U and S run OPRF(kU;PwdU) with only U learning the result,
	//     denoted RwdU (mnemonics for "randomized password").
	//
	//     Protocol for computing DH-OPRF, U with input x and S with input k:
	//     U: choose random r in [0..q-1], send a=H'(x)*g^r to S

	a, r, err := dhOprf1(password)
	if err != nil {
		return nil, PwRegMsg1{}, err
	}
	session := &PwRegClientSession{
		a:        a,
		r:        r,
		password: password,
		bits:     bits,
	}
	msg1 := PwRegMsg1{
		Username: username,
		R:        r,
		A:        a,
	}

	return session, msg1, nil
}

// PwReg1 is the processing done by the server when it has received a PwRegMsg1
// struct from a client.
//
// privS is the server's private RSA key. It can be the same for all users.
//
// A non-nil error is returned on failure.
//
// See also PwRegInit, PwReg2, and PwReg3.
func PwReg1(privS *rsa.PrivateKey, msg1 PwRegMsg1) (*PwRegServerSession, PwRegMsg2, error) {
	// From the I-D:
	//
	//    S chooses OPRF key kU (random and independent for each user U) and sets vU
	//    = g^kU; it also chooses its own pair of private-public keys PrivS and PubS
	//    for use with protocol KE (the server can use the same pair of keys with
	//    multiple users), and sends PubS to U.
	//
	//    S: upon receiving a value a, respond with v=g^k and b=a^k
	k, err := generateSalt()
	if err != nil {
		return nil, PwRegMsg2{}, err
	}
	// func dhOprf2(a, k *big.Int) (v *big.Int, b *big.Int)
	v, b, err := dhOprf2(msg1.A, k)
	if err != nil {
		return nil, PwRegMsg2{}, err
	}
	session := &PwRegServerSession{
		username: msg1.Username,
		k:        k,
		v:        v,
	}
	msg2 := PwRegMsg2{V: v, B: b, PubS: &privS.PublicKey}
	return session, msg2, nil
}

// PwReg2 is invoked on the client when it has received a PwRegMsg2 struct from
// the server.
//
// A non-nil error is returned on failure.
//
// See also PwRegInit, PwReg1, and PwReg3.
func PwReg2(sess *PwRegClientSession, msg2 PwRegMsg2) (PwRegMsg3, error) {
	// From the I-D:
	//   U: upon receiving values b and v, set the PRF output to H(x, v, b*v^{-r})
	//
	//   U generates an "envelope" EnvU defined as EnvU = AuthEnc(RwdU; PrivU, PubU,
	//   PubS, vU)

	rwdU, err := dhOprf3(sess.password, msg2.V, msg2.B, sess.r)
	if err != nil {
		return PwRegMsg3{}, err
	}
	privU, err := rsa.GenerateKey(randr, sess.bits)
	if err != nil {
		return PwRegMsg3{}, err
	}
	env := envU{
		privU: privU,
		pubS:  msg2.PubS,
	}

	encodedEnvU := encodeEnvU(&env)
	encryptedEnvU, err := authenc.AuthEnc(randr, rwdU[:16], encodedEnvU)
	if err != nil {
		return PwRegMsg3{}, err
	}
	return PwRegMsg3{EnvU: encryptedEnvU, PubU: &privU.PublicKey}, nil
}

// PwReg3 is invoked on the server after it has received a PwRegMsg3 struct from
// the client.
//
// The returned User struct should be stored by the server and associated with
// the username.
//
// See also PwRegInit, PwReg1, and PwReg2.
func PwReg3(sess *PwRegServerSession, msg3 PwRegMsg3) *User {
	// From the I-D:
	//
	//    o  U sends EnvU and PubU to S and erases PwdU, RwdU and all keys.
	//       S stores (EnvU, PubS, PrivS, PubU, kU, vU) in a user-specific
	//       record.  If PrivS and PubS are used for different users, they can
	//       be stored separately and omitted from the record.
	return &User{
		Username: sess.username,
		K:        sess.k,
		V:        sess.v,
		EnvU:     msg3.EnvU,
		PubU:     msg3.PubU,
	}
}
