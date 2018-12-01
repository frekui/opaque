// Copyright (c) 2018 Fredrik Kuivinen, frekui@gmail.com
//
// Use of this source code is governed by the BSD-style license that can be
// found in the LICENSE file.

package opaque

import (
	"crypto/hmac"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"math/big"

	"github.com/frekui/opaque/internal/pkg/authenc"
	"github.com/frekui/opaque/internal/pkg/dh"
	"golang.org/x/crypto/hkdf"
)

// AuthClientSession keeps track of state needed on the client-side during a
// run of the authentication protocol.
type AuthClientSession struct {
	// Client ephemeral private D-H key for this session.
	x           *big.Int
	dhPubClient *big.Int
	r           *big.Int
	password    string
}

// AuthServerSession keeps track of state needed on the server-side during a
// run of the authentication protocol.
type AuthServerSession struct {
	// Server ephemeral private D-H key for this session.
	y              *big.Int
	dhPubClient    *big.Int
	dhPubServer    *big.Int
	dhMacKey       []byte
	dhSharedSecret []byte
	pubS           *rsa.PublicKey

	user *User
}

// AuthMsg1 is the first message in the authentication protocol. It is sent from
// the client to the server.
//
// Users of package opaque does not need to read nor write to the A or DhPub
// field fields in this struct except to serialize and deserialize the struct
// when it's sent between the peers in the authentication protocol.
type AuthMsg1 struct {
	// From the I-D:
	//   Uid, a=H'(PwdU)*g^r, KE1

	Username string

	// a=H'(x)*g^r
	A *big.Int

	// First message of D-H key-exchange (KE1): g^x
	DhPubClient *big.Int
}

// AuthMsg2 is the second message in the authentication protocol. It is sent
// from the server to the client.
//
// Users of package opaque does not need to read nor write to any fields in this
// struct except to serialize and deserialize the struct when it's sent between
// the peers in the authentication protocol.
type AuthMsg2 struct {
	// From the I-D:
	//   b=a^k, EnvU, KE2

	// v=g^k
	V *big.Int

	// k below is the salt.
	// b=a^k
	B *big.Int

	// EnvU contains data encrypted by the client which is stored
	// server-side.
	EnvU []byte

	// Second message of D-H key-exchange (KE2): g^y, Sig(PrivS; g^x, g^y), Mac(Km1; IdS)
	// g^y
	DhPubServer *big.Int

	// Sig(PrivS; g^x, g^y)
	// RSASSA-PSS is used to compute dhSig.
	DhSig []byte

	// Mac(Km1; IdS)
	DhMac []byte
}

// After receiving AuthMsg2 client can compute RwdU as H(x, v, b*v^{-r}).
//
// Client can now decrypt envU, which contains PrivU and PubS. Using PubS the
// client can verify the signature AuthMsg2.DhSig. With PrivU the client can
// compute AuthMsg3.DhSig.

// AuthMsg3 is the third and final message in the authentication protocol. It is sent from
// the client to the server.
//
// Users of package opaque does not need to read nor write to any fields in this
// struct except to serialize and deserialize the struct when it's sent between
// the peers in the authentication protocol.
type AuthMsg3 struct {
	// From the I-D:
	//   KE3

	// Third message of D-H key exchange (KE3): Sig(PrivU; g^y, g^x), Mac(Km2; IdU)
	// RSASSA-PSS is used to compute dhSig.
	DhSig []byte

	// Mac(Km2; IdU)
	DhMac []byte
}

// AuthInit initiates the authentication protocol. It's run on the client and,
// on success, returns a nil error, a client auth session, and an AuthMsg1
// struct. The AuthMsg1 struct should be sent to the server.
//
// A non-nil error is returned on failure.
//
// See also Auth1, Auth2, and Auth3.
func AuthInit(username, password string) (*AuthClientSession, AuthMsg1, error) {
	var sess AuthClientSession
	sess.password = password
	var msg1 AuthMsg1
	var err error
	msg1.Username = username

	msg1.A, sess.r, err = dhOprf1(password)
	if err != nil {
		return nil, AuthMsg1{}, err
	}
	sess.x, err = dh.GeneratePrivateKey(dhGroup)
	if err != nil {
		return nil, AuthMsg1{}, err
	}
	sess.dhPubClient = dh.GeneratePublicKey(dhGroup, sess.x)
	msg1.DhPubClient = sess.dhPubClient

	return &sess, msg1, nil
}

// Auth1 is the processing done by the server when it receives an AuthMsg1
// struct. On success a nil error is returned together with a AuthServerSession
// and an AuthMsg2 struct. The AuthMsg2 struct should be sent to the client.
//
// privS is the server's private RSA key. It can be the same for all users. The
// user argument needs to be created by the server (e.g., by looking it up based
// on msg1.Username).
//
// A non-nil error is returned on failure.
//
// See also AuthInit, Auth2, and Auth3.
func Auth1(privS *rsa.PrivateKey, user *User, msg1 AuthMsg1) (*AuthServerSession, AuthMsg2, error) {
	y, err := dh.GeneratePrivateKey(dhGroup)
	if err != nil {
		return nil, AuthMsg2{}, err
	}
	var msg2 AuthMsg2

	msg2.V, msg2.B, err = dhOprf2(msg1.A, user.K)
	if err != nil {
		return nil, AuthMsg2{}, err
	}
	msg2.EnvU = user.EnvU
	msg2.DhPubServer = dh.GeneratePublicKey(dhGroup, y)

	h := hasher()
	h.Write(dhGroup.Bytes(msg1.DhPubClient))
	h.Write(dhGroup.Bytes(msg2.DhPubServer))
	sig, err := rsa.SignPSS(randr, privS, hasherId, h.Sum(nil), nil)
	if err != nil {
		return nil, AuthMsg2{}, err
	}
	msg2.DhSig = sig
	dhSharedSecret, dhMacKey, err := dhSecrets(y, msg1.DhPubClient)
	if err != nil {
		return nil, AuthMsg2{}, err
	}
	msg2.DhMac = computeDhMac(dhMacKey, &privS.PublicKey)
	session := &AuthServerSession{
		y:              y,
		dhPubServer:    msg2.DhPubServer,
		dhPubClient:    msg1.DhPubClient,
		pubS:           &privS.PublicKey,
		user:           user,
		dhMacKey:       dhMacKey,
		dhSharedSecret: dhSharedSecret,
	}
	return session, msg2, nil
}

// Auth2 is the processing done by the client when it receives an AuthMsg2
// struct. On success a nil error is returned together with a secret byte slice
// and an AuthMsg3 struct. The AuthMsg3 struct should be sent to the server. On
// a successful completion of the protocol the secret will be shared between the
// client and the server. Auth2 is the final round in the authentication
// protocol for the client.
//
// If Auth2 returns a nil error the client has authenticated the server
// (i.e., the server has proved to the client that it posses information
// obtained from the password registration protocol for this user).
//
// A non-nil error is returned on failure.
//
// See also InitAuth, Auth1, and Auth3.
func Auth2(sess *AuthClientSession, msg2 AuthMsg2) (secret []byte, msg3 AuthMsg3, err error) {
	rwdU, err := dhOprf3(sess.password, msg2.V, msg2.B, sess.r)
	if err != nil {
		return nil, AuthMsg3{}, err
	}
	encodedEnvU, err := authenc.AuthDec(rwdU[:16], msg2.EnvU)
	if err != nil {
		return nil, AuthMsg3{}, err
	}
	envU, err := decodeEnvU(encodedEnvU)
	if err != nil {
		return nil, AuthMsg3{}, err
	}
	h := hasher()
	h.Write(dhGroup.Bytes(sess.dhPubClient))
	h.Write(dhGroup.Bytes(msg2.DhPubServer))
	err = rsa.VerifyPSS(envU.pubS, hasherId, h.Sum(nil), msg2.DhSig, nil)
	if err != nil {
		return nil, AuthMsg3{}, err
	}
	dhSharedSecret, dhMacKey, err := dhSecrets(sess.x, msg2.DhPubServer)
	if err != nil {
		return nil, AuthMsg3{}, err
	}
	if !verifyDhMac(dhMacKey, envU.pubS, msg2.DhMac) {
		return nil, AuthMsg3{}, errors.New("MAC mismatch")
	}
	sig, err := rsa.SignPSS(randr, envU.privU, hasherId, h.Sum(nil), nil)
	if err != nil {
		return nil, AuthMsg3{}, err
	}
	mac := computeDhMac(dhMacKey, &envU.privU.PublicKey)
	return dhSharedSecret, AuthMsg3{DhSig: sig, DhMac: mac}, nil
}

// Auth3 is the processing done by the server when it receives an AuthMsg3
// struct. On success a nil error is returned together with a secret. On
// successful completion the secret returned by this function is equal to the
// secret returned by Auth2 invoked on the client. Auth3 is the final round in
// the authentication protocol.
//
// If Auth3 returns a nil error the server has authenticated the client (i.e.,
// the client has proved to the server that it posses information used when the
// password registration protocol ran for this user).
//
// A non-nil error is returned on failure.
//
// See also AuthInit, Auth1, and Auth2.
func Auth3(sess *AuthServerSession, msg3 AuthMsg3) (secret []byte, err error) {
	h := hasher()
	h.Write(dhGroup.Bytes(sess.dhPubClient))
	h.Write(dhGroup.Bytes(sess.dhPubServer))
	err = rsa.VerifyPSS(sess.user.PubU, hasherId, h.Sum(nil), msg3.DhSig, nil)
	if err != nil {
		return nil, err
	}
	if !verifyDhMac(sess.dhMacKey, sess.user.PubU, msg3.DhMac) {
		return nil, errors.New("MAC mismatch")
	}
	return sess.dhSharedSecret, nil
}

func computeDhMac(key []byte, pk *rsa.PublicKey) []byte {
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(pk),
		},
	)
	mac := hmac.New(hasher, key)
	mac.Write(pemdata)
	return mac.Sum(nil)
}

func verifyDhMac(key []byte, pk *rsa.PublicKey, origMac []byte) bool {
	mac := computeDhMac(key, pk)
	return hmac.Equal(mac, origMac)
}

func dhSecrets(dhPriv, dhPub *big.Int) (dhSharedSecret, dhMacKey []byte, err error) {
	kdf := hkdf.New(hasher, dh.SharedSecret(dhGroup, dhPriv, dhPub), nil, nil)
	dhSharedSecret = make([]byte, 16)
	dhMacKey = make([]byte, 16)
	_, err = io.ReadFull(kdf, dhSharedSecret)
	if err != nil {
		return
	}
	_, err = io.ReadFull(kdf, dhMacKey)
	if err != nil {
		return
	}
	return
}
