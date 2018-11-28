// Copyright (c) 2018 Fredrik Kuivinen, frekui@gmail.com
//
// Use of this source code is governed by the BSD-style license that can be
// found in the LICENSE file.

package opaque

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// envU is information stored encrypted on the server. The encryption key is
// derived from the password together with the salt.
type envU struct {
	// pubU is privU.Public()
	privU *rsa.PrivateKey
	pubS  *rsa.PublicKey
}

// decodeEnvU decodes an envU from a slice of bytes.
func decodeEnvU(pemdata []byte) (envU, error) {
	privblock, pemdata := pem.Decode(pemdata)
	if privblock == nil {
		return envU{}, fmt.Errorf("Failed to decode private key")
	}
	if privblock.Type != "RSA PRIVATE KEY" {
		return envU{}, fmt.Errorf("Unexpected type of block: %s", privblock.Type)
	}
	privkey, err := x509.ParsePKCS1PrivateKey(privblock.Bytes)
	if err != nil {
		return envU{}, err
	}
	pubblock, _ := pem.Decode(pemdata)
	if pubblock == nil {
		return envU{}, fmt.Errorf("Failed to decode public key")
	}
	if pubblock.Type != "RSA PUBLIC KEY" {
		return envU{}, fmt.Errorf("Unexpected type of block: %s", pubblock.Type)
	}
	pubkey, err := x509.ParsePKCS1PublicKey(pubblock.Bytes)
	if err != nil {
		return envU{}, err
	}
	return envU{privU: privkey, pubS: pubkey}, nil
}

// encodeEnvU encodes an envU as a slice of bytes.
func encodeEnvU(env *envU) []byte {
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(env.privU),
		},
	)
	pemdata = append(pemdata, pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(env.pubS),
		},
	)...)
	return pemdata
}
