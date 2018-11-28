// Copyright (c) 2018 Fredrik Kuivinen, frekui@gmail.com
//
// Use of this source code is governed by the BSD-style license that can be
// found in the LICENSE file.

package authenc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"io/ioutil"

	"golang.org/x/crypto/hkdf"
)

// var debug = os.Stdout
var debug = ioutil.Discard

func hasher() hash.Hash {
	return sha256.New()
}

// AuthEnc performs authenticated encryption of the provided input using the
// provided key. AES-128 is used in CBC mode with HMAC-SHA256 in
// encrypt-then-authenticate mode. The output is IV || ciphertext || auth-tag,
// where "||" is concatenation of byte slices.
//
// On success the ciphertext is returned together with a nil error.
//
// See also AuthDec.
func AuthEnc(randr io.Reader, key []byte, plaintext []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("Got key length %d, expected 16", len(key))
	}
	kdfr := hkdf.New(hasher, key, nil, nil)
	cbcKey := make([]byte, 16)
	hmacKey := make([]byte, 16)
	fmt.Fprintf(debug, "AuthEnc: hmacKey %v\n", hmacKey)
	_, err := io.ReadFull(kdfr, cbcKey)
	if err != nil {
		return nil, err
	}
	_, err = io.ReadFull(kdfr, hmacKey)
	if err != nil {
		return nil, err
	}
	ciph, err := aes.NewCipher(cbcKey)
	if err != nil {
		panic("aes.NewCipher failed")
	}
	iv := make([]byte, ciph.BlockSize())
	_, err = io.ReadFull(randr, iv)
	if err != nil {
		return nil, err
	}
	enc := cipher.NewCBCEncrypter(ciph, iv)
	numBlocks := len(plaintext)/ciph.BlockSize() + 1
	res := make([]byte,
		ciph.BlockSize()+ // IV
			numBlocks*ciph.BlockSize()+ // cipher text, including padding
			hasher().Size()+ // authtag
			0)
	// Copy IV to res.
	copy(res, iv)
	// Encrypt all blocks except for the last one and store the result in res.
	enc.CryptBlocks(res[ciph.BlockSize():], plaintext[0:(numBlocks-1)*ciph.BlockSize()])
	// Pad and encrypt the last block. Store the result in res.
	lastBlock := addPadding(ciph.BlockSize(), plaintext[(numBlocks-1)*ciph.BlockSize():])
	fmt.Fprintf(debug, "AuthEnc last block: %v\n", lastBlock)
	enc.CryptBlocks(res[ciph.BlockSize()*numBlocks:], lastBlock)
	fmt.Fprintf(debug, "AuthEnc: res (before HMAC): %v\n", res)

	mac := hmac.New(hasher, hmacKey)
	fmt.Fprintf(debug, "AuthEnc mac.Write %v\n", res)
	if _, err = mac.Write(res[0 : ciph.BlockSize()*(numBlocks+1)]); err != nil {
		return nil, err
	}
	authtag := mac.Sum(nil)
	fmt.Fprintf(debug, "AuthEnc: authtag: %v\n", authtag)
	copy(res[ciph.BlockSize()*(numBlocks+1):], authtag)
	fmt.Fprintf(debug, "AuthEnc: res: %v\n", res)
	return res, nil
}

// AuthtagMismatch is returned by AuthDec if authentication of the ciphertext
// failed.
var AuthtagMismatch = fmt.Errorf("Authtag mismatch")

// AuthDec performs authenticated decryption of the provided input using the
// provided key. See AuthEnc for more details.
//
// On success the plaintext is returned together with a nil error.
func AuthDec(key []byte, input []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("Got key length %d, expected 16", len(key))
	}
	if len(input) < 3*16 {
		return nil, fmt.Errorf("AuthDec: Input too short")
	}
	if len(input)%16 != 0 {
		return nil, fmt.Errorf("AuthDec: Invalid input length")
	}
	iv := input[:16]
	ciphertext := input[16 : len(input)-hasher().Size()]
	authtag := input[len(input)-hasher().Size():]
	fmt.Fprintf(debug, "AuthDec: iv: %v\n", iv)
	fmt.Fprintf(debug, "AuthDec: ciphertext: %v\n", ciphertext)
	fmt.Fprintf(debug, "AuthDec: authtag: %v\n", authtag)

	kdfr := hkdf.New(hasher, key, nil, nil)
	cbcKey := make([]byte, 16)
	hmacKey := make([]byte, 16)
	fmt.Fprintf(debug, "AuthDec: hmacKey %v\n", hmacKey)
	_, err := io.ReadFull(kdfr, cbcKey)
	if err != nil {
		return nil, err
	}
	_, err = io.ReadFull(kdfr, hmacKey)
	if err != nil {
		return nil, err
	}

	mac := hmac.New(hasher, hmacKey)
	fmt.Fprintf(debug, "AuthDec mac.Write %v\n", iv)
	if _, err = mac.Write(iv); err != nil {
		return nil, err
	}
	fmt.Fprintf(debug, "AuthDec mac.Write %v\n", ciphertext)
	if _, err = mac.Write(ciphertext); err != nil {
		return nil, err
	}
	fmt.Fprintf(debug, "AuthDec hmac.Sum: %v\n", mac.Sum(nil))
	if !hmac.Equal(mac.Sum(nil), authtag) {
		return nil, AuthtagMismatch
	}

	ciph, err := aes.NewCipher(cbcKey)
	if err != nil {
		panic("aes.NewCipher failed")
	}
	enc := cipher.NewCBCDecrypter(ciph, iv)
	plaintext := make([]byte, len(ciphertext))
	enc.CryptBlocks(plaintext, ciphertext)
	fmt.Fprintf(debug, "AuthDec plaintext: %v\n", plaintext)
	plaintext = removePadding(ciph.BlockSize(), plaintext)
	return plaintext, nil
}

// addPadding pads "input" using the padding algorithm from
// https://tools.ietf.org/html/rfc5652#section-6.3
func addPadding(blockSize int, input []byte) []byte {
	out := make([]byte, blockSize*(len(input)/blockSize+1))
	copy(out, input)
	var b byte = byte(blockSize - len(input)%blockSize)
	for i := len(input); i < len(out); i++ {
		out[i] = b
	}
	return out
}

// removePadding removes the padding from "input". See also addPadding.
func removePadding(blockSize int, input []byte) []byte {
	if len(input)%blockSize != 0 {
		panic("removePadding: Input length is not a multiple of block size")
	}
	if len(input) == 0 {
		panic("removePadding: Empty input")
	}
	b := input[len(input)-1]
	if int(b) > blockSize {
		panic("removePadding: Invalid padding")
	}
	input = input[:len(input)-int(b)]
	return input
}
