// Copyright (c) 2018 Fredrik Kuivinen, frekui@gmail.com
//
// Use of this source code is governed by the BSD-style license that can be
// found in the LICENSE file.

// Package util contains functions to simplify the example server and client in
// cmd/.
package util

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/frekui/opaque/internal/pkg/authenc"
)

func Write(w *bufio.Writer, data []byte) error {
	fmt.Printf("> %s\n", string(data))
	w.Write(data)
	w.Write([]byte("\n"))
	if err := w.Flush(); err != nil {
		return err
	}

	return nil
}

func Read(r *bufio.Reader) ([]byte, error) {
	fmt.Print("< ")
	data, err := r.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	fmt.Print(string(data))
	return data[:len(data)-1], nil
}

func EncryptAndWrite(w *bufio.Writer, key []byte, plaintext string) error {
	ciphertext, err := authenc.AuthEnc(rand.Reader, key, []byte(plaintext))
	if err != nil {
		return err
	}
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(ciphertext)))
	base64.StdEncoding.Encode(encoded, ciphertext)
	if err := Write(w, encoded); err != nil {
		return err
	}
	return nil
}

func ReadAndDecrypt(r *bufio.Reader, key []byte) (string, error) {
	encodedCiphertext, err := Read(r)
	if err != nil {
		return "", err
	}
	ciphertext := make([]byte, base64.StdEncoding.DecodedLen(len(encodedCiphertext)))
	n, err := base64.StdEncoding.Decode(ciphertext, encodedCiphertext)
	if err != nil {
		return "", err
	}
	ciphertext = ciphertext[:n]
	plaintext, err := authenc.AuthDec(key, ciphertext)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
