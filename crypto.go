// Copyright (c) 2018 Fredrik Kuivinen, frekui@gmail.com
//
// Use of this source code is governed by the BSD-style license that can be
// found in the LICENSE file.

package opaque

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"hash"
)

var randr = rand.Reader

// This hash function is used as H from the I-D.
func hasher() hash.Hash {
	return sha256.New()
}

var hasherId = crypto.SHA256
