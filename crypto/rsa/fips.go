package rsa

// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/**
 * Partial source from crypto/internal/fips140/rsa
 */

import (
	"crypto/fips140"
	"crypto/rsa"
	"errors"
	"hash"
)

var ErrMessageTooLong = errors.New("crypto/rsa: message too long for RSA key size")

// PSSMaxSaltLength returns the maximum salt length for a given public key and
// hash function.
func PSSMaxSaltLength(pub *rsa.PublicKey, hash hash.Hash) (int, error) {
	saltLength := (pub.N.BitLen()-1+7)/8 - 2 - hash.Size()
	if saltLength < 0 {
		return 0, ErrMessageTooLong
	}
	// FIPS 186-5, Section 5.4(g): "the length (in bytes) of the salt (sLen)
	// shall satisfy 0 ≤ sLen ≤ hLen".
	if fips140.Enabled() && saltLength > hash.Size() {
		return hash.Size(), nil
	}
	return saltLength, nil
}
