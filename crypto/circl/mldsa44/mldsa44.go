// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mldsa44

import (
	"io"

	circlSign "github.com/otpki/circl/sign"
	circlMldsa44 "github.com/otpki/circl/sign/mldsa/mldsa44"
)

type PublicKey = circlMldsa44.PublicKey
type PrivateKey = circlMldsa44.PrivateKey

func GenerateKey(rand io.Reader) (circlSign.PublicKey, circlSign.PrivateKey, error) {
	return circlMldsa44.GenerateKey(rand)
}
