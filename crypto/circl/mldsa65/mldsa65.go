// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mldsa65

import (
	"io"

	circlSign "github.com/otpki/circl/sign"
	circlMldsa65 "github.com/otpki/circl/sign/mldsa/mldsa65"
)

type PublicKey = circlMldsa65.PublicKey
type PrivateKey = circlMldsa65.PrivateKey

func GenerateKey(rand io.Reader) (circlSign.PublicKey, circlSign.PrivateKey, error) {
	return circlMldsa65.GenerateKey(rand)
}
