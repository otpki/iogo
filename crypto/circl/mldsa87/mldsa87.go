// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mldsa87

import (
	"io"

	circlSign "github.com/otpki/circl/sign"
	circlMldsa87 "github.com/otpki/circl/sign/mldsa/mldsa87"
)

type PublicKey = circlMldsa87.PublicKey
type PrivateKey = circlMldsa87.PrivateKey

func GenerateKey(rand io.Reader) (circlSign.PublicKey, circlSign.PrivateKey, error) {
	return circlMldsa87.GenerateKey(rand)
}
