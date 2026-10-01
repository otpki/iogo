// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package eddilithium3

import (
	"io"

	circlSign "github.com/otpki/circl/sign"
	circlEddilithium3 "github.com/otpki/circl/sign/eddilithium3"
)

func GenerateKey(rand io.Reader) (circlSign.PublicKey, circlSign.PrivateKey, error) {
	return circlEddilithium3.GenerateKey(rand)
}
