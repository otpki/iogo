// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ed448

import (
	"io"

	circlSign "github.com/otpki/circl/sign"
	circlEd448 "github.com/otpki/circl/sign/ed448"
)

func GenerateKey(rand io.Reader) (circlSign.PublicKey, circlSign.PrivateKey, error) {
	return circlEd448.GenerateKey(rand)
}
