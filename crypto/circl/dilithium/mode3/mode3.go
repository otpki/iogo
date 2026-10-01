// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mode3

import (
	"io"

	circlSign "github.com/otpki/circl/sign"
	circlMode3 "github.com/otpki/circl/sign/dilithium/mode3"
)

func GenerateKey(rand io.Reader) (circlSign.PublicKey, circlSign.PrivateKey, error) {
	return circlMode3.GenerateKey(rand)
}
