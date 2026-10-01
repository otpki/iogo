// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package slhdsa

import (
	"io"

	circlSign "github.com/otpki/circl/sign"
	circlSlhdsa "github.com/otpki/circl/sign/slhdsa"
)

type ID = circlSlhdsa.ID

const (
	SHA2_128s  ID = iota + 1 // SLH-DSA-SHA2-128s
	SHAKE_128s               // SLH-DSA-SHAKE-128s
	SHA2_128f                // SLH-DSA-SHA2-128f
	SHAKE_128f               // SLH-DSA-SHAKE-128f
	SHA2_192s                // SLH-DSA-SHA2-192s
	SHAKE_192s               // SLH-DSA-SHAKE-192s
	SHA2_192f                // SLH-DSA-SHA2-192f
	SHAKE_192f               // SLH-DSA-SHAKE-192f
	SHA2_256s                // SLH-DSA-SHA2-256s
	SHAKE_256s               // SLH-DSA-SHAKE-256s
	SHA2_256f                // SLH-DSA-SHA2-256f
	SHAKE_256f               // SLH-DSA-SHAKE-256f
	_MaxParams
)

func GenerateKey(rand io.Reader, id ID) (circlSign.PublicKey, circlSign.PrivateKey, error) {
	return circlSlhdsa.GenerateKey(rand, id)
}
