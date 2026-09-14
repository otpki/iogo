// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mode2

import (
	"io"

	circlSign "github.com/cloudflare/circl/sign"
	circlMode2 "github.com/cloudflare/circl/sign/dilithium/mode2"
)

func GenerateKey(rand io.Reader) (circlSign.PublicKey, circlSign.PrivateKey, error) {
	return circlMode2.GenerateKey(rand)
}
