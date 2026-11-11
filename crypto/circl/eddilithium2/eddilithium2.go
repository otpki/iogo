// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package eddilithium2

import (
	"io"

	circlSign "github.com/cloudflare/circl/sign"
	circlEddilithium2 "github.com/cloudflare/circl/sign/eddilithium2"
)

func GenerateKey(rand io.Reader) (circlSign.PublicKey, circlSign.PrivateKey, error) {
	return circlEddilithium2.GenerateKey(rand)
}
