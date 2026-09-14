// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pki

import (
	circlPki "github.com/cloudflare/circl/pki"
	circlSign "github.com/cloudflare/circl/sign"
)

func UnmarshalPKIXPrivateKey(data []byte) (circlSign.PrivateKey, error) {
	return circlPki.UnmarshalPKIXPrivateKey(data)
}

func UnmarshalPKIXPublicKey(data []byte) (circlSign.PublicKey, error) {
	return circlPki.UnmarshalPKIXPublicKey(data)
}
