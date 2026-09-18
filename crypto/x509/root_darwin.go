// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

// macOS has no default SSL_CERT_{FILE,DIR} paths.
var certFiles, certDirectories []string

func (c *Certificate) systemVerify(options *VerifyOptions) ([][]*Certificate, error) {
	return nil, nil
}
