// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nist

import (
	"github.com/cloudflare/circl/ecc"
	"github.com/cloudflare/circl/ecc/nist"
)

func P192() ecc.Curve {
	return nist.P192()
}

func P224() ecc.Curve {
	return nist.P224()
}

func P256() ecc.Curve {
	return nist.P256()
}

func P384() ecc.Curve {
	return nist.P384()
}

func P521() ecc.Curve {
	return nist.P521()
}

// binary parameters

func K163() ecc.BinaryCurve {
	return nist.K163()
}

func B163() ecc.BinaryCurve {
	return nist.B163()
}

func K233() ecc.BinaryCurve {
	return nist.K233()
}

func B233() ecc.BinaryCurve {
	return nist.B233()
}

func K283() ecc.BinaryCurve {
	return nist.K283()
}

func B283() ecc.BinaryCurve {
	return nist.B283()
}

func K409() ecc.BinaryCurve {
	return nist.K409()
}

func B409() ecc.BinaryCurve {
	return nist.B409()
}

func K571() ecc.BinaryCurve {
	return nist.K571()
}

func B571() ecc.BinaryCurve {
	return nist.B571()
}
