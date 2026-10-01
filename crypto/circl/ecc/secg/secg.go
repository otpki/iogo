// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package secg

import (
	"github.com/otpki/circl/ecc"
	"github.com/otpki/circl/ecc/secg"
)

func Secp192r1() ecc.Curve {
	return secg.Secp192r1()
}

func Secp224r1() ecc.Curve {
	return secg.Secp224r1()
}

func Secp256r1() ecc.Curve {
	return secg.Secp256r1()
}

func Secp384r1() ecc.Curve {
	return secg.Secp384r1()
}

func Secp521r1() ecc.Curve {
	return secg.Secp521r1()
}

// binary parameters

func Sect113r1() ecc.BinaryCurve {
	return secg.Sect113r1()
}

func Sect113r2() ecc.BinaryCurve {
	return secg.Sect113r2()
}

func Sect131r1() ecc.BinaryCurve {
	return secg.Sect131r1()
}

func Sect131r2() ecc.BinaryCurve {
	return secg.Sect131r2()
}

func Sect163k1() ecc.BinaryCurve {
	return secg.Sect163k1()
}

func Sect163r1() ecc.BinaryCurve {
	return secg.Sect163r1()
}

func Sect163r2() ecc.BinaryCurve {
	return secg.Sect163r2()
}

func Sect193r1() ecc.BinaryCurve {
	return secg.Sect193r1()
}

func Sect193r2() ecc.BinaryCurve {
	return secg.Sect193r2()
}

func Sect233k1() ecc.BinaryCurve {
	return secg.Sect233k1()
}

func Sect233r1() ecc.BinaryCurve {
	return secg.Sect233r1()
}

func Sect239k1() ecc.BinaryCurve {
	return secg.Sect239k1()
}

func Sect283k1() ecc.BinaryCurve {
	return secg.Sect283k1()
}

func Sect283r1() ecc.BinaryCurve {
	return secg.Sect283r1()
}

func Sect409k1() ecc.BinaryCurve {
	return secg.Sect409k1()
}

func Sect409r1() ecc.BinaryCurve {
	return secg.Sect409r1()
}

func Sect571k1() ecc.BinaryCurve {
	return secg.Sect571k1()
}

func Sect571r1() ecc.BinaryCurve {
	return secg.Sect571r1()
}
