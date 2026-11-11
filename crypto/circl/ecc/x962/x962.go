// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x962

import (
	"github.com/cloudflare/circl/ecc"
	"github.com/cloudflare/circl/ecc/x962"
)

func Prime192v1() ecc.Curve {
	return x962.Prime192v1()
}

func Prime192v2() ecc.Curve {
	return x962.Prime192v2()
}

func Prime192v3() ecc.Curve {
	return x962.Prime192v3()
}

func Prime239v1() ecc.Curve {
	return x962.Prime192v3()
}

func Prime239v2() ecc.Curve {
	return x962.Prime192v3()
}

func Prime239v3() ecc.Curve {
	return x962.Prime192v3()
}

func Prime256v1() ecc.Curve {
	return x962.Prime256v1()
}

// binary fields

func C2pnb176w1() ecc.BinaryCurve {
	return x962.C2pnb176w1()
}

func C2pnb163v1() ecc.BinaryCurve {
	return x962.C2pnb163v1()
}

func C2pnb163v2() ecc.BinaryCurve {
	return x962.C2pnb163v2()
}

func C2pnb163v3() ecc.BinaryCurve {
	return x962.C2pnb163v3()
}

func C2pnb208w1() ecc.BinaryCurve {
	return x962.C2pnb208w1()
}

func C2tnb191v3() ecc.BinaryCurve {
	return x962.C2tnb191v3()
}

func C2tnb191v2() ecc.BinaryCurve {
	return x962.C2tnb191v2()
}

func C2tnb191v1() ecc.BinaryCurve {
	return x962.C2tnb191v1()
}

func C2tnb239v3() ecc.BinaryCurve {
	return x962.C2tnb239v3()
}

func C2tnb239v2() ecc.BinaryCurve {
	return x962.C2tnb239v2()
}

func C2tnb239v1() ecc.BinaryCurve {
	return x962.C2tnb239v1()
}

func C2pnb272w1() ecc.BinaryCurve {
	return x962.C2pnb272w1()
}

func C2pnb304w1() ecc.BinaryCurve {
	return x962.C2pnb304w1()
}

func C2pnb368w1() ecc.BinaryCurve {
	return x962.C2pnb368w1()
}

func C2tnb359v1() ecc.BinaryCurve {
	return x962.C2tnb359v1()
}

func C2tnb431r1() ecc.BinaryCurve {
	return x962.C2tnb431r1()
}

//func C2onb191v4() ecc.BinaryCurve {
//	initonce.Do(initAll)
//	return c2onb191v4
//}
//
//func C2onb191v5() ecc.BinaryCurve {
//	initonce.Do(initAll)
//	return c2onb191v5
//}
//
//func C2onb239v4() ecc.BinaryCurve {
//	initonce.Do(initAll)
//	return c2onb239v4
//}
//
//func C2onb239v5() ecc.BinaryCurve {
//	initonce.Do(initAll)
//	return c2onb239v5
//}
