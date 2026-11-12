// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"crypto"
	"encoding/asn1"

	iogoCrypto "github.com/otpki/iogo/crypto"

	circlPki "github.com/cloudflare/circl/pki"
	circlSign "github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/dilithium/mode2"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/cloudflare/circl/sign/dilithium/mode5"
	"github.com/cloudflare/circl/sign/ed448"
	"github.com/cloudflare/circl/sign/eddilithium2"
	"github.com/cloudflare/circl/sign/eddilithium3"
	"github.com/cloudflare/circl/sign/slhdsa"
)

// To add a signature scheme from Circl
//
//   1. make sure it implements CertificateScheme,
//	 2. add SignatureAlgorithm and PublicKeyAlgorithm constants in x509.go
//   3. add row in circlSchemes below
//   4. update publicKeyAlgoName in x509.go

var circlSchemes = [...]struct {
	sga    SignatureAlgorithm
	alg    PublicKeyAlgorithm
	scheme circlSign.Scheme
}{
	//	PureSLHDSA
	{PureEd448, Ed448, ed448.Scheme()},
	{PureEdDilithium2, EdDilithium2, eddilithium2.Scheme()},
	{PureEdDilithium3, EdDilithium3, eddilithium3.Scheme()},
	{PureDilithium2, Dilithium2, mode2.Scheme()},
	{PureDilithium3, Dilithium3, mode3.Scheme()},
	{PureDilithium5, Dilithium5, mode5.Scheme()},
	{SLHDSAWithSHA128s, SLHDSASHA128s, slhdsa.SHA2_128s.Scheme()},
	{SLHDSAWithSHAKE128s, SLHDSASHAKE128s, slhdsa.SHAKE_128s.Scheme()},
	{SLHDSAWithSHA128f, SLHDSASHA128f, slhdsa.SHA2_128f.Scheme()},
	{SLHDSAWithSHAKE128f, SLHDSASHAKE128f, slhdsa.SHAKE_128f.Scheme()},
	{SLHDSAWithSHA192s, SLHDSASHA192s, slhdsa.SHA2_192s.Scheme()},
	{SLHDSAWithSHAKE192s, SLHDSASHAKE192s, slhdsa.SHAKE_192s.Scheme()},
	{SLHDSAWithSHA192f, SLHDSASHA192f, slhdsa.SHA2_192f.Scheme()},
	{SLHDSAWithSHAKE192f, SLHDSASHAKE192f, slhdsa.SHAKE_192f.Scheme()},
	{SLHDSAWithSHA256s, SLHDSASHA256s, slhdsa.SHA2_256s.Scheme()},
	{SLHDSAWithSHAKE256s, SLHDSASHAKE256s, slhdsa.SHAKE_256s.Scheme()},
	{SLHDSAWithSHA256f, SLHDSASHA256f, slhdsa.SHA2_256f.Scheme()},
	{SLHDSAWithSHAKE256f, SLHDSASHAKE256f, slhdsa.SHAKE_256f.Scheme()},
}

func CirclSchemeBySignatureAlgorithm(alg SignatureAlgorithm) circlSign.Scheme {
	for _, cs := range circlSchemes {
		if cs.sga == alg {
			return cs.scheme
		}
	}
	return nil
}

func CirclSchemeByPublicKeyAlgorithm(alg PublicKeyAlgorithm) circlSign.Scheme {
	for _, cs := range circlSchemes {
		if cs.alg == alg {
			return cs.scheme
		}
	}
	return nil
}

func SignatureAlgorithmByCirclScheme(scheme circlSign.Scheme) SignatureAlgorithm {
	for _, cs := range circlSchemes {
		if cs.scheme == scheme {
			return cs.sga
		}
	}
	return UnknownSignatureAlgorithm
}

func PublicKeyAlgorithmByCirclScheme(scheme circlSign.Scheme) PublicKeyAlgorithm {
	for _, cs := range circlSchemes {
		if cs.scheme == scheme {
			return cs.alg
		}
	}
	return UnknownPublicKeyAlgorithm
}

func init() {
	for _, cs := range circlSchemes {
		signatureAlgorithmDetails = append(signatureAlgorithmDetails,
			struct {
				algo       SignatureAlgorithm
				name       string
				oid        asn1.ObjectIdentifier
				params     asn1.RawValue
				pubKeyAlgo PublicKeyAlgorithm
				hash       crypto.Hash
				isRSAPSS   bool
				isIOGO     bool
				iogoHash   iogoCrypto.Hash
				sign       signFunc
				verify     verifyFunc
			}{
				algo:       cs.sga,
				name:       cs.scheme.Name(),
				oid:        cs.scheme.(circlPki.CertificateScheme).Oid(),
				params:     emptyRawValue,
				pubKeyAlgo: cs.alg,
				hash:       crypto.Hash(0),
				isRSAPSS:   false,
				isIOGO:     false,
				iogoHash:   iogoCrypto.Hash(0),
				sign:       noOpSigner,
				verify:     noOpVerifier,
			},
		)
	}
}
