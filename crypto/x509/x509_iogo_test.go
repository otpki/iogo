// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"
	"time"
)

func createHybridCert(t *testing.T) (*Certificate, crypto.Signer, crypto.Signer) {
	t.Helper()
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA private key: %s", err)
	}

	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA private key: %s", err)
	}

	tmpl := &Certificate{
		SignatureAlgorithm:            SHAKE256WithRSAPSS,
		AlternativeSignatureAlgorithm: ECDSAWithSHAKE256,
		KeyUsage:                      KeyUsageCRLSign | KeyUsageCertSign,
		BasicConstraintsValid:         true,
		IsCA:                          true,
	}

	certDer, err := CreateCertificateWithAltSigner(rand.Reader, tmpl, tmpl, rsaPriv.Public(), rsaPriv, ecdsaPriv.Public(), ecdsaPriv)
	if err != nil {
		t.Fatalf("failed to create certificate: %s", err)
	}

	parsedCert, err := ParseCertificate(certDer)
	if err != nil {
		t.Fatalf("failed to parse certificate: %s", err)
	}
	return parsedCert, rsaPriv, ecdsaPriv
}

func createHybridCSR(t *testing.T) (*CertificateRequest, crypto.Signer, crypto.Signer) {
	t.Helper()
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA private key: %s", err)
	}

	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA private key: %s", err)
	}

	tmpl := &CertificateRequest{
		SignatureAlgorithm:            SHAKE256WithRSAPSS,
		AlternativeSignatureAlgorithm: ECDSAWithSHAKE256,
	}

	csrDer, err := CreateCertificateRequestWithAltSigner(rand.Reader, tmpl, rsaPriv, ecdsaPriv)
	if err != nil {
		t.Fatalf("failed to create CSR: %s", err)
	}

	parsedCSR, err := ParseCertificateRequest(csrDer)
	if err != nil {
		t.Fatalf("failed to parse CSR: %s", err)
	}
	return parsedCSR, rsaPriv, ecdsaPriv
}

func createHybridCRL(t *testing.T, parent *Certificate, signer, altSigner crypto.Signer) *RevocationList {
	t.Helper()

	tmpl := &RevocationList{
		SignatureAlgorithm:            SHAKE256WithRSAPSS,
		AlternativeSignatureAlgorithm: ECDSAWithSHAKE256,
		ThisUpdate:                    time.Now(),
		NextUpdate:                    time.Now().Add(time.Hour),
		Number:                        big.NewInt(1),
	}

	crl, err := CreateRevocationListWithAltSigner(rand.Reader, tmpl, parent, signer, altSigner)
	if err != nil {
		t.Fatalf("failed to create revocation list: %s", err)
	}

	parsedCRL, err := ParseRevocationList(crl)
	if err != nil {
		t.Fatalf("failed to parse revocation list: %s", err)
	}
	return parsedCRL
}

func comparePublicKeys(t *testing.T, a, b crypto.PublicKey) bool {
	t.Helper()
	der1, err := MarshalPKIXPublicKey(a)
	if err != nil {
		t.Fatalf("failed to marshal first public key: %s", err)
	}

	// 2. Marshal the second public key to DER format
	der2, err := MarshalPKIXPublicKey(b)
	if err != nil {
		t.Fatalf("failed to marshal second public key: %s", err)
	}

	// 3. Compare the DER-encoded byte slices
	return bytes.Equal(der1, der2)
}

func TestMarshalUnmarshalAltSigner(t *testing.T) {
	parsedCert, priv, altPriv := createHybridCert(t)
	if parsedCert.SignatureAlgorithm != SHAKE256WithRSAPSS {
		t.Errorf("invalid signature algorithm: %s, expected: %s", parsedCert.SignatureAlgorithm, SHAKE256WithRSAPSS)
	}
	if parsedCert.PublicKeyAlgorithm != RSA {
		t.Errorf("invalid public key algorithm: %s, expected: %s", parsedCert.PublicKeyAlgorithm, RSA)
	}
	if !comparePublicKeys(t, parsedCert.PublicKey, priv.Public()) {
		t.Errorf("invalid public key: %s, expected: %s", parsedCert.PublicKey, priv.Public())
	}
	if parsedCert.AlternativeSignatureAlgorithm != ECDSAWithSHAKE256 {
		t.Errorf("invalid alt signature algorithm: %s, expected: %s", parsedCert.AlternativeSignatureAlgorithm, ECDSAWithSHAKE256)
	}
	if parsedCert.AlternativePublicKeyAlgorithm != ECDSA {
		t.Errorf("invalid alt public key algorithm: %s, expected: %s", parsedCert.AlternativePublicKeyAlgorithm, ECDSA)
	}
	if !comparePublicKeys(t, parsedCert.AlternativePublicKey, altPriv.Public()) {
		t.Errorf("invalid alt public key: %s, expected: %s", parsedCert.AlternativePublicKey, altPriv.Public())
	}
}

func TestCertificateCheckAltSignature(t *testing.T) {
	parsedCert, key, altKey := createHybridCert(t)
	signed := []byte("hello world")
	signature, err := signTBS(signed, key, SHAKE256WithRSAPSS, rand.Reader)
	if err != nil {
		t.Fatalf("failed to sign TBS: %s", err)
	}
	altSignature, err := signTBS(signed, altKey, ECDSAWithSHAKE256, rand.Reader)
	err = parsedCert.CheckSignature(SHAKE256WithRSAPSS, signed, signature)
	if err != nil {
		t.Errorf("failed to check signature: %s", err)
	}
	err = parsedCert.CheckAltSignature(ECDSAWithSHAKE256, signed, altSignature)
	if err != nil {
		t.Errorf("failed to check alt signature: %s", err)
	}
}

func TestMarshalUnmarshalAltCSR(t *testing.T) {
	parsedCSR, priv, altPriv := createHybridCSR(t)
	if parsedCSR.SignatureAlgorithm != SHAKE256WithRSAPSS {
		t.Errorf("invalid signature algorithm: %s, expected: %s", parsedCSR.SignatureAlgorithm, SHAKE256WithRSAPSS)
	}
	if parsedCSR.PublicKeyAlgorithm != RSA {
		t.Errorf("invalid public key algorithm: %s, expected: %s", parsedCSR.PublicKeyAlgorithm, RSA)
	}
	if !comparePublicKeys(t, parsedCSR.PublicKey, priv.Public()) {
		t.Errorf("invalid public key: %s, expected: %s", parsedCSR.PublicKey, priv.Public())
	}
	if parsedCSR.AlternativeSignatureAlgorithm != ECDSAWithSHAKE256 {
		t.Errorf("invalid alt signature algorithm: %s, expected: %s", parsedCSR.AlternativeSignatureAlgorithm, ECDSAWithSHAKE256)
	}
	if parsedCSR.AlternativePublicKeyAlgorithm != ECDSA {
		t.Errorf("invalid alt public key algorithm: %s, expected: %s", parsedCSR.AlternativePublicKeyAlgorithm, ECDSA)
	}
	if !comparePublicKeys(t, parsedCSR.AlternativePublicKey, altPriv.Public()) {
		t.Errorf("invalid alt public key: %s, expected: %s", parsedCSR.AlternativePublicKey, altPriv.Public())
	}
}

func TestCSRCheckAltSignature(t *testing.T) {
	parsedCSR, _, _ := createHybridCSR(t)
	err := parsedCSR.CheckSignature()
	if err != nil {
		t.Errorf("failed to check signature: %s", err)
	}
	err = parsedCSR.CheckAltSignature()
	if err != nil {
		t.Errorf("failed to check alt signature: %s", err)
	}
}

func TestMarshalUnmarshalCRL(t *testing.T) {
	parsedCert, key, altKey := createHybridCert(t)
	parsedCRL := createHybridCRL(t, parsedCert, key, altKey)
	if parsedCRL.SignatureAlgorithm != SHAKE256WithRSAPSS {
		t.Errorf("invalid signature algorithm: %s, expected: %s", parsedCRL.SignatureAlgorithm, SHAKE256WithRSAPSS)
	}
	if parsedCRL.AlternativeSignatureAlgorithm != ECDSAWithSHAKE256 {
		t.Errorf("invalid alt signature algorithm: %s, expected: %s", parsedCRL.AlternativeSignatureAlgorithm, ECDSAWithSHAKE256)
	}
}

func TestCRLCheckAltSignature(t *testing.T) {
	parsedCert, key, altKey := createHybridCert(t)
	parsedCRL := createHybridCRL(t, parsedCert, key, altKey)
	err := parsedCRL.CheckSignatureFrom(parsedCert)
	if err != nil {
		t.Errorf("failed to check signature: %s", err)
	}
	err = parsedCRL.CheckAltSignatureFrom(parsedCert)
	if err != nil {
		t.Errorf("failed to check alt signature: %s", err)
	}
}
