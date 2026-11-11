package x509

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/dilithium/mode2"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/cloudflare/circl/sign/dilithium/mode5"
)

func TestCIRCLSchemesWithoutCertificateOID(t *testing.T) {
	for _, scheme := range []sign.Scheme{mode2.Scheme(), mode3.Scheme(), mode5.Scheme()} {
		t.Run(scheme.Name(), func(t *testing.T) {
			publicKey, privateKey, err := scheme.GenerateKey()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := MarshalPKIXPublicKey(publicKey); err == nil {
				t.Fatal("marshaled a public key without a certificate OID")
			}
			if _, err := MarshalPKCS8PrivateKey(privateKey); err == nil {
				t.Fatal("marshaled a private key without a certificate OID")
			}
			template := &Certificate{SerialNumber: big.NewInt(1)}
			if _, err := CreateCertificate(rand.Reader, template, template, publicKey, privateKey); err == nil {
				t.Fatal("created a certificate with a scheme without a certificate OID")
			}
		})
	}
}
