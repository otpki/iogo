package signer_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"hash"
	"io"
	"testing"

	"github.com/otpki/iogo/crypto/signer"
	"github.com/otpki/iogo/crypto/x509"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type rsaMessageSigner struct {
	key *rsa.PrivateKey
}

func (ms *rsaMessageSigner) Public() crypto.PublicKey { return ms.Public() }

func (ms *rsaMessageSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
		return rsa.SignPSS(rand, ms.key, opts.HashFunc(), digest, pssOpts)
	}
	return rsa.SignPKCS1v15(rand, ms.key, opts.HashFunc(), digest)
}

func (ms *rsaMessageSigner) SignMessage(rand io.Reader, msg []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	h := opts.HashFunc().New()
	h.Write(msg)
	tbs := h.Sum(nil)
	return rsa.SignPKCS1v15(rand, ms.key, opts.HashFunc(), tbs)
}

type ecdsaMessageSigner struct {
	key *ecdsa.PrivateKey
}

func (ms *ecdsaMessageSigner) Public() crypto.PublicKey { return ms.Public() }

func (ms *ecdsaMessageSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return ecdsa.SignASN1(rand, ms.key, digest)
}

func (ms *ecdsaMessageSigner) SignMessage(rand io.Reader, msg []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	h := opts.HashFunc().New()
	h.Write(msg)
	tbs := h.Sum(nil)
	return ecdsa.SignASN1(rand, ms.key, tbs)
}

type mldsaMessageSigner struct {
	key *mldsa.PrivateKey
}

func (ms *mldsaMessageSigner) Public() crypto.PublicKey { return ms.Public() }

func (ms *mldsaMessageSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return nil, errors.New("unimplemented")
}

func (ms *mldsaMessageSigner) SignMessage(rand io.Reader, msg []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return ms.key.Sign(rand, msg, opts)
}

func TestMessageSignerExtension(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	mldsaKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)

	data := []byte("wow some data")
	tests := []struct {
		signer crypto.MessageSigner
		opts   crypto.SignerOpts
		data   []byte
	}{
		{
			signer: &signer.ExtendedSigner{&rsaMessageSigner{rsaKey}},
			opts:   x509.SHA256WithRSA.GetHashFunc(),
			data:   data,
		},
		{
			signer: &signer.ExtendedSigner{&rsaMessageSigner{rsaKey}},
			opts:   x509.SHA256WithRSAPSS.GetHashFunc(),
			data:   data,
		},
		{
			signer: &signer.ExtendedSigner{&rsaMessageSigner{rsaKey}},
			opts: &x509.ExtendedSignerOpts{
				SignatureAlgorithm: x509.SHAKE128WithRSAPSS,
			},
			data: data,
		},
		{
			signer: &signer.ExtendedSigner{&rsaMessageSigner{rsaKey}},
			opts: &x509.ExtendedSignerOpts{
				SignatureAlgorithm: x509.SHAKE256WithRSAPSS,
			},
			data: data,
		},
		{
			signer: &signer.ExtendedSigner{&ecdsaMessageSigner{ecdsaKey}},
			opts:   x509.ECDSAWithSHA256.GetHashFunc(),
			data:   data,
		},
		{
			signer: &signer.ExtendedSigner{&ecdsaMessageSigner{ecdsaKey}},
			opts:   x509.ECDSAWithSHA512.GetHashFunc(),
			data:   data,
		},
		{
			signer: &signer.ExtendedSigner{&ecdsaMessageSigner{ecdsaKey}},
			opts: &x509.ExtendedSignerOpts{
				SignatureAlgorithm: x509.ECDSAWithSHAKE128,
			},
			data: data,
		},
		{
			signer: &signer.ExtendedSigner{&ecdsaMessageSigner{ecdsaKey}},
			opts: &x509.ExtendedSignerOpts{
				SignatureAlgorithm: x509.ECDSAWithSHAKE256,
			},
			data: data,
		},
		{
			signer: &signer.ExtendedSigner{&mldsaMessageSigner{mldsaKey}},
			data:   data,
		},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("TestExtendedMessageSigner:Key:%T;SignOpts:%T", tc.signer, tc.opts), func(t *testing.T) {
			t.Parallel()
			sig, err := tc.signer.SignMessage(rand.Reader, append([]byte{}, data...), tc.opts)
			require.NoError(t, err)
			assert.NotEmpty(t, sig)
		})
	}
}

func TestSignerExtension(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	mldsaKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	data := []byte("wow some data")
	tests := []struct {
		signer crypto.Signer
		opts   crypto.SignerOpts
		data   []byte
	}{
		{
			signer: &signer.ExtendedSigner{Signer: rsaKey},
			opts:   x509.SHA256WithRSA.GetHashFunc(),
			data:   data,
		},
		{
			signer: &signer.ExtendedSigner{Signer: rsaKey},
			opts:   x509.SHA256WithRSAPSS.GetHashFunc(),
			data:   data,
		},
		{
			signer: &signer.ExtendedSigner{Signer: rsaKey},
			opts: &x509.ExtendedSignerOpts{
				SignatureAlgorithm: x509.SHAKE128WithRSAPSS,
			},
			data: data,
		},
		{
			signer: &signer.ExtendedSigner{Signer: rsaKey},
			opts: &x509.ExtendedSignerOpts{
				SignatureAlgorithm: x509.SHAKE256WithRSAPSS,
			},
			data: data,
		},
		{
			signer: &signer.ExtendedSigner{Signer: ecdsaKey},
			opts:   x509.ECDSAWithSHA256.GetHashFunc(),
			data:   data,
		},
		{
			signer: &signer.ExtendedSigner{Signer: ecdsaKey},
			opts:   x509.ECDSAWithSHA512.GetHashFunc(),
			data:   data,
		},
		{
			signer: &signer.ExtendedSigner{Signer: ecdsaKey},
			opts: &x509.ExtendedSignerOpts{
				SignatureAlgorithm: x509.ECDSAWithSHAKE128,
			},
			data: data,
		},
		{
			signer: &signer.ExtendedSigner{Signer: ecdsaKey},
			opts: &x509.ExtendedSignerOpts{
				SignatureAlgorithm: x509.ECDSAWithSHAKE256,
			},
			data: data,
		},
		{
			signer: &signer.ExtendedSigner{Signer: mldsaKey},
			data:   data,
		},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("TestExtendedSigner:Key:%T;SignOpts:%T", tc.signer, tc.opts), func(t *testing.T) {
			t.Parallel()
			digest := hashData(tc.opts, data)
			doSign(t, tc.signer, tc.opts, digest)
		})
	}

}

func doSign(t *testing.T, signer crypto.Signer, opts crypto.SignerOpts, digest []byte) {
	t.Helper()
	sig, err := signer.Sign(rand.Reader, digest, opts)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)
}

func hashData(opts crypto.SignerOpts, data []byte) []byte {
	// No opts, therefore no prehash
	if opts == nil {
		return data
	}
	var h hash.Hash
	if opts.HashFunc().Available() {
		h = opts.HashFunc().New()
	}
	if extendedOpts, ok := opts.(*x509.ExtendedSignerOpts); ok && extendedOpts.IsExtended() {
		h = extendedOpts.ExtendedHashFunc().New()
	}
	// No prehash
	if h == nil {
		return data
	}
	h.Write(data)
	return h.Sum(nil)
}
