package rsa_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"hash"
	"testing"

	iogoCrypto "github.com/otpki/iogo/crypto"
	pss "github.com/otpki/iogo/crypto/rsa"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRsaPss(t *testing.T) {
	t.Parallel()
	tests := []struct {
		key        *rsa.PrivateKey
		keySize    int
		saltLength int
		hashName   string
		hash       func() hash.Hash
		stdHash    crypto.Hash
		tbsData    []byte
		iogoOnly   bool
	}{}
	keySizes := []int{
		1024,
		1536,
		2048,
		3072,
		4096,
		6144,
		8192,
	}
	hashes := []struct {
		name     string
		hashFunc func() hash.Hash
		value    crypto.Hash
	}{
		{name: crypto.MD5.String(), hashFunc: crypto.MD5.New, value: crypto.MD5},
		{name: crypto.SHA224.String(), hashFunc: crypto.SHA224.New, value: crypto.SHA224},
		{name: crypto.SHA256.String(), hashFunc: crypto.SHA256.New, value: crypto.SHA256},
		{name: crypto.SHA384.String(), hashFunc: crypto.SHA384.New, value: crypto.SHA384},
		{name: crypto.SHA512.String(), hashFunc: crypto.SHA512.New, value: crypto.SHA512},
		{name: crypto.SHA3_224.String(), hashFunc: crypto.SHA3_224.New, value: crypto.SHA3_224},
		{name: crypto.SHA3_256.String(), hashFunc: crypto.SHA3_256.New, value: crypto.SHA3_256},
		{name: crypto.SHA3_384.String(), hashFunc: crypto.SHA3_384.New, value: crypto.SHA3_384},
		{name: crypto.SHA3_512.String(), hashFunc: crypto.SHA3_512.New, value: crypto.SHA3_512},
		{name: crypto.SHA512_224.String(), hashFunc: crypto.SHA512_224.New, value: crypto.SHA512_224},
		{name: crypto.SHA512_256.String(), hashFunc: crypto.SHA512_256.New, value: crypto.SHA512_256},

		{name: crypto.BLAKE2b_256.String(), hashFunc: crypto.BLAKE2b_256.New, value: crypto.BLAKE2b_256},
		{name: crypto.BLAKE2b_384.String(), hashFunc: crypto.BLAKE2b_384.New, value: crypto.BLAKE2b_384},
		{name: crypto.BLAKE2b_512.String(), hashFunc: crypto.BLAKE2b_512.New, value: crypto.BLAKE2b_512},
		{name: crypto.BLAKE2s_256.String(), hashFunc: crypto.BLAKE2s_256.New, value: crypto.BLAKE2s_256},

		{name: iogoCrypto.SHAKE128.String(), hashFunc: iogoCrypto.SHAKE128.New, value: crypto.Hash(0)},
		{name: iogoCrypto.SHAKE256.String(), hashFunc: iogoCrypto.SHAKE256.New, value: crypto.Hash(0)},
	}

	for _, bits := range keySizes {
		pk, err := rsa.GenerateKey(rand.Reader, bits)
		require.NoError(t, err, "failed to generate rsa key")
		for _, h := range hashes {
			// Assess if key has enough bits to have salt of hash.Size()
			saltLength := rsa.PSSSaltLengthEqualsHash
			isTooSmall := bits/8 < h.hashFunc().Size()*2+2 //hash+salt(=hash) + 2
			if isTooSmall {
				saltLength = rsa.PSSSaltLengthAuto // Else: use available bits < hash size
			}
			tests = append(tests, struct {
				key        *rsa.PrivateKey
				keySize    int
				saltLength int
				hashName   string
				hash       func() hash.Hash
				stdHash    crypto.Hash
				tbsData    []byte
				iogoOnly   bool
			}{
				key:        pk,
				keySize:    bits,
				saltLength: saltLength,
				hash:       h.hashFunc,
				hashName:   h.name,
				stdHash:    h.value,
				tbsData:    []byte("0923rhiohwaefnaweifg\n\nwow good data"),
			})
		}
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("TestRsaPSS:Key:%d;Hash:%s;SaltMode:%d", tc.keySize, tc.hashName, tc.saltLength), func(t *testing.T) {
			t.Parallel()

			digest := hashData(tc.hash(), tc.tbsData)
			iogoSigned, err := pss.SignPSS(rand.Reader, tc.key, digest, tc.hash, tc.saltLength)
			require.NoError(t, err, "failed to sign with iogo crypto/rsa")
			err = pss.VerifyPSS(&tc.key.PublicKey, digest, iogoSigned, tc.hash, tc.saltLength)
			assert.NoError(t, err, "failed to verify with iogo crypto/rsa")

			// Test against crypto/rsa public function IFF hash algo is std lib crypto
			if tc.stdHash == crypto.Hash(0) {
				return // Skip hash functions not supported by std crypto/rsa
			}
			opts := &rsa.PSSOptions{
				SaltLength: tc.saltLength,
				Hash:       tc.stdHash,
			}
			// Std lib self-test
			sig, err := rsa.SignPSS(rand.Reader, tc.key, tc.stdHash, digest, opts)
			require.NoError(t, err, "failed to sign stdlib crypto/rsa pss")
			err = rsa.VerifyPSS(&tc.key.PublicKey, tc.stdHash, digest, sig, opts)
			assert.NoError(t, err, "failed to verify stdlib crypto/rsa pss")

			// Verify std Signature with iogo Verify
			err = pss.VerifyPSS(&tc.key.PublicKey, digest, sig, tc.hash, rsa.PSSSaltLengthAuto)
			assert.NoError(t, err, "failed to verify stdlib signature with iogo crypto/rsa VerifyPSS")
			// Verify iogo Signature with stdLib Verify
			err = rsa.VerifyPSS(&tc.key.PublicKey, tc.stdHash, digest, iogoSigned, opts)
			assert.NoError(t, err, "failed to verify iogo signature with stdlib crypto/rsa VerifyPSS")
		})
	}
}

func hashData(h hash.Hash, data []byte) []byte {
	h.Write(data)
	return h.Sum(nil)
}
