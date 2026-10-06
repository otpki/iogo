package signer

import (
	stdCrypto "crypto"
	"fmt"
	"io"

	"github.com/otpki/iogo/crypto/x509"
)

// Implements Signer and MessageSigner
type ExtendedSigner struct {
	stdCrypto.Signer
}

func (e *ExtendedSigner) Sign(rand io.Reader, digest []byte, opts stdCrypto.SignerOpts) ([]byte, error) {
	if extendedOpts, ok := opts.(*x509.ExtendedSignerOpts); ok {
		if extendedOpts.IsExtended() {
			return extendedOpts.SignatureAlgorithm.GetSign()(e.Signer, rand, digest, opts)
		}
		return e.Signer.Sign(rand, digest, extendedOpts.SignerOpts)
	}
	return e.Signer.Sign(rand, digest, opts)
}

// Skips prehashing if opts.HashFunc or ExtendedHashFunc is crypto.Hash(0)
func (e *ExtendedSigner) SignMessage(rand io.Reader, msg []byte, opts stdCrypto.SignerOpts) ([]byte, error) {
	if extendedOpts, ok := opts.(*x509.ExtendedSignerOpts); ok {
		// Check if we skip because hash is 0
		if !extendedOpts.IsNilHash() {
			// Hash with either iogo or std, whichever is provided
			hasher := extendedOpts.GetHasher()
			if !hasher.Available() {
				return nil, fmt.Errorf("iogo-crypto: requested hash function unavailable: %s", hasher.String())
			}
			h := hasher.New()
			h.Write(msg)
			msg = h.Sum(nil)
		}
		// Sign the pre-hashed digest (or message if configured to skip)
		return e.Sign(rand, msg, opts)
	}
	return stdCrypto.SignMessage(e.Signer, rand, msg, opts)
}
