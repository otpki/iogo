package signer

import (
	stdCrypto "crypto"
	"fmt"
	"io"

	iogoCrypto "github.com/otpki/iogo/crypto"
	"github.com/otpki/iogo/crypto/x509"
)

// Implements Signer and MessageSigner
type ExtendedSigner struct {
	stdCrypto.Signer
}

func (e *ExtendedSigner) Sign(rand io.Reader, digest []byte, opts stdCrypto.SignerOpts) ([]byte, error) {
	if extendedOpts, ok := opts.(*x509.ExtendedSignerOpts); ok && extendedOpts.IsExtended() {
		return extendedOpts.SignatureAlgorithm.GetSign()(e.Signer, rand, digest, opts)
	}
	return e.Signer.Sign(rand, digest, opts)
}

// Skips prehashing if opts.HashFunc or ExtendedHashFunc is crypto.Hash(0)
func (e *ExtendedSigner) SignMessage(rand io.Reader, msg []byte, opts stdCrypto.SignerOpts) ([]byte, error) {
	if extendedOpts, ok := opts.(*x509.ExtendedSignerOpts); ok {
		if extendedOpts.IsExtended() {
			if hash := extendedOpts.ExtendedHashFunc(); hash != 0 {
				if !hash.Available() {
					return nil, fmt.Errorf("iogo-crypto: requested hash function unavailable: %s", iogoCrypto.Hash(hash).String())
				}
				h := hash.New()
				h.Write(msg)
				msg = h.Sum(nil)
			}
			return e.Sign(rand, msg, opts)
		}
	}
	return stdCrypto.SignMessage(e.Signer, rand, msg, opts)
}
