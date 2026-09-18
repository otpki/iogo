package signer

import (
	stdCrypto "crypto"
	"fmt"
	"io"

	iogoCrypto "github.com/otpki/iogo/crypto"
	"github.com/otpki/iogo/crypto/x509"
)

type ExtendedSignerOpts struct {
	stdCrypto.SignerOpts
	SignatureAlgorithm x509.SignatureAlgorithm
}

func (s *ExtendedSignerOpts) String() string {
	return "ExtSignerOpts, Sig:" + s.SignatureAlgorithm.String() + ", extHash: " + s.ExtendedHashFunc().String() + ", stdHash: " + s.HashFunc().String()
}

func (s *ExtendedSignerOpts) IsExtended() bool {
	return s.SignatureAlgorithm.GetIogoHash().Available()
}

func (s *ExtendedSignerOpts) ExtendedHashFunc() iogoCrypto.Hash {
	return s.SignatureAlgorithm.GetIogoHash()
}

func (s *ExtendedSignerOpts) HashFunc() stdCrypto.Hash {
	return s.SignatureAlgorithm.GetHashFunc()
}

type ExtendedSigner struct {
	stdCrypto.Signer
}

func (e *ExtendedSigner) Sign(rand io.Reader, digest []byte, opts stdCrypto.SignerOpts) ([]byte, error) {
	if extendedOpts, ok := opts.(*ExtendedSignerOpts); ok && extendedOpts.IsExtended() {
		return extendedOpts.SignatureAlgorithm.GetSign()(e.Signer, rand, digest, opts)
	}
	return e.Signer.Sign(rand, digest, opts)
}

type ExtendedMessageSigner struct {
	stdCrypto.MessageSigner
}

// Skips prehashing if opts.HashFunc or ExtendedHashFunc is crypto.Hash(0)
func (e *ExtendedMessageSigner) SignMessage(rand io.Reader, msg []byte, opts stdCrypto.SignerOpts) ([]byte, error) {
	if extendedOpts, ok := opts.(*ExtendedSignerOpts); ok {
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
	return e.MessageSigner.SignMessage(rand, msg, opts)
}
