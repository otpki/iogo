package x509

import (
	stdCrypto "crypto"
	"crypto/rsa"

	iogoCrypto "github.com/otpki/iogo/crypto"
)

type ExtendedSignerOpts struct {
	stdCrypto.SignerOpts
	SignatureAlgorithm SignatureAlgorithm
}

func NewSignerOpts(sigAlgo SignatureAlgorithm) *ExtendedSignerOpts {
	var opts stdCrypto.SignerOpts = sigAlgo.GetHashFunc()
	if sigAlgo.isRSAPSS() {
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigAlgo.GetHashFunc()}
	}
	return &ExtendedSignerOpts{
		SignerOpts:         opts,
		SignatureAlgorithm: sigAlgo,
	}
}

func (s *ExtendedSignerOpts) String() string {
	return "ExtSignerOpts, Sig:" + s.SignatureAlgorithm.String() + ", extHash: " + s.ExtendedHashFunc().String() + ", stdHash: " + s.HashFunc().String()
}

func (s *ExtendedSignerOpts) IsExtended() bool {
	return s.SignatureAlgorithm.IsExtended()
}

func (s *ExtendedSignerOpts) GetHasher() iogoCrypto.Hasher {
	if s.IsExtended() {
		return s.ExtendedHashFunc()
	}
	return s.HashFunc()
}

func (s *ExtendedSignerOpts) IsNilHash() bool {
	return iogoCrypto.IsZeroHash(s.GetHasher())
}

func (s *ExtendedSignerOpts) ExtendedHashFunc() iogoCrypto.Hash {
	return s.SignatureAlgorithm.GetIogoHash()
}

func (s *ExtendedSignerOpts) HashFunc() stdCrypto.Hash {
	return s.SignatureAlgorithm.GetHashFunc()
}
