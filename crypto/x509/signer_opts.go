package x509

import (
	stdCrypto "crypto"

	iogoCrypto "github.com/otpki/iogo/crypto"
)

type ExtendedSignerOpts struct {
	stdCrypto.SignerOpts
	SignatureAlgorithm SignatureAlgorithm
}

func (s *ExtendedSignerOpts) String() string {
	return "ExtSignerOpts, Sig:" + s.SignatureAlgorithm.String() + ", extHash: " + s.ExtendedHashFunc().String() + ", stdHash: " + s.HashFunc().String()
}

func (s *ExtendedSignerOpts) IsExtended() bool {
	return s.SignatureAlgorithm.IsExtended()
}

func (s *ExtendedSignerOpts) ExtendedHashFunc() iogoCrypto.Hash {
	return s.SignatureAlgorithm.GetIogoHash()
}

func (s *ExtendedSignerOpts) HashFunc() stdCrypto.Hash {
	return s.SignatureAlgorithm.GetHashFunc()
}
