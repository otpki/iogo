package crypto

import (
	"crypto"
	"hash"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	xsha3 "golang.org/x/crypto/sha3"
)

func init() {
	// IOGO hashes
	RegisterHash(SHAKE128, func() hash.Hash { return xsha3.NewShake128() })
	RegisterHash(SHAKE256, func() hash.Hash { return xsha3.NewShake256() })

	// Extra std lib hashes
	newHash256 := func() hash.Hash {
		h, _ := blake2b.New256(nil)
		return h
	}
	newHash384 := func() hash.Hash {
		h, _ := blake2b.New384(nil)
		return h
	}

	newHash512 := func() hash.Hash {
		h, _ := blake2b.New512(nil)
		return h
	}
	crypto.RegisterHash(crypto.BLAKE2s_256, func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	})
	crypto.RegisterHash(crypto.BLAKE2b_256, newHash256)
	crypto.RegisterHash(crypto.BLAKE2b_384, newHash384)
	crypto.RegisterHash(crypto.BLAKE2b_512, newHash512)
}
