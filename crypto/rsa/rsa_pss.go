package rsa

/**
 * This implementation is primarily LLM-generated and should be scrutinized accordingly.
 * It exists to allow custom hashes not supported in std lib crypto to be used with RSA PSS algos.
 */

import (
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"

	"filippo.io/bigmod"
)

type HashFactory func() hash.Hash

// SignPSS signs digest using RSASSA-PSS.
// digest MUST already be: H(payload)
// where H is the hash returned by newHash.
// The same H is also used by MGF1.
// The saltLength can be rsa.PSSSaltLengthAuto, rsa.PSSSaltLengthEqualsHash or a specified positive int
func SignPSS(rand io.Reader, priv *rsa.PrivateKey, digest []byte, newHash HashFactory, saltLength int) ([]byte, error) {
	if rand == nil {
		return nil, errors.New("pss: random source is nil")
	}
	if priv == nil || priv.N == nil || priv.D == nil {
		return nil, errors.New("pss: invalid RSA private key")
	}

	h := newHash()
	if h == nil {
		return nil, errors.New("pss: hash constructor returned nil")
	}

	hLen := h.Size()
	if len(digest) != hLen {
		return nil, fmt.Errorf(
			"pss: digest length %d does not match hash size %d",
			len(digest),
			hLen,
		)
	}
	// Salt length can be -1, 0, or greater
	saltLen := saltLength
	switch saltLength {
	case rsa.PSSSaltLengthEqualsHash: // -1
		saltLen = hLen
	case rsa.PSSSaltLengthAuto: // 0
		var err error
		saltLen, err = PSSMaxSaltLength(&priv.PublicKey, h)
		if err != nil {
			return nil, err
		}
	}
	// saltlen should be set to a positive int, otherwise an invalid saltlength was provided
	if saltLen <= 0 {
		return nil, errors.New("pss: invalid PSS salt length")
	}

	emBits := priv.N.BitLen() - 1
	emLen := (emBits + 7) / 8

	if emLen < hLen+saltLen+2 {
		return nil, errors.New("pss: RSA key too small for hash and salt")
	}

	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand, salt); err != nil {
		return nil, fmt.Errorf("pss: generate salt: %w", err)
	}

	em, err := emsaPSSEncode(digest, priv.N.BitLen()-1, salt, newHash)
	if err != nil {
		return nil, err
	}

	signature, err := rsaPrivateOperation(priv, em)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func rsaPrivateOperation(priv *rsa.PrivateKey, em []byte) ([]byte, error) {
	if priv == nil || priv.N == nil || priv.D == nil {
		return nil, errors.New("rsa: invalid private key")
	}
	if priv.N.Sign() <= 0 || priv.N.Bit(0) == 0 {
		return nil, errors.New("rsa: modulus must be positive and odd")
	}
	if priv.D.Sign() <= 0 {
		return nil, errors.New("rsa: invalid private exponent")
	}

	// N is public, so leaking its size is fine.
	modulus, err := bigmod.NewModulus(priv.N.Bytes())
	if err != nil {
		return nil, fmt.Errorf("rsa: invalid modulus: %w", err)
	}

	// EMSA-PSS encoding guarantees EM < N, but SetBytes also enforces it.
	m := bigmod.NewNat()
	if _, err := m.SetBytes(em, modulus); err != nil {
		return nil, errors.New("rsa: encoded message out of range")
	}

	// modulus.Size() depends only on the public RSA modulus.
	d := make([]byte, modulus.Size())
	if priv.D.BitLen() > len(d)*8 {
		return nil, errors.New("rsa: private exponent too large")
	}
	priv.D.FillBytes(d)
	defer clear(d)

	// RSASP1: s = m^d mod N
	s := bigmod.NewNat().Exp(m, d, modulus)

	if priv.E < 2 {
		return nil, errors.New("rsa: invalid public exponent")
	}
	// Optional check: s^e mod N == m
	// E is public, so ExpShortVarTime is safe here.
	check := bigmod.NewNat().ExpShortVarTime(s, uint(priv.E), modulus)

	if check.Equal(m) != 1 {
		return nil, errors.New("rsa: private operation verification failed")
	}

	return s.Bytes(modulus), nil
}

// VerifyPSS verifies an RSASSA-PSS signature.
//
// digest MUST already be H(payload), where H is newHash.
// The saltlength is as provided from rsa.PSSOptions
func VerifyPSS(pub *rsa.PublicKey, digest, signature []byte, newHash HashFactory, saltLength int) error {
	if pub == nil || pub.N == nil || pub.E < 2 {
		return rsa.ErrVerification
	}

	h := newHash()
	if h == nil {
		return rsa.ErrVerification
	}

	hLen := h.Size()
	if len(digest) != hLen {
		return rsa.ErrVerification
	}

	// A valid RSA signature is exactly k octets.
	k := (pub.N.BitLen() + 7) / 8
	if len(signature) != k {
		return rsa.ErrVerification
	}

	s := new(big.Int).SetBytes(signature)
	if s.Cmp(pub.N) >= 0 {
		return rsa.ErrVerification
	}

	// RSAVP1: m = s^e mod n
	e := big.NewInt(int64(pub.E))
	m := new(big.Int).Exp(s, e, pub.N)

	emBits := pub.N.BitLen() - 1
	emLen := (emBits + 7) / 8

	if m.BitLen() > emLen*8 {
		return rsa.ErrVerification
	}

	em := make([]byte, emLen)
	m.FillBytes(em)

	switch saltLength {
	case rsa.PSSSaltLengthAuto:
		// Leave as PSSSaltLengthAuto.
		// emsaPSSVerify will discover the salt length from DB.
	case rsa.PSSSaltLengthEqualsHash:
		saltLength = hLen
	default:
		if saltLength < 0 {
			return rsa.ErrVerification
		}
	}

	if !emsaPSSVerify(digest, em, emBits, saltLength, newHash) {
		return rsa.ErrVerification
	}

	return nil
}

func emsaPSSEncode(mHash []byte, emBits int, salt []byte, newHash HashFactory) ([]byte, error) {
	h := newHash()
	if h == nil {
		return nil, errors.New("pss: hash constructor returned nil")
	}
	hLen := h.Size()
	sLen := len(salt)

	if len(mHash) != hLen {
		return nil, errors.New("pss: invalid digest length")
	}

	emLen := (emBits + 7) / 8
	if emLen < hLen+sLen+2 {
		return nil, errors.New("pss: encoding error")
	}

	// M' = 0x0000000000000000 || mHash || salt
	// H = Hash(M')
	h.Write(make([]byte, 8))
	h.Write(mHash)
	h.Write(salt)

	H := h.Sum(nil)

	// DB = PS || 0x01 || salt
	// where PS is all zero bytes.
	dbLen := emLen - hLen - 1

	db := make([]byte, dbLen)

	separator := dbLen - sLen - 1
	db[separator] = 0x01
	copy(db[separator+1:], salt)

	// maskedDB = DB XOR MGF1(H, dbLen)
	dbMask := mgf1(H, dbLen, newHash)

	for i := range db {
		db[i] ^= dbMask[i]
	}

	// Clear the leftmost unused bits.
	unusedBits := 8*emLen - emBits
	db[0] &= byte(0xff >> unusedBits)

	// EM = maskedDB || H || 0xbc
	em := make([]byte, emLen)

	copy(em, db)
	copy(em[dbLen:], H)

	em[emLen-1] = 0xbc

	return em, nil
}

func emsaPSSVerify(mHash, em []byte, emBits, saltLength int, newHash HashFactory) bool {
	h := newHash()
	if h == nil {
		return false
	}

	hLen := h.Size()
	emLen := (emBits + 7) / 8

	if len(mHash) != hLen {
		return false
	}

	if len(em) != emLen {
		return false
	}

	// In auto mode, the salt may be any length, including zero,
	// so only enough room for H, 0x01, and 0xbc is required.
	if saltLength == rsa.PSSSaltLengthAuto {
		if emLen < hLen+2 {
			return false
		}
	} else {
		if saltLength < 0 {
			return false
		}

		if emLen < hLen+saltLength+2 {
			return false
		}
	}

	// RFC 8017 trailer field.
	if em[emLen-1] != 0xbc {
		return false
	}

	dbLen := emLen - hLen - 1

	maskedDB := em[:dbLen]
	H := em[dbLen : emLen-1]

	// The leftmost unused bits of maskedDB must be zero.
	unusedBits := 8*emLen - emBits

	if unusedBits > 0 {
		mask := byte(0xff << (8 - unusedBits))

		if maskedDB[0]&mask != 0 {
			return false
		}
	}

	// DB = maskedDB XOR MGF1(H, dbLen)
	dbMask := mgf1(H, dbLen, newHash)

	db := make([]byte, dbLen)
	for i := range db {
		db[i] = maskedDB[i] ^ dbMask[i]
	}

	// Clear the unused high bits after unmasking.
	if unusedBits > 0 {
		db[0] &= byte(0xff >> unusedBits)
	}

	var salt []byte
	// DB has the form: PS || 0x01 || salt
	// where PS consists entirely of zero bytes.
	if saltLength == rsa.PSSSaltLengthAuto {
		// In auto mode, find the separator and infer salt length
		// from however many bytes remain.
		i := 0
		for i < len(db) && db[i] == 0 {
			i++
		}
		if i >= len(db) || db[i] != 0x01 {
			return false
		}
		salt = db[i+1:]
	} else {
		// Exact salt length.
		psLen := dbLen - saltLength - 1

		if psLen < 0 {
			return false
		}
		for i := range psLen {
			if db[i] != 0 {
				return false
			}
		}
		if db[psLen] != 0x01 {
			return false
		}

		salt = db[psLen+1:]

		if len(salt) != saltLength {
			return false
		}
	}

	// H' = Hash(
	//     0x0000000000000000 ||
	//     mHash ||
	//     salt
	// )
	h.Reset()

	var prefix [8]byte

	_, _ = h.Write(prefix[:])
	_, _ = h.Write(mHash)
	_, _ = h.Write(salt)

	expectedH := h.Sum(nil)

	return subtle.ConstantTimeCompare(H, expectedH) == 1
}

func mgf1(seed []byte, length int, newHash HashFactory) []byte {
	out := make([]byte, 0, length)

	var counter [4]byte

	for i := uint32(0); len(out) < length; i++ {
		counter[0] = byte(i >> 24)
		counter[1] = byte(i >> 16)
		counter[2] = byte(i >> 8)
		counter[3] = byte(i)

		h := newHash()

		h.Write(seed)
		h.Write(counter[:])

		out = append(out, h.Sum(nil)...)
	}

	return out[:length]
}
