// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package crypto collects common cryptographic constants.
package crypto

import (
	stdCrypto "crypto"
	"fmt"
	"hash"
	"strconv"
)

// Common interface to allow callers to interop with std lib hashes
type Hasher interface {
	fmt.Stringer
	New() hash.Hash
	Available() bool
	Size() int
}

func IsZeroHash(h Hasher) bool {
	switch t := h.(type) {
	case stdCrypto.Hash:
		return t == stdCrypto.Hash(0)
	case Hash:
		return t == Hash(0)
	}
	return false
}

// Hash identifies a cryptographic hash function that is implemented in another
// package.
type Hash uint

// HashFunc simply returns the value of h so that [Hash] implements [SignerOpts].
func (h Hash) HashFunc() Hash {
	return h
}

func (h Hash) String() string {
	switch h {
	case SHAKE128:
		return "SHAKE-128"
	case SHAKE256:
		return "SHAKE-256"
	default:
		return "unknown hash value " + strconv.Itoa(int(h))
	}
}

const (
	SHAKE128 Hash = 1 + iota
	SHAKE256
	maxHash
)

var digestSizes = []uint8{
	SHAKE128: 32, // extendable
	SHAKE256: 64, // extendable
}

// Size returns the length, in bytes, of a digest resulting from the given hash
// function. It doesn't require that the hash function in question be linked
// into the program.
func (h Hash) Size() int {
	if h > 0 && h < maxHash {
		return int(digestSizes[h])
	}
	panic("crypto: Size of unknown hash function")
}

var hashes = make([]func() hash.Hash, maxHash)

// New returns a new hash.Hash calculating the given hash function. New panics
// if the hash function is not linked into the binary.
func (h Hash) New() hash.Hash {
	if h > 0 && h < maxHash {
		f := hashes[h]
		if f != nil {
			return f()
		}
	}
	panic("crypto: requested hash function unavailable: " + h.String())
}

// Available reports whether the given hash function is linked into the binary.
func (h Hash) Available() bool {
	return h < maxHash && hashes[h] != nil
}

// RegisterHash registers a function that returns a new instance of the given
// hash function. This is intended to be called from the init function in
// packages that implement hash functions.
func RegisterHash(h Hash, f func() hash.Hash) {
	if h == 0 || h >= maxHash {
		panic("crypto: RegisterHash of unknown hash function")
	}
	hashes[h] = f
}

func DoHash(hash Hash, data []byte) ([]byte, error) {
	if !hash.Available() {
		return nil, hashUnavailableError(hash)
	}
	h := hash.New()
	h.Write(data)
	return h.Sum(nil), nil
}

type hashUnavailableError Hash

func (h hashUnavailableError) Error() string {
	return "iogo-crypto: requested hash function unavailable: " + Hash(h).String()
}
