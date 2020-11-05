// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package aes

import (
	"errors"
	"github.com/ElrondfromRussia/cryptofix/cipher"
	"github.com/ElrondfromRussia/cryptofix/internal/subtle"
	"strconv"
)

// The AES block size in bytes.
const BlockSize = 16

// A cipher is an instance of AES encryption using a particular key.
type aesCipher struct {
	enc []uint32
	dec []uint32
}

type KeySizeError int

func (k KeySizeError) Error() string {
	return "crypto/aes: invalid key size " + strconv.Itoa(int(k))
}

// NewCipher creates and returns a new cipher.Block.
// The key argument should be the AES key,
// either 16, 24, or 32 bytes to select
// AES-128, AES-192, or AES-256.
func NewCipher(key []byte) (cipher.Block, error) {
	k := len(key)
	switch k {
	default:
		return nil, KeySizeError(k)
	case 16, 24, 32:
		break
	}
	return newCipher(key)
}

// newCipherGeneric creates and returns a new cipher.Block
// implemented in pure Go.
func newCipherGeneric(key []byte) (cipher.Block, error) {
	n := len(key) + 28
	c := aesCipher{make([]uint32, n), make([]uint32, n)}
	expandKeyGo(key, c.enc, c.dec)
	return &c, nil
}

func (c *aesCipher) BlockSize() int { return BlockSize }

func (c *aesCipher) Encrypt(dst, src []byte) error {
	if len(src) < BlockSize {
		return errors.New("crypto/aes-input not full blocks")
	}
	if len(dst) < BlockSize {
		return errors.New("crypto/aes-output not full blocks")
	}
	if subtle.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		return errors.New("crypto/aes-invalid buffer overlap")
	}
	encryptBlockGo(c.enc, dst, src)
	return nil
}

func (c *aesCipher) Decrypt(dst, src []byte) error {
	if len(src) < BlockSize {
		return errors.New("crypto/aes-input not full blocks")
	}
	if len(dst) < BlockSize {
		return errors.New("crypto/aes-output not full blocks")
	}
	if subtle.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		return errors.New("crypto/aes-invalid buffer overlap")
	}
	decryptBlockGo(c.dec, dst, src)
	return nil
}
