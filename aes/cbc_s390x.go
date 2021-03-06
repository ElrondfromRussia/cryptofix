// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package aes

import (
	"github.com/ElrondfromRussia/cryptofix/cipher"
	"github.com/ElrondfromRussia/cryptofix/internal/subtle"
)

// Assert that aesCipherAsm implements the cbcEncAble and cbcDecAble interfaces.
var _ cbcEncAble = (*aesCipherAsm)(nil)
var _ cbcDecAble = (*aesCipherAsm)(nil)

type cbc struct {
	b  *aesCipherAsm
	c  code
	iv [BlockSize]byte
}

func (b *aesCipherAsm) NewCBCEncrypter(iv []byte) cipher.BlockMode {
	var c cbc
	c.b = b
	c.c = b.function
	copy(c.iv[:], iv)
	return &c
}

func (b *aesCipherAsm) NewCBCDecrypter(iv []byte) cipher.BlockMode {
	var c cbc
	c.b = b
	c.c = b.function + 128 // decrypt function code is encrypt + 128
	copy(c.iv[:], iv)
	return &c
}

func (x *cbc) BlockSize() int { return BlockSize }

// cryptBlocksChain invokes the cipher message with chaining (KMC) instruction
// with the given function code. The length must be a multiple of BlockSize (16).
//go:noescape
func cryptBlocksChain(c code, iv, key, dst, src *byte, length int)

func (x *cbc) CryptBlocks(dst, src []byte) error {
	if len(src)%BlockSize != 0 {
		return errors.New("crypto/cipher-input not full blocks")
	}
	if len(dst) < len(src) {
		return errors.New("crypto/cipher-output smaller than input")
	}
	if subtle.InexactOverlap(dst[:len(src)], src) {
		return errors.New("crypto-cipher-invalid buffer overlap")
	}
	if len(src) > 0 {
		cryptBlocksChain(x.c, &x.iv[0], &x.b.key[0], &dst[0], &src[0], len(src))
	}
}

func (x *cbc) SetIV(iv []byte) error {
	if len(iv) != BlockSize {
		return errors.New("cipher-incorrect length IV")
	}
	copy(x.iv[:], iv)
}
