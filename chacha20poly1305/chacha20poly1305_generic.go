// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package chacha20poly1305

import (
	"encoding/binary"
	"errors"

	"github.com/ElrondfromRussia/cryptofix/chacha20"
	"github.com/ElrondfromRussia/cryptofix/internal/subtle"
	"github.com/ElrondfromRussia/cryptofix/poly1305"
)

func writeWithPadding(p *poly1305.MAC, b []byte) {
	p.Write(b)
	if rem := len(b) % 16; rem != 0 {
		var buf [16]byte
		padLen := 16 - rem
		p.Write(buf[:padLen])
	}
}

func writeUint64(p *poly1305.MAC, n int) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(n))
	p.Write(buf[:])
}

func (c *chacha20poly1305) sealGeneric(dst, nonce, plaintext, additionalData []byte) ([]byte, error) {
	ret, out := sliceForAppend(dst, len(plaintext)+poly1305.TagSize)
	ciphertext, tag := out[:len(plaintext)], out[len(plaintext):]
	if subtle.InexactOverlap(out, plaintext) {
		return nil, errors.New("chacha20poly1305: invalid buffer overlap")
	}

	var polyKey [32]byte
	s, _ := chacha20.NewUnauthenticatedCipher(c.key[:], nonce)
	err := s.XORKeyStream(polyKey[:], polyKey[:])
	if err != nil {
		return nil, err
	}
	err = s.SetCounter(1) // set the counter to 1, skipping 32 bytes
	if err != nil {
		return nil, err
	}
	err = s.XORKeyStream(ciphertext, plaintext)
	if err != nil {
		return nil, err
	}

	p := poly1305.New(&polyKey)
	writeWithPadding(p, additionalData)
	writeWithPadding(p, ciphertext)
	writeUint64(p, len(additionalData))
	writeUint64(p, len(plaintext))
	p.Sum(tag[:0])

	return ret, nil
}

func (c *chacha20poly1305) openGeneric(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	tag := ciphertext[len(ciphertext)-16:]
	ciphertext = ciphertext[:len(ciphertext)-16]

	var polyKey [32]byte
	s, _ := chacha20.NewUnauthenticatedCipher(c.key[:], nonce)
	err := s.XORKeyStream(polyKey[:], polyKey[:])
	if err != nil {
		return nil, err
	}
	err = s.SetCounter(1) // set the counter to 1, skipping 32 bytes
	if err != nil {
		return nil, err
	}

	p := poly1305.New(&polyKey)
	writeWithPadding(p, additionalData)
	writeWithPadding(p, ciphertext)
	writeUint64(p, len(additionalData))
	writeUint64(p, len(ciphertext))

	ret, out := sliceForAppend(dst, len(ciphertext))
	if subtle.InexactOverlap(out, ciphertext) {
		return nil, errors.New("chacha20poly1305: invalid buffer overlap")
	}
	if !p.Verify(tag) {
		for i := range out {
			out[i] = 0
		}
		return nil, errOpen
	}

	err = s.XORKeyStream(out, ciphertext)
	if err != nil {
		return nil, err
	}
	return ret, nil
}
