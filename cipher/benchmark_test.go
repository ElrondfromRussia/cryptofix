// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cipher_test

import (
	"github.com/ElrondfromRussia/cryptofix/aes"
	"github.com/ElrondfromRussia/cryptofix/cipher"
	"testing"
)

func benchmarkAESGCMSign(b *testing.B, buf []byte) {
	b.SetBytes(int64(len(buf)))

	var key [16]byte
	var nonce [12]byte
	aesP, _ := aes.NewCipher(key[:])
	aesgcm, _ := cipher.NewGCM(aesP)
	var out []byte
	var err error

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err = aesgcm.Seal(out[:0], nonce[:], nil, buf)
		if err != nil {
			b.Fatal("bad benchmarkAESGCMSign:", err)
		}
	}
}

func benchmarkAESGCMSeal(b *testing.B, buf []byte) {
	b.SetBytes(int64(len(buf)))

	var err error
	var key [16]byte
	var nonce [12]byte
	var ad [13]byte
	aesP, _ := aes.NewCipher(key[:])
	aesgcm, _ := cipher.NewGCM(aesP)
	var out []byte

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err = aesgcm.Seal(out[:0], nonce[:], buf, ad[:])
		if err != nil {
			b.Fatal("bad benchmarkAESGCMSeal:", err)
		}
	}
}

func benchmarkAESGCMOpen(b *testing.B, buf []byte) {
	b.SetBytes(int64(len(buf)))

	var err error
	var key [16]byte
	var nonce [12]byte
	var ad [13]byte
	aesP, _ := aes.NewCipher(key[:])
	aesgcm, _ := cipher.NewGCM(aesP)
	var out []byte
	out, err = aesgcm.Seal(out[:0], nonce[:], buf, ad[:])
	if err != nil {
		b.Fatal("bad benchmarkAESGCMOpen:", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := aesgcm.Open(buf[:0], nonce[:], out, ad[:])
		if err != nil {
			b.Errorf("Open: %v", err)
		}
	}
}

func BenchmarkAESGCMSeal1K(b *testing.B) {
	benchmarkAESGCMSeal(b, make([]byte, 1024))
}

func BenchmarkAESGCMOpen1K(b *testing.B) {
	benchmarkAESGCMOpen(b, make([]byte, 1024))
}

func BenchmarkAESGCMSign8K(b *testing.B) {
	benchmarkAESGCMSign(b, make([]byte, 8*1024))
}

func BenchmarkAESGCMSeal8K(b *testing.B) {
	benchmarkAESGCMSeal(b, make([]byte, 8*1024))
}

func BenchmarkAESGCMOpen8K(b *testing.B) {
	benchmarkAESGCMOpen(b, make([]byte, 8*1024))
}

func benchmarkAESStream(b *testing.B, mode func(cipher.Block, []byte) (cipher.Stream, error), buf []byte) {
	b.SetBytes(int64(len(buf)))

	var key [16]byte
	var iv [16]byte
	aesP, _ := aes.NewCipher(key[:])
	stream, err := mode(aesP, iv[:])
	if err != nil {
		b.Fatal("bad NewCipher benchmarkAESStream:", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := stream.XORKeyStream(buf, buf)
		if err != nil {
			b.Fatal("bad NewCipher benchmarkAESStream:", err)
		}
	}
}

// If we test exactly 1K blocks, we would generate exact multiples of
// the cipher's block size, and the cipher stream fragments would
// always be wordsize aligned, whereas non-aligned is a more typical
// use-case.
const almost1K = 1024 - 5
const almost8K = 8*1024 - 5

func BenchmarkAESCFBEncrypt1K(b *testing.B) {
	benchmarkAESStream(b, cipher.NewCFBEncrypter, make([]byte, almost1K))
}

func BenchmarkAESCFBDecrypt1K(b *testing.B) {
	benchmarkAESStream(b, cipher.NewCFBDecrypter, make([]byte, almost1K))
}

func BenchmarkAESCFBDecrypt8K(b *testing.B) {
	benchmarkAESStream(b, cipher.NewCFBDecrypter, make([]byte, almost8K))
}

func BenchmarkAESOFB1K(b *testing.B) {
	benchmarkAESStream(b, cipher.NewOFB, make([]byte, almost1K))
}

func BenchmarkAESCTR1K(b *testing.B) {
	benchmarkAESStream(b, cipher.NewCTR, make([]byte, almost1K))
}

func BenchmarkAESCTR8K(b *testing.B) {
	benchmarkAESStream(b, cipher.NewCTR, make([]byte, almost8K))
}

func BenchmarkAESCBCEncrypt1K(b *testing.B) {
	buf := make([]byte, 1024)
	b.SetBytes(int64(len(buf)))

	var key [16]byte
	var iv [16]byte
	aesP, _ := aes.NewCipher(key[:])
	cbc, err := cipher.NewCBCEncrypter(aesP, iv[:])
	if err != nil {
		b.Fatal("bad BenchmarkAESCBCEncrypt1K1:", err)
	}
	for i := 0; i < b.N; i++ {
		err := cbc.CryptBlocks(buf, buf)
		if err != nil {
			b.Fatal("bad BenchmarkAESCBCEncrypt1K2:", err)
		}
	}
}

func BenchmarkAESCBCDecrypt1K(b *testing.B) {
	buf := make([]byte, 1024)
	b.SetBytes(int64(len(buf)))

	var key [16]byte
	var iv [16]byte
	aesP, _ := aes.NewCipher(key[:])
	cbc, err := cipher.NewCBCDecrypter(aesP, iv[:])
	if err != nil {
		b.Fatal("bad BenchmarkAESCBCDecrypt1K1:", err)
	}
	for i := 0; i < b.N; i++ {
		err := cbc.CryptBlocks(buf, buf)
		if err != nil {
			b.Fatal("bad BenchmarkAESCBCDecrypt1K2:", err)
		}
	}
}
