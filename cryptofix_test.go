package cryptofix

import (
	"encoding/base64"
	"encoding/hex"
	"github.com/ElrondfromRussia/cryptofix/aes"
	"github.com/ElrondfromRussia/cryptofix/cipher"
	"testing"
)

var (
	KEY, _ = hex.DecodeString("253213321246341111403244855552821" +
		"5288885444902314832383904444984")
)

func TestCryptofix(t *testing.T) {
	encMsg := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	bstdBytes := make([]byte, len(encMsg))
	n, err := base64.StdEncoding.Decode(bstdBytes, encMsg)
	if err != nil {
		t.Error("BAD DECRYPT1: ", err)
	}
	rDb := bstdBytes[:n]

	iv := KEY[:aes.BlockSize]
	block, err := aes.NewCipher(KEY)
	if err != nil {
		t.Error("BAD DECRYPT2: ", err)
	}

	if len(encMsg) < aes.BlockSize {
		t.Error("BAD DECRYPT3: ", "too short enc msg")
	}

	decrypted := make([]byte, len(rDb))
	mode, err := cipher.NewCBCDecrypter(block, iv)
	if err != nil {
		t.Error("BAD DECRYPT4: ", err)
	}
	err = mode.CryptBlocks(decrypted, rDb)
	if err == nil {
		t.Error("BAD DECRYPT5: ", err)
	}

	t.Log(decrypted)
}
