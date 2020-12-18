// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"errors"
	"github.com/ElrondfromRussia/cryptofix/elliptic"
	"github.com/ElrondfromRussia/cryptofix/hmac"
	"hash"
	"io"
	"math/big"

	"github.com/ElrondfromRussia/cryptofix/cryptobyte"
	"github.com/ElrondfromRussia/cryptofix/hkdf"
	"golang.org/x/crypto/curve25519"
)

// This file contains the functions necessary to compute the TLS 1.3 key
// schedule. See RFC 8446, Section 7.

const (
	resumptionBinderLabel         = "res binder"
	clientHandshakeTrafficLabel   = "c hs traffic"
	serverHandshakeTrafficLabel   = "s hs traffic"
	clientApplicationTrafficLabel = "c ap traffic"
	serverApplicationTrafficLabel = "s ap traffic"
	exporterLabel                 = "exp master"
	resumptionLabel               = "res master"
	trafficUpdateLabel            = "traffic upd"
)

// expandLabel implements HKDF-Expand-Label from RFC 8446, Section 7.1.
func (c *cipherSuiteTLS13) expandLabel(secret []byte, label string, context []byte, length int) ([]byte, error) {
	var hkdfLabel cryptobyte.Builder
	hkdfLabel.AddUint16(uint16(length))
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte("tls13 "))
		b.AddBytes([]byte(label))
	})
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(context)
	})
	out := make([]byte, length)

	res, err := hkdf.Expand(c.hash.New, secret, hkdfLabel.BytesOrPanic())
	if err != nil {
		return nil, err
	}
	n, err := res.Read(out)
	if err != nil || n != length {
		return nil, errors.New("tls: HKDF-Expand-Label invocation failed unexpectedly")
	}
	return out, nil
}

// deriveSecret implements Derive-Secret from RFC 8446, Section 7.1.
func (c *cipherSuiteTLS13) deriveSecret(secret []byte, label string, transcript hash.Hash) ([]byte, error) {
	if transcript == nil {
		var err error
		transcript, err = c.hash.New()
		if err != nil {
			return nil, err
		}
	}
	Hsz, err := c.hash.Size()
	if err != nil {
		return nil, err
	}
	return c.expandLabel(secret, label, transcript.Sum(nil), Hsz)
}

// extract implements HKDF-Extract with the cipher suite hash.
func (c *cipherSuiteTLS13) extract(newSecret, currentSecret []byte) ([]byte, error) {
	if newSecret == nil {
		Hsz, err := c.hash.Size()
		if err != nil {
			return nil, err
		}
		newSecret = make([]byte, Hsz)
	}
	return hkdf.Extract(c.hash.New, newSecret, currentSecret)
}

// nextTrafficSecret generates the next traffic secret, given the current one,
// according to RFC 8446, Section 7.2.
func (c *cipherSuiteTLS13) nextTrafficSecret(trafficSecret []byte) ([]byte, error) {
	Hsz, err := c.hash.Size()
	if err != nil {
		return nil, err
	}
	return c.expandLabel(trafficSecret, trafficUpdateLabel, nil, Hsz)
}

// trafficKey generates traffic keys according to RFC 8446, Section 7.3.
func (c *cipherSuiteTLS13) trafficKey(trafficSecret []byte) (key, iv []byte, err error) {
	key, err = c.expandLabel(trafficSecret, "key", nil, c.keyLen)
	iv, err = c.expandLabel(trafficSecret, "iv", nil, aeadNonceLength)
	return
}

// finishedHash generates the Finished verify_data or PskBinderEntry according
// to RFC 8446, Section 4.4.4. See sections 4.4 and 4.2.11.2 for the baseKey
// selection.
func (c *cipherSuiteTLS13) finishedHash(baseKey []byte, transcript hash.Hash) ([]byte, error) {
	Hsz, err := c.hash.Size()
	if err != nil {
		return nil, err
	}
	finishedKey, err := c.expandLabel(baseKey, "finished", nil, Hsz)
	if err != nil {
		return nil, err
	}
	verifyData, err := hmac.New(c.hash.New, finishedKey)
	if err != nil {
		return nil, err
	}
	verifyData.Write(transcript.Sum(nil))
	return verifyData.Sum(nil), err
}

// exportKeyingMaterial implements RFC5705 exporters for TLS 1.3 according to
// RFC 8446, Section 7.5.
func (c *cipherSuiteTLS13) exportKeyingMaterial(masterSecret []byte, transcript hash.Hash) (func(string, []byte, int) ([]byte, error), error) {
	expMasterSecret, err := c.deriveSecret(masterSecret, exporterLabel, transcript)
	if err != nil {
		return nil, err
	}
	return func(label string, context []byte, length int) ([]byte, error) {
		secret, err := c.deriveSecret(expMasterSecret, label, nil)
		if err != nil {
			return nil, err
		}
		h, err := c.hash.New()
		if err != nil {
			return nil, err
		}
		h.Write(context)
		res, err := c.expandLabel(secret, "exporter", h.Sum(nil), length)
		if err != nil {
			return nil, err
		}
		return res, nil
	}, nil
}

// ecdheParameters implements Diffie-Hellman with either NIST curves or X25519,
// according to RFC 8446, Section 4.2.8.2.
type ecdheParameters interface {
	CurveID() CurveID
	PublicKey() []byte
	SharedKey(peerPublicKey []byte) []byte
}

func generateECDHEParameters(rand io.Reader, curveID CurveID) (ecdheParameters, error) {
	if curveID == X25519 {
		privateKey := make([]byte, curve25519.ScalarSize)
		if _, err := io.ReadFull(rand, privateKey); err != nil {
			return nil, err
		}
		publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
		if err != nil {
			return nil, err
		}
		return &x25519Parameters{privateKey: privateKey, publicKey: publicKey}, nil
	}

	curve, ok := curveForCurveID(curveID)
	if !ok {
		return nil, errors.New("tls: internal error: unsupported curve")
	}

	p := &nistParameters{curveID: curveID}
	var err error
	p.privateKey, p.x, p.y, err = elliptic.GenerateKey(curve, rand)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func curveForCurveID(id CurveID) (elliptic.Curve, bool) {
	switch id {
	case CurveP256:
		return elliptic.P256(), true
	case CurveP384:
		return elliptic.P384(), true
	case CurveP521:
		return elliptic.P521(), true
	default:
		return nil, false
	}
}

type nistParameters struct {
	privateKey []byte
	x, y       *big.Int // public key
	curveID    CurveID
}

func (p *nistParameters) CurveID() CurveID {
	return p.curveID
}

func (p *nistParameters) PublicKey() []byte {
	curve, _ := curveForCurveID(p.curveID)
	return elliptic.Marshal(curve, p.x, p.y)
}

func (p *nistParameters) SharedKey(peerPublicKey []byte) []byte {
	curve, _ := curveForCurveID(p.curveID)
	// Unmarshal also checks whether the given point is on the curve.
	x, y := elliptic.Unmarshal(curve, peerPublicKey)
	if x == nil {
		return nil
	}

	xShared, _ := curve.ScalarMult(x, y, p.privateKey)
	sharedKey := make([]byte, (curve.Params().BitSize+7)>>3)
	xBytes := xShared.Bytes()
	copy(sharedKey[len(sharedKey)-len(xBytes):], xBytes)

	return sharedKey
}

type x25519Parameters struct {
	privateKey []byte
	publicKey  []byte
}

func (p *x25519Parameters) CurveID() CurveID {
	return X25519
}

func (p *x25519Parameters) PublicKey() []byte {
	return p.publicKey[:]
}

func (p *x25519Parameters) SharedKey(peerPublicKey []byte) []byte {
	sharedKey, err := curve25519.X25519(p.privateKey, peerPublicKey)
	if err != nil {
		return nil
	}
	return sharedKey
}
