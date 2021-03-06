// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"errors"
	"github.com/ElrondfromRussia/cryptofix"
	"github.com/ElrondfromRussia/cryptofix/hmac"
	"github.com/ElrondfromRussia/cryptofix/rsa"
	"hash"
	"sync/atomic"
	"time"
)

type clientHandshakeStateTLS13 struct {
	c           *Conn
	serverHello *serverHelloMsg
	hello       *clientHelloMsg
	ecdheParams ecdheParameters

	session     *ClientSessionState
	earlySecret []byte
	binderKey   []byte

	certReq       *certificateRequestMsgTLS13
	usingPSK      bool
	sentDummyCCS  bool
	suite         *cipherSuiteTLS13
	transcript    hash.Hash
	masterSecret  []byte
	trafficSecret []byte // client_application_traffic_secret_0
}

// handshake requires hs.c, hs.hello, hs.serverHello, hs.ecdheParams, and,
// optionally, hs.session, hs.earlySecret and hs.binderKey to be set.
func (hs *clientHandshakeStateTLS13) handshake() error {
	c := hs.c
	var err error

	// The server must not select TLS 1.3 in a renegotiation. See RFC 8446,
	// sections 4.1.2 and 4.1.3.
	if c.handshakes > 0 {
		_ = c.sendAlert(alertProtocolVersion)
		return errors.New("tls: server selected TLS 1.3 in a renegotiation")
	}

	// Consistency check on the presence of a keyShare and its parameters.
	if hs.ecdheParams == nil || len(hs.hello.keyShares) != 1 {
		return c.sendAlert(alertInternalError)
	}

	if err := hs.checkServerHelloOrHRR(); err != nil {
		return err
	}

	hs.transcript, err = hs.suite.hash.New()
	if err != nil {
		return err
	}

	resMursh, err := hs.hello.marshal()
	if err != nil {
		return err
	}
	hs.transcript.Write(resMursh)

	if bytes.Equal(hs.serverHello.random, helloRetryRequestRandom) {
		if err := hs.sendDummyChangeCipherSpec(); err != nil {
			return err
		}
		if err := hs.processHelloRetryRequest(); err != nil {
			return err
		}
	}

	resMursh, err = hs.serverHello.marshal()
	if err != nil {
		return err
	}
	hs.transcript.Write(resMursh)

	c.buffering = true
	if err := hs.processServerHello(); err != nil {
		return err
	}
	if err := hs.sendDummyChangeCipherSpec(); err != nil {
		return err
	}
	if err := hs.establishHandshakeKeys(); err != nil {
		return err
	}
	if err := hs.readServerParameters(); err != nil {
		return err
	}
	if err := hs.readServerCertificate(); err != nil {
		return err
	}
	if err := hs.readServerFinished(); err != nil {
		return err
	}
	if err := hs.sendClientCertificate(); err != nil {
		return err
	}
	if err := hs.sendClientFinished(); err != nil {
		return err
	}
	if _, err := c.flush(); err != nil {
		return err
	}

	atomic.StoreUint32(&c.handshakeStatus, 1)

	return nil
}

// checkServerHelloOrHRR does validity checks that apply to both ServerHello and
// HelloRetryRequest messages. It sets hs.suite.
func (hs *clientHandshakeStateTLS13) checkServerHelloOrHRR() error {
	c := hs.c

	if hs.serverHello.supportedVersion == 0 {
		_ = c.sendAlert(alertMissingExtension)
		return errors.New("tls: server selected TLS 1.3 using the legacy version field")
	}

	if hs.serverHello.supportedVersion != VersionTLS13 {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server selected an invalid version after a HelloRetryRequest")
	}

	if hs.serverHello.vers != VersionTLS12 {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server sent an incorrect legacy version")
	}

	if hs.serverHello.ocspStapling ||
		hs.serverHello.ticketSupported ||
		hs.serverHello.secureRenegotiationSupported ||
		len(hs.serverHello.secureRenegotiation) != 0 ||
		len(hs.serverHello.alpnProtocol) != 0 ||
		len(hs.serverHello.scts) != 0 {
		_ = c.sendAlert(alertUnsupportedExtension)
		return errors.New("tls: server sent a ServerHello extension forbidden in TLS 1.3")
	}

	if !bytes.Equal(hs.hello.sessionId, hs.serverHello.sessionId) {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server did not echo the legacy session ID")
	}

	if hs.serverHello.compressionMethod != compressionNone {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server selected unsupported compression format")
	}

	selectedSuite := mutualCipherSuiteTLS13(hs.hello.cipherSuites, hs.serverHello.cipherSuite)
	if hs.suite != nil && selectedSuite != hs.suite {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server changed cipher suite after a HelloRetryRequest")
	}
	if selectedSuite == nil {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server chose an unconfigured cipher suite")
	}
	hs.suite = selectedSuite
	c.cipherSuite = hs.suite.id

	return nil
}

// sendDummyChangeCipherSpec sends a ChangeCipherSpec record for compatibility
// with middleboxes that didn't implement TLS correctly. See RFC 8446, Appendix D.4.
func (hs *clientHandshakeStateTLS13) sendDummyChangeCipherSpec() error {
	if hs.sentDummyCCS {
		return nil
	}
	hs.sentDummyCCS = true

	_, err := hs.c.writeRecord(recordTypeChangeCipherSpec, []byte{1})
	return err
}

// processHelloRetryRequest handles the HRR in hs.serverHello, modifies and
// resends hs.hello, and reads the new ServerHello into hs.serverHello.
func (hs *clientHandshakeStateTLS13) processHelloRetryRequest() error {
	c := hs.c

	// The first ClientHello gets double-hashed into the transcript upon a
	// HelloRetryRequest. See RFC 8446, Section 4.4.1.
	chHash := hs.transcript.Sum(nil)
	hs.transcript.Reset()
	hs.transcript.Write([]byte{typeMessageHash, 0, 0, uint8(len(chHash))})
	hs.transcript.Write(chHash)
	resMursh, err := hs.serverHello.marshal()
	if err != nil {
		return err
	}
	hs.transcript.Write(resMursh)

	if hs.serverHello.serverShare.group != 0 {
		_ = c.sendAlert(alertDecodeError)
		return errors.New("tls: received malformed key_share extension")
	}

	curveID := hs.serverHello.selectedGroup
	if curveID == 0 {
		_ = c.sendAlert(alertMissingExtension)
		return errors.New("tls: received HelloRetryRequest without selected group")
	}
	curveOK := false
	for _, id := range hs.hello.supportedCurves {
		if id == curveID {
			curveOK = true
			break
		}
	}
	if !curveOK {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server selected unsupported group")
	}
	if hs.ecdheParams.CurveID() == curveID {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server sent an unnecessary HelloRetryRequest message")
	}
	if _, ok := curveForCurveID(curveID); curveID != X25519 && !ok {
		_ = c.sendAlert(alertInternalError)
		return errors.New("tls: CurvePreferences includes unsupported curve")
	}
	params, err := generateECDHEParameters(c.config.rand(), curveID)
	if err != nil {
		_ = c.sendAlert(alertInternalError)
		return err
	}
	hs.ecdheParams = params
	hs.hello.keyShares = []keyShare{{group: curveID, data: params.PublicKey()}}

	hs.hello.cookie = hs.serverHello.cookie

	hs.hello.raw = nil
	if len(hs.hello.pskIdentities) > 0 {
		pskSuite := cipherSuiteTLS13ByID(hs.session.cipherSuite)
		if pskSuite == nil {
			return c.sendAlert(alertInternalError)
		}
		if pskSuite.hash == hs.suite.hash {
			// Update binders and obfuscated_ticket_age.
			ticketAge := uint32(c.config.time().Sub(hs.session.receivedAt) / time.Millisecond)
			hs.hello.pskIdentities[0].obfuscatedTicketAge = ticketAge + hs.session.ageAdd

			transcript, err := hs.suite.hash.New()
			if err != nil {
				return err
			}
			transcript.Write([]byte{typeMessageHash, 0, 0, uint8(len(chHash))})
			transcript.Write(chHash)
			resMursh, err := hs.serverHello.marshal()
			if err != nil {
				return err
			}
			transcript.Write(resMursh)
			resMursh, err = hs.hello.marshalWithoutBinders()
			if err != nil {
				return err
			}
			transcript.Write(resMursh)
			finHash, err := hs.suite.finishedHash(hs.binderKey, transcript)
			if err != nil {
				return err
			}
			pskBinders := [][]byte{finHash}
			//TODO: think, not sure about that
			hs.hello.updateBinders(pskBinders)
		} else {
			// Server selected a cipher suite incompatible with the PSK.
			hs.hello.pskIdentities = nil
			hs.hello.pskBinders = nil
		}
	}

	resMursh, err = hs.hello.marshal()
	if err != nil {
		return err
	}
	hs.transcript.Write(resMursh)
	resMursh, err = hs.hello.marshal()
	if err != nil {
		return err
	}
	if _, err := c.writeRecord(recordTypeHandshake, resMursh); err != nil {
		return err
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	serverHello, ok := msg.(*serverHelloMsg)
	if !ok {
		_ = c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverHello, msg)
	}
	hs.serverHello = serverHello

	if err := hs.checkServerHelloOrHRR(); err != nil {
		return err
	}

	return nil
}

func (hs *clientHandshakeStateTLS13) processServerHello() error {
	c := hs.c

	if bytes.Equal(hs.serverHello.random, helloRetryRequestRandom) {
		_ = c.sendAlert(alertUnexpectedMessage)
		return errors.New("tls: server sent two HelloRetryRequest messages")
	}

	if len(hs.serverHello.cookie) != 0 {
		_ = c.sendAlert(alertUnsupportedExtension)
		return errors.New("tls: server sent a cookie in a normal ServerHello")
	}

	if hs.serverHello.selectedGroup != 0 {
		_ = c.sendAlert(alertDecodeError)
		return errors.New("tls: malformed key_share extension")
	}

	if hs.serverHello.serverShare.group == 0 {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server did not send a key share")
	}
	if hs.serverHello.serverShare.group != hs.ecdheParams.CurveID() {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server selected unsupported group")
	}

	if !hs.serverHello.selectedIdentityPresent {
		return nil
	}

	if int(hs.serverHello.selectedIdentity) >= len(hs.hello.pskIdentities) {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server selected an invalid PSK")
	}

	if len(hs.hello.pskIdentities) != 1 || hs.session == nil {
		return c.sendAlert(alertInternalError)
	}
	pskSuite := cipherSuiteTLS13ByID(hs.session.cipherSuite)
	if pskSuite == nil {
		return c.sendAlert(alertInternalError)
	}
	if pskSuite.hash != hs.suite.hash {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server selected an invalid PSK and cipher suite pair")
	}

	hs.usingPSK = true
	c.didResume = true
	c.peerCertificates = hs.session.serverCertificates
	c.verifiedChains = hs.session.verifiedChains
	return nil
}

func (hs *clientHandshakeStateTLS13) establishHandshakeKeys() error {
	c := hs.c

	sharedKey := hs.ecdheParams.SharedKey(hs.serverHello.serverShare.data)
	if sharedKey == nil {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("tls: invalid server key share")
	}

	earlySecret := hs.earlySecret
	var err error
	if !hs.usingPSK {
		earlySecret, err = hs.suite.extract(nil, nil)
		if err != nil {
			return err
		}
	}
	derSecret, err := hs.suite.deriveSecret(earlySecret, "derived", nil)
	if err != nil {
		return err
	}
	handshakeSecret, err := hs.suite.extract(sharedKey, derSecret)
	if err != nil {
		return err
	}

	clientSecret, err := hs.suite.deriveSecret(handshakeSecret,
		clientHandshakeTrafficLabel, hs.transcript)
	if err != nil {
		return err
	}
	err = c.out.setTrafficSecret(hs.suite, clientSecret)
	if err != nil {
		return err
	}
	serverSecret, err := hs.suite.deriveSecret(handshakeSecret,
		serverHandshakeTrafficLabel, hs.transcript)
	if err != nil {
		return err
	}
	err = c.in.setTrafficSecret(hs.suite, serverSecret)
	if err != nil {
		return err
	}

	err = c.config.writeKeyLog(keyLogLabelClientHandshake, hs.hello.random, clientSecret)
	if err != nil {
		_ = c.sendAlert(alertInternalError)
		return err
	}
	err = c.config.writeKeyLog(keyLogLabelServerHandshake, hs.hello.random, serverSecret)
	if err != nil {
		_ = c.sendAlert(alertInternalError)
		return err
	}
	derSecret, err = hs.suite.deriveSecret(handshakeSecret, "derived", nil)
	if err != nil {
		return err
	}
	hs.masterSecret, err = hs.suite.extract(nil, derSecret)
	if err != nil {
		return err
	}

	return nil
}

func (hs *clientHandshakeStateTLS13) readServerParameters() error {
	c := hs.c

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	encryptedExtensions, ok := msg.(*encryptedExtensionsMsg)
	if !ok {
		_ = c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(encryptedExtensions, msg)
	}
	resMursh, err := encryptedExtensions.marshal()
	if err != nil {
		return err
	}
	hs.transcript.Write(resMursh)

	if len(encryptedExtensions.alpnProtocol) != 0 && len(hs.hello.alpnProtocols) == 0 {
		_ = c.sendAlert(alertUnsupportedExtension)
		return errors.New("tls: server advertised unrequested ALPN extension")
	}
	c.clientProtocol = encryptedExtensions.alpnProtocol

	return nil
}

func (hs *clientHandshakeStateTLS13) readServerCertificate() error {
	c := hs.c

	// Either a PSK or a certificate is always used, but not both.
	// See RFC 8446, Section 4.1.1.
	if hs.usingPSK {
		return nil
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	certReq, ok := msg.(*certificateRequestMsgTLS13)
	if ok {
		resMursh, err := certReq.marshal()
		if err != nil {
			return err
		}
		hs.transcript.Write(resMursh)

		hs.certReq = certReq

		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	certMsg, ok := msg.(*certificateMsgTLS13)
	if !ok {
		_ = c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(certMsg, msg)
	}
	if len(certMsg.certificate.Certificate) == 0 {
		_ = c.sendAlert(alertDecodeError)
		return errors.New("tls: received empty certificates message")
	}
	resMursh, err := certMsg.marshal()
	if err != nil {
		return err
	}
	hs.transcript.Write(resMursh)

	c.scts = certMsg.certificate.SignedCertificateTimestamps
	c.ocspResponse = certMsg.certificate.OCSPStaple

	if err := c.verifyServerCertificate(certMsg.certificate.Certificate); err != nil {
		return err
	}

	msg, err = c.readHandshake()
	if err != nil {
		return err
	}

	certVerify, ok := msg.(*certificateVerifyMsg)
	if !ok {
		_ = c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(certVerify, msg)
	}

	// See RFC 8446, Section 4.4.3.
	if !isSupportedSignatureAlgorithm(certVerify.signatureAlgorithm, supportedSignatureAlgorithms) {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("tls: certificate used with invalid signature algorithm")
	}
	sigType, sigHash, err := typeAndHashFromSignatureScheme(certVerify.signatureAlgorithm)
	if err != nil {
		return c.sendAlert(alertInternalError)
	}
	if sigType == signaturePKCS1v15 || sigHash == cryptofix.SHA1 {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("tls: certificate used with invalid signature algorithm")
	}
	signed, err := signedMessage(sigHash, serverSignatureContext, hs.transcript)
	if err != nil {
		return err
	}
	if err := verifyHandshakeSignature(sigType, c.peerCertificates[0].PublicKey,
		sigHash, signed, certVerify.signature); err != nil {
		_ = c.sendAlert(alertDecryptError)
		return errors.New("tls: invalid signature by the server certificate: " + err.Error())
	}

	resMursh, err = certVerify.marshal()
	if err != nil {
		return err
	}
	hs.transcript.Write(resMursh)

	return nil
}

func (hs *clientHandshakeStateTLS13) readServerFinished() error {
	c := hs.c

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	finished, ok := msg.(*finishedMsg)
	if !ok {
		_ = c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(finished, msg)
	}

	expectedMAC, err := hs.suite.finishedHash(c.in.trafficSecret, hs.transcript)
	if err != nil {
		return err
	}
	if !hmac.Equal(expectedMAC, finished.verifyData) {
		_ = c.sendAlert(alertDecryptError)
		return errors.New("tls: invalid server finished hash")
	}

	resMursh, err := finished.marshal()
	if err != nil {
		return err
	}
	hs.transcript.Write(resMursh)

	// Derive secrets that take context through the server Finished.

	hs.trafficSecret, err = hs.suite.deriveSecret(hs.masterSecret,
		clientApplicationTrafficLabel, hs.transcript)
	if err != nil {
		return err
	}
	serverSecret, err := hs.suite.deriveSecret(hs.masterSecret,
		serverApplicationTrafficLabel, hs.transcript)
	if err != nil {
		return err
	}
	err = c.in.setTrafficSecret(hs.suite, serverSecret)
	if err != nil {
		return err
	}

	err = c.config.writeKeyLog(keyLogLabelClientTraffic, hs.hello.random, hs.trafficSecret)
	if err != nil {
		_ = c.sendAlert(alertInternalError)
		return err
	}
	err = c.config.writeKeyLog(keyLogLabelServerTraffic, hs.hello.random, serverSecret)
	if err != nil {
		_ = c.sendAlert(alertInternalError)
		return err
	}

	c.ekm, err = hs.suite.exportKeyingMaterial(hs.masterSecret, hs.transcript)
	if err != nil {
		return err
	}

	return nil
}

func (hs *clientHandshakeStateTLS13) sendClientCertificate() error {
	c := hs.c

	if hs.certReq == nil {
		return nil
	}

	cert, err := c.getClientCertificate(&CertificateRequestInfo{
		AcceptableCAs:    hs.certReq.certificateAuthorities,
		SignatureSchemes: hs.certReq.supportedSignatureAlgorithms,
		Version:          c.vers,
	})
	if err != nil {
		return err
	}

	certMsg := new(certificateMsgTLS13)

	certMsg.certificate = *cert
	certMsg.scts = hs.certReq.scts && len(cert.SignedCertificateTimestamps) > 0
	certMsg.ocspStapling = hs.certReq.ocspStapling && len(cert.OCSPStaple) > 0

	resMursh, err := certMsg.marshal()
	if err != nil {
		return err
	}
	hs.transcript.Write(resMursh)
	resMursh, err = certMsg.marshal()
	if err != nil {
		return err
	}
	if _, err := c.writeRecord(recordTypeHandshake, resMursh); err != nil {
		return err
	}

	// If we sent an empty certificate message, skip the CertificateVerify.
	if len(cert.Certificate) == 0 {
		return nil
	}

	certVerifyMsg := new(certificateVerifyMsg)
	certVerifyMsg.hasSignatureAlgorithm = true

	certVerifyMsg.signatureAlgorithm, err = selectSignatureScheme(c.vers, cert, hs.certReq.supportedSignatureAlgorithms)
	if err != nil {
		// getClientCertificate returned a certificate incompatible with the
		// CertificateRequestInfo supported signature algorithms.
		_ = c.sendAlert(alertHandshakeFailure)
		return err
	}

	sigType, sigHash, err := typeAndHashFromSignatureScheme(certVerifyMsg.signatureAlgorithm)
	if err != nil {
		return c.sendAlert(alertInternalError)
	}

	signed, err := signedMessage(sigHash, clientSignatureContext, hs.transcript)
	if err != nil {
		return err
	}
	signOpts := cryptofix.SignerOpts(sigHash)
	if sigType == signatureRSAPSS {
		signOpts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash}
	}
	sig, err := cert.PrivateKey.(cryptofix.Signer).Sign(c.config.rand(), signed, signOpts)
	if err != nil {
		_ = c.sendAlert(alertInternalError)
		return errors.New("tls: failed to sign handshake: " + err.Error())
	}
	certVerifyMsg.signature = sig

	resMursh, err = certVerifyMsg.marshal()
	if err != nil {
		return err
	}
	hs.transcript.Write(resMursh)
	resMursh, err = certVerifyMsg.marshal()
	if err != nil {
		return err
	}
	if _, err := c.writeRecord(recordTypeHandshake, resMursh); err != nil {
		return err
	}

	return nil
}

func (hs *clientHandshakeStateTLS13) sendClientFinished() error {
	c := hs.c

	finHash, err := hs.suite.finishedHash(c.out.trafficSecret, hs.transcript)
	if err != nil {
		return err
	}

	finished := &finishedMsg{
		verifyData: finHash,
	}

	resMursh, err := finished.marshal()
	if err != nil {
		return err
	}
	hs.transcript.Write(resMursh)
	resMursh, err = finished.marshal()
	if err != nil {
		return err
	}
	if _, err := c.writeRecord(recordTypeHandshake, resMursh); err != nil {
		return err
	}

	err = c.out.setTrafficSecret(hs.suite, hs.trafficSecret)
	if err != nil {
		return err
	}

	if !c.config.SessionTicketsDisabled && c.config.ClientSessionCache != nil {
		c.resumptionSecret, err = hs.suite.deriveSecret(hs.masterSecret,
			resumptionLabel, hs.transcript)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Conn) handleNewSessionTicket(msg *newSessionTicketMsgTLS13) error {
	if !c.isClient {
		_ = c.sendAlert(alertUnexpectedMessage)
		return errors.New("tls: received new session ticket from a client")
	}

	if c.config.SessionTicketsDisabled || c.config.ClientSessionCache == nil {
		return nil
	}

	// See RFC 8446, Section 4.6.1.
	if msg.lifetime == 0 {
		return nil
	}
	lifetime := time.Duration(msg.lifetime) * time.Second
	if lifetime > maxSessionTicketLifetime {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("tls: received a session ticket with invalid lifetime")
	}

	cipherSuite := cipherSuiteTLS13ByID(c.cipherSuite)
	if cipherSuite == nil || c.resumptionSecret == nil {
		return c.sendAlert(alertInternalError)
	}

	// Save the resumption_master_secret and nonce instead of deriving the PSK
	// to do the least amount of work on NewSessionTicket messages before we
	// know if the ticket will be used. Forward secrecy of resumed connections
	// is guaranteed by the requirement for pskModeDHE.
	session := &ClientSessionState{
		sessionTicket:      msg.label,
		vers:               c.vers,
		cipherSuite:        c.cipherSuite,
		masterSecret:       c.resumptionSecret,
		serverCertificates: c.peerCertificates,
		verifiedChains:     c.verifiedChains,
		receivedAt:         c.config.time(),
		nonce:              msg.nonce,
		useBy:              c.config.time().Add(lifetime),
		ageAdd:             msg.ageAdd,
	}

	cacheKey := clientSessionCacheKey(c.conn.RemoteAddr(), c.config)
	c.config.ClientSessionCache.Put(cacheKey, session)

	return nil
}
