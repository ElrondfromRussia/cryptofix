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
	"io"
	"sync/atomic"
	"time"
)

// maxClientPSKIdentities is the number of client PSK identities the server will
// attempt to validate. It will ignore the rest not to let cheap ClientHello
// messages cause too much work in session ticket decryption attempts.
const maxClientPSKIdentities = 5

type serverHandshakeStateTLS13 struct {
	c               *Conn
	clientHello     *clientHelloMsg
	hello           *serverHelloMsg
	sentDummyCCS    bool
	usingPSK        bool
	suite           *cipherSuiteTLS13
	cert            *Certificate
	sigAlg          SignatureScheme
	earlySecret     []byte
	sharedKey       []byte
	handshakeSecret []byte
	masterSecret    []byte
	trafficSecret   []byte // client_application_traffic_secret_0
	transcript      hash.Hash
	clientFinished  []byte
}

func (hs *serverHandshakeStateTLS13) handshake() error {
	c := hs.c

	// For an overview of the TLS 1.3 handshake, see RFC 8446, Section 2.
	if err := hs.processClientHello(); err != nil {
		return err
	}
	if err := hs.checkForResumption(); err != nil {
		return err
	}
	if err := hs.pickCertificate(); err != nil {
		return err
	}
	c.buffering = true
	if err := hs.sendServerParameters(); err != nil {
		return err
	}
	if err := hs.sendServerCertificate(); err != nil {
		return err
	}
	if err := hs.sendServerFinished(); err != nil {
		return err
	}
	// Note that at this point we could start sending application data without
	// waiting for the client's second flight, but the application might not
	// expect the lack of replay protection of the ClientHello parameters.
	if _, err := c.flush(); err != nil {
		return err
	}
	if err := hs.readClientCertificate(); err != nil {
		return err
	}
	if err := hs.readClientFinished(); err != nil {
		return err
	}

	atomic.StoreUint32(&c.handshakeStatus, 1)

	return nil
}

func (hs *serverHandshakeStateTLS13) processClientHello() error {
	c := hs.c

	hs.hello = new(serverHelloMsg)

	// TLS 1.3 froze the ServerHello.legacy_version field, and uses
	// supported_versions instead. See RFC 8446, sections 4.1.3 and 4.2.1.
	hs.hello.vers = VersionTLS12
	hs.hello.supportedVersion = c.vers

	if len(hs.clientHello.supportedVersions) == 0 {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("tls: client used the legacy version field to negotiate TLS 1.3")
	}

	// Abort if the client is doing a fallback and landing lower than what we
	// support. See RFC 7507, which however does not specify the interaction
	// with supported_versions. The only difference is that with
	// supported_versions a client has a chance to attempt a [TLS 1.2, TLS 1.4]
	// handshake in case TLS 1.3 is broken but 1.2 is not. Alas, in that case,
	// it will have to drop the TLS_FALLBACK_SCSV protection if it falls back to
	// TLS 1.2, because a TLS 1.3 server would abort here. The situation before
	// supported_versions was not better because there was just no way to do a
	// TLS 1.4 handshake without risking the server selecting TLS 1.3.
	for _, id := range hs.clientHello.cipherSuites {
		if id == TLS_FALLBACK_SCSV {
			// Use c.vers instead of max(supported_versions) because an attacker
			// could defeat this by adding an arbitrary high version otherwise.
			if c.vers < c.config.maxSupportedVersion() {
				_ = c.sendAlert(alertInappropriateFallback)
				return errors.New("tls: client using inappropriate protocol fallback")
			}
			break
		}
	}

	if len(hs.clientHello.compressionMethods) != 1 ||
		hs.clientHello.compressionMethods[0] != compressionNone {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("tls: TLS 1.3 client supports illegal compression methods")
	}

	hs.hello.random = make([]byte, 32)
	if _, err := io.ReadFull(c.config.rand(), hs.hello.random); err != nil {
		_ = c.sendAlert(alertInternalError)
		return err
	}

	if len(hs.clientHello.secureRenegotiation) != 0 {
		_ = c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: initial handshake had non-empty renegotiation extension")
	}

	if hs.clientHello.earlyData {
		// See RFC 8446, Section 4.2.10 for the complicated behavior required
		// here. The scenario is that a different server at our address offered
		// to accept early data in the past, which we can't handle. For now, all
		// 0-RTT enabled session tickets need to expire before a Go server can
		// replace a server or join a pool. That's the same requirement that
		// applies to mixing or replacing with any TLS 1.2 server.
		_ = c.sendAlert(alertUnsupportedExtension)
		return errors.New("tls: client sent unexpected early data")
	}

	hs.hello.sessionId = hs.clientHello.sessionId
	hs.hello.compressionMethod = compressionNone

	var preferenceList, supportedList []uint16
	if c.config.PreferServerCipherSuites {
		preferenceList = defaultCipherSuitesTLS13()
		supportedList = hs.clientHello.cipherSuites
	} else {
		preferenceList = hs.clientHello.cipherSuites
		supportedList = defaultCipherSuitesTLS13()
	}
	for _, suiteID := range preferenceList {
		hs.suite = mutualCipherSuiteTLS13(supportedList, suiteID)
		if hs.suite != nil {
			break
		}
	}
	if hs.suite == nil {
		_ = c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: no cipher suite supported by both client and server")
	}
	c.cipherSuite = hs.suite.id
	hs.hello.cipherSuite = hs.suite.id
	var err error
	hs.transcript, err = hs.suite.hash.New()
	if err != nil {
		return err
	}

	// Pick the ECDHE group in server preference order, but give priority to
	// groups with a key share, to avoid a HelloRetryRequest round-trip.
	var selectedGroup CurveID
	var clientKeyShare *keyShare
GroupSelection:
	for _, preferredGroup := range c.config.curvePreferences() {
		for _, ks := range hs.clientHello.keyShares {
			if ks.group == preferredGroup {
				selectedGroup = ks.group
				clientKeyShare = &ks
				break GroupSelection
			}
		}
		if selectedGroup != 0 {
			continue
		}
		for _, group := range hs.clientHello.supportedCurves {
			if group == preferredGroup {
				selectedGroup = group
				break
			}
		}
	}
	if selectedGroup == 0 {
		_ = c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: no ECDHE curve supported by both client and server")
	}
	if clientKeyShare == nil {
		if err := hs.doHelloRetryRequest(selectedGroup); err != nil {
			return err
		}
		clientKeyShare = &hs.clientHello.keyShares[0]
	}

	if _, ok := curveForCurveID(selectedGroup); selectedGroup != X25519 && !ok {
		_ = c.sendAlert(alertInternalError)
		return errors.New("tls: CurvePreferences includes unsupported curve")
	}
	params, err := generateECDHEParameters(c.config.rand(), selectedGroup)
	if err != nil {
		_ = c.sendAlert(alertInternalError)
		return err
	}
	hs.hello.serverShare = keyShare{group: selectedGroup, data: params.PublicKey()}
	hs.sharedKey = params.SharedKey(clientKeyShare.data)
	if hs.sharedKey == nil {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("tls: invalid client key share")
	}

	c.serverName = hs.clientHello.serverName
	return nil
}

func (hs *serverHandshakeStateTLS13) checkForResumption() error {
	c := hs.c

	if c.config.SessionTicketsDisabled {
		return nil
	}

	modeOK := false
	for _, mode := range hs.clientHello.pskModes {
		if mode == pskModeDHE {
			modeOK = true
			break
		}
	}
	if !modeOK {
		return nil
	}

	if len(hs.clientHello.pskIdentities) != len(hs.clientHello.pskBinders) {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("tls: invalid or missing PSK binders")
	}
	if len(hs.clientHello.pskIdentities) == 0 {
		return nil
	}

	for i, identity := range hs.clientHello.pskIdentities {
		if i >= maxClientPSKIdentities {
			break
		}

		plaintext, _ := c.decryptTicket(identity.label)
		if plaintext == nil {
			continue
		}
		sessionState := new(sessionStateTLS13)
		if ok := sessionState.unmarshal(plaintext); !ok {
			continue
		}

		createdAt := time.Unix(int64(sessionState.createdAt), 0)
		if c.config.time().Sub(createdAt) > maxSessionTicketLifetime {
			continue
		}

		// We don't check the obfuscated ticket age because it's affected by
		// clock skew and it's only a freshness signal useful for shrinking the
		// window for replay attacks, which don't affect us as we don't do 0-RTT.

		pskSuite := cipherSuiteTLS13ByID(sessionState.cipherSuite)
		if pskSuite == nil || pskSuite.hash != hs.suite.hash {
			continue
		}

		// PSK connections don't re-establish client certificates, but carry
		// them over in the session ticket. Ensure the presence of client certs
		// in the ticket is consistent with the configured requirements.
		sessionHasClientCerts := len(sessionState.certificate.Certificate) != 0
		needClientCerts := requiresClientCert(c.config.ClientAuth)
		if needClientCerts && !sessionHasClientCerts {
			continue
		}
		if sessionHasClientCerts && c.config.ClientAuth == NoClientCert {
			continue
		}

		hsHS, err := hs.suite.hash.Size()
		if err != nil {
			return err
		}
		psk, err := hs.suite.expandLabel(sessionState.resumptionSecret, "resumption",
			nil, hsHS)
		if err != nil {
			return err
		}
		hs.earlySecret, err = hs.suite.extract(psk, nil)
		if err != nil {
			return err
		}
		binderKey, err := hs.suite.deriveSecret(hs.earlySecret, resumptionBinderLabel, nil)
		if err != nil {
			return err
		}
		// Clone the transcript in case a HelloRetryRequest was recorded.
		transcript := cloneHash(hs.transcript, hs.suite.hash)
		if transcript == nil {
			_ = c.sendAlert(alertInternalError)
			return errors.New("tls: internal error: failed to clone hash")
		}
		hsclientHelloM, err := hs.clientHello.marshal()
		if err != nil {
			return err
		}
		transcript.Write(hsclientHelloM)
		pskBinder, err := hs.suite.finishedHash(binderKey, transcript)
		if err != nil {
			return err
		}
		if !hmac.Equal(hs.clientHello.pskBinders[i], pskBinder) {
			_ = c.sendAlert(alertDecryptError)
			return errors.New("tls: invalid PSK binder")
		}

		if err := c.processCertsFromClient(sessionState.certificate); err != nil {
			return err
		}

		hs.hello.selectedIdentityPresent = true
		hs.hello.selectedIdentity = uint16(i)
		hs.usingPSK = true
		c.didResume = true
		return nil
	}

	return nil
}

// cloneHash uses the encoding.BinaryMarshaler and encoding.BinaryUnmarshaler
// interfaces implemented by standard library hashes to clone the state of in
// to a new instance of h. It returns nil if the operation fails.
func cloneHash(in hash.Hash, h cryptofix.Hash) hash.Hash {
	// Recreate the interface to avoid importing encoding.
	type binaryMarshaler interface {
		MarshalBinary() (data []byte, err error)
		UnmarshalBinary(data []byte) error
	}
	marshaler, ok := in.(binaryMarshaler)
	if !ok {
		return nil
	}
	state, err := marshaler.MarshalBinary()
	if err != nil {
		return nil
	}
	out, err := h.New()
	if err != nil {
		return nil
	}
	unmarshaler, ok := out.(binaryMarshaler)
	if !ok {
		return nil
	}
	if err := unmarshaler.UnmarshalBinary(state); err != nil {
		return nil
	}
	return out
}

func (hs *serverHandshakeStateTLS13) pickCertificate() error {
	c := hs.c

	// Only one of PSK and certificates are used at a time.
	if hs.usingPSK {
		return nil
	}

	// signature_algorithms is required in TLS 1.3. See RFC 8446, Section 4.2.3.
	if len(hs.clientHello.supportedSignatureAlgorithms) == 0 {
		return c.sendAlert(alertMissingExtension)
	}

	certificate, err := c.config.getCertificate(clientHelloInfo(c, hs.clientHello))
	if err != nil {
		if err == errNoCertificates {
			_ = c.sendAlert(alertUnrecognizedName)
		} else {
			_ = c.sendAlert(alertInternalError)
		}
		return err
	}
	hs.sigAlg, err = selectSignatureScheme(c.vers, certificate, hs.clientHello.supportedSignatureAlgorithms)
	if err != nil {
		// getCertificate returned a certificate that is unsupported or
		// incompatible with the client's signature algorithms.
		_ = c.sendAlert(alertHandshakeFailure)
		return err
	}
	hs.cert = certificate

	return nil
}

// sendDummyChangeCipherSpec sends a ChangeCipherSpec record for compatibility
// with middleboxes that didn't implement TLS correctly. See RFC 8446, Appendix D.4.
func (hs *serverHandshakeStateTLS13) sendDummyChangeCipherSpec() error {
	if hs.sentDummyCCS {
		return nil
	}
	hs.sentDummyCCS = true

	_, err := hs.c.writeRecord(recordTypeChangeCipherSpec, []byte{1})
	return err
}

func (hs *serverHandshakeStateTLS13) doHelloRetryRequest(selectedGroup CurveID) error {
	c := hs.c

	// The first ClientHello gets double-hashed into the transcript upon a
	// HelloRetryRequest. See RFC 8446, Section 4.4.1.
	hsclientHelloM, err := hs.clientHello.marshal()
	if err != nil {
		return err
	}
	hs.transcript.Write(hsclientHelloM)
	chHash := hs.transcript.Sum(nil)
	hs.transcript.Reset()
	hs.transcript.Write([]byte{typeMessageHash, 0, 0, uint8(len(chHash))})
	hs.transcript.Write(chHash)

	helloRetryRequest := &serverHelloMsg{
		vers:              hs.hello.vers,
		random:            helloRetryRequestRandom,
		sessionId:         hs.hello.sessionId,
		cipherSuite:       hs.hello.cipherSuite,
		compressionMethod: hs.hello.compressionMethod,
		supportedVersion:  hs.hello.supportedVersion,
		selectedGroup:     selectedGroup,
	}

	helloRetryRequestM, err := helloRetryRequest.marshal()
	if err != nil {
		return err
	}
	hs.transcript.Write(helloRetryRequestM)
	helloRetryRequestM, err = helloRetryRequest.marshal()
	if err != nil {
		return err
	}
	if _, err := c.writeRecord(recordTypeHandshake, helloRetryRequestM); err != nil {
		return err
	}

	if err := hs.sendDummyChangeCipherSpec(); err != nil {
		return err
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	clientHello, ok := msg.(*clientHelloMsg)
	if !ok {
		_ = c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(clientHello, msg)
	}

	if len(clientHello.keyShares) != 1 || clientHello.keyShares[0].group != selectedGroup {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("tls: client sent invalid key share in second ClientHello")
	}

	if clientHello.earlyData {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("tls: client indicated early data in second ClientHello")
	}

	if illegalClientHelloChange(clientHello, hs.clientHello) {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("tls: client illegally modified second ClientHello")
	}

	hs.clientHello = clientHello
	return nil
}

// illegalClientHelloChange reports whether the two ClientHello messages are
// different, with the exception of the changes allowed before and after a
// HelloRetryRequest. See RFC 8446, Section 4.1.2.
func illegalClientHelloChange(ch, ch1 *clientHelloMsg) bool {
	if len(ch.supportedVersions) != len(ch1.supportedVersions) ||
		len(ch.cipherSuites) != len(ch1.cipherSuites) ||
		len(ch.supportedCurves) != len(ch1.supportedCurves) ||
		len(ch.supportedSignatureAlgorithms) != len(ch1.supportedSignatureAlgorithms) ||
		len(ch.supportedSignatureAlgorithmsCert) != len(ch1.supportedSignatureAlgorithmsCert) ||
		len(ch.alpnProtocols) != len(ch1.alpnProtocols) {
		return true
	}
	for i := range ch.supportedVersions {
		if ch.supportedVersions[i] != ch1.supportedVersions[i] {
			return true
		}
	}
	for i := range ch.cipherSuites {
		if ch.cipherSuites[i] != ch1.cipherSuites[i] {
			return true
		}
	}
	for i := range ch.supportedCurves {
		if ch.supportedCurves[i] != ch1.supportedCurves[i] {
			return true
		}
	}
	for i := range ch.supportedSignatureAlgorithms {
		if ch.supportedSignatureAlgorithms[i] != ch1.supportedSignatureAlgorithms[i] {
			return true
		}
	}
	for i := range ch.supportedSignatureAlgorithmsCert {
		if ch.supportedSignatureAlgorithmsCert[i] != ch1.supportedSignatureAlgorithmsCert[i] {
			return true
		}
	}
	for i := range ch.alpnProtocols {
		if ch.alpnProtocols[i] != ch1.alpnProtocols[i] {
			return true
		}
	}
	return ch.vers != ch1.vers ||
		!bytes.Equal(ch.random, ch1.random) ||
		!bytes.Equal(ch.sessionId, ch1.sessionId) ||
		!bytes.Equal(ch.compressionMethods, ch1.compressionMethods) ||
		ch.serverName != ch1.serverName ||
		ch.ocspStapling != ch1.ocspStapling ||
		!bytes.Equal(ch.supportedPoints, ch1.supportedPoints) ||
		ch.ticketSupported != ch1.ticketSupported ||
		!bytes.Equal(ch.sessionTicket, ch1.sessionTicket) ||
		ch.secureRenegotiationSupported != ch1.secureRenegotiationSupported ||
		!bytes.Equal(ch.secureRenegotiation, ch1.secureRenegotiation) ||
		ch.scts != ch1.scts ||
		!bytes.Equal(ch.cookie, ch1.cookie) ||
		!bytes.Equal(ch.pskModes, ch1.pskModes)
}

func (hs *serverHandshakeStateTLS13) sendServerParameters() error {
	c := hs.c

	hsclientHelloM, err := hs.clientHello.marshal()
	if err != nil {
		return err
	}
	hs.transcript.Write(hsclientHelloM)
	hshelloMM, err := hs.hello.marshal()
	if err != nil {
		return err
	}
	hs.transcript.Write(hshelloMM)
	hshelloM, err := hs.hello.marshal()
	if err != nil {
		return err
	}
	if _, err := c.writeRecord(recordTypeHandshake, hshelloM); err != nil {
		return err
	}

	if err := hs.sendDummyChangeCipherSpec(); err != nil {
		return err
	}

	earlySecret := hs.earlySecret
	if earlySecret == nil {
		earlySecret, err = hs.suite.extract(nil, nil)
		if err != nil {
			return err
		}
	}

	derSecret, err := hs.suite.deriveSecret(earlySecret, "derived", nil)
	if err != nil {
		return err
	}

	hs.handshakeSecret, err = hs.suite.extract(hs.sharedKey, derSecret)
	if err != nil {
		return err
	}

	clientSecret, err := hs.suite.deriveSecret(hs.handshakeSecret,
		clientHandshakeTrafficLabel, hs.transcript)
	if err != nil {
		return err
	}
	err = c.in.setTrafficSecret(hs.suite, clientSecret)
	if err != nil {
		return err
	}
	serverSecret, err := hs.suite.deriveSecret(hs.handshakeSecret,
		serverHandshakeTrafficLabel, hs.transcript)
	err = c.out.setTrafficSecret(hs.suite, serverSecret)
	if err != nil {
		return err
	}

	err = c.config.writeKeyLog(keyLogLabelClientHandshake, hs.clientHello.random, clientSecret)
	if err != nil {
		_ = c.sendAlert(alertInternalError)
		return err
	}
	err = c.config.writeKeyLog(keyLogLabelServerHandshake, hs.clientHello.random, serverSecret)
	if err != nil {
		_ = c.sendAlert(alertInternalError)
		return err
	}

	encryptedExtensions := new(encryptedExtensionsMsg)

	if len(hs.clientHello.alpnProtocols) > 0 {
		if selectedProto, fallback := mutualProtocol(hs.clientHello.alpnProtocols, c.config.NextProtos); !fallback {
			encryptedExtensions.alpnProtocol = selectedProto
			c.clientProtocol = selectedProto
		}
	}

	encryptedExtensionsM, err := encryptedExtensions.marshal()
	if err != nil {
		return err
	}
	hs.transcript.Write(encryptedExtensionsM)
	encryptedExtensionsM, err = encryptedExtensions.marshal()
	if err != nil {
		return err
	}
	if _, err := c.writeRecord(recordTypeHandshake, encryptedExtensionsM); err != nil {
		return err
	}

	return nil
}

func (hs *serverHandshakeStateTLS13) requestClientCert() bool {
	return hs.c.config.ClientAuth >= RequestClientCert && !hs.usingPSK
}

func (hs *serverHandshakeStateTLS13) sendServerCertificate() error {
	c := hs.c

	// Only one of PSK and certificates are used at a time.
	if hs.usingPSK {
		return nil
	}

	if hs.requestClientCert() {
		// Request a client certificate
		certReq := new(certificateRequestMsgTLS13)
		certReq.ocspStapling = true
		certReq.scts = true
		certReq.supportedSignatureAlgorithms = supportedSignatureAlgorithms
		if c.config.ClientCAs != nil {
			certReq.certificateAuthorities = c.config.ClientCAs.Subjects()
		}

		certReqM, err := certReq.marshal()
		if err != nil {
			return err
		}
		hs.transcript.Write(certReqM)
		certReqM, err = certReq.marshal()
		if err != nil {
			return err
		}
		if _, err := c.writeRecord(recordTypeHandshake, certReqM); err != nil {
			return err
		}
	}

	certMsg := new(certificateMsgTLS13)

	certMsg.certificate = *hs.cert
	certMsg.scts = hs.clientHello.scts && len(hs.cert.SignedCertificateTimestamps) > 0
	certMsg.ocspStapling = hs.clientHello.ocspStapling && len(hs.cert.OCSPStaple) > 0

	certMsgM, err := certMsg.marshal()
	if err != nil {
		return err
	}
	hs.transcript.Write(certMsgM)
	certMsgM, err = certMsg.marshal()
	if err != nil {
		return err
	}
	if _, err := c.writeRecord(recordTypeHandshake, certMsgM); err != nil {
		return err
	}

	certVerifyMsg := new(certificateVerifyMsg)
	certVerifyMsg.hasSignatureAlgorithm = true
	certVerifyMsg.signatureAlgorithm = hs.sigAlg

	sigType, sigHash, err := typeAndHashFromSignatureScheme(hs.sigAlg)
	if err != nil {
		return c.sendAlert(alertInternalError)
	}

	signed, err := signedMessage(sigHash, serverSignatureContext, hs.transcript)
	if err != nil {
		return err
	}
	signOpts := cryptofix.SignerOpts(sigHash)
	if sigType == signatureRSAPSS {
		signOpts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash}
	}
	sig, err := hs.cert.PrivateKey.(cryptofix.Signer).Sign(c.config.rand(), signed, signOpts)
	if err != nil {
		public := hs.cert.PrivateKey.(cryptofix.Signer).Public()
		sHSize, errM := sigHash.Size()
		if errM != nil {
			return errM
		}
		if rsaKey, ok := public.(*rsa.PublicKey); ok && sigType == signatureRSAPSS &&
			rsaKey.N.BitLen()/8 < sHSize*2+2 { // key too small for RSA-PSS
			_ = c.sendAlert(alertHandshakeFailure)
		} else {
			_ = c.sendAlert(alertInternalError)
		}
		return errors.New("tls: failed to sign handshake: " + err.Error())
	}
	certVerifyMsg.signature = sig

	certVerifyMsgM, err := certVerifyMsg.marshal()
	if err != nil {
		return err
	}
	hs.transcript.Write(certVerifyMsgM)
	certVerifyMsgM, err = certVerifyMsg.marshal()
	if err != nil {
		return err
	}
	if _, err := c.writeRecord(recordTypeHandshake, certVerifyMsgM); err != nil {
		return err
	}

	return nil
}

func (hs *serverHandshakeStateTLS13) sendServerFinished() error {
	c := hs.c

	finHash, err := hs.suite.finishedHash(c.out.trafficSecret, hs.transcript)
	if err != nil {
		return err
	}

	finished := &finishedMsg{
		verifyData: finHash,
	}

	finishedM, err := finished.marshal()
	if err != nil {
		return err
	}
	hs.transcript.Write(finishedM)
	finishedM, err = finished.marshal()
	if err != nil {
		return err
	}
	if _, err := c.writeRecord(recordTypeHandshake, finishedM); err != nil {
		return err
	}

	// Derive secrets that take context through the server Finished.

	derSecret, err := hs.suite.deriveSecret(hs.handshakeSecret, "derived", nil)
	if err != nil {
		return err
	}

	hs.masterSecret, err = hs.suite.extract(nil, derSecret)
	if err != nil {
		return err
	}

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
	err = c.out.setTrafficSecret(hs.suite, serverSecret)
	if err != nil {
		return err
	}

	err = c.config.writeKeyLog(keyLogLabelClientTraffic, hs.clientHello.random, hs.trafficSecret)
	if err != nil {
		_ = c.sendAlert(alertInternalError)
		return err
	}
	err = c.config.writeKeyLog(keyLogLabelServerTraffic, hs.clientHello.random, serverSecret)
	if err != nil {
		_ = c.sendAlert(alertInternalError)
		return err
	}

	c.ekm, err = hs.suite.exportKeyingMaterial(hs.masterSecret, hs.transcript)
	if err != nil {
		return err
	}

	// If we did not request client certificates, at this point we can
	// precompute the client finished and roll the transcript forward to send
	// session tickets in our first flight.
	if !hs.requestClientCert() {
		if err := hs.sendSessionTickets(); err != nil {
			return err
		}
	}

	return nil
}

func (hs *serverHandshakeStateTLS13) shouldSendSessionTickets() bool {
	if hs.c.config.SessionTicketsDisabled {
		return false
	}

	// Don't send tickets the client wouldn't use. See RFC 8446, Section 4.2.9.
	for _, pskMode := range hs.clientHello.pskModes {
		if pskMode == pskModeDHE {
			return true
		}
	}
	return false
}

func (hs *serverHandshakeStateTLS13) sendSessionTickets() error {
	c := hs.c

	var err error
	hs.clientFinished, err = hs.suite.finishedHash(c.in.trafficSecret, hs.transcript)
	if err != nil {
		return err
	}
	finishedMsg := &finishedMsg{
		verifyData: hs.clientFinished,
	}
	finishedMsgM, err := finishedMsg.marshal()
	if err != nil {
		return err
	}
	hs.transcript.Write(finishedMsgM)

	if !hs.shouldSendSessionTickets() {
		return nil
	}

	resumptionSecret, err := hs.suite.deriveSecret(hs.masterSecret,
		resumptionLabel, hs.transcript)
	if err != nil {
		return err
	}

	m := new(newSessionTicketMsgTLS13)

	var certsFromClient [][]byte
	for _, cert := range c.peerCertificates {
		certsFromClient = append(certsFromClient, cert.Raw)
	}
	state := sessionStateTLS13{
		cipherSuite:      hs.suite.id,
		createdAt:        uint64(c.config.time().Unix()),
		resumptionSecret: resumptionSecret,
		certificate: Certificate{
			Certificate:                 certsFromClient,
			OCSPStaple:                  c.ocspResponse,
			SignedCertificateTimestamps: c.scts,
		},
	}

	m.label, err = c.encryptTicket(state.marshal())
	if err != nil {
		return err
	}
	m.lifetime = uint32(maxSessionTicketLifetime / time.Second)

	mM, err := m.marshal()
	if err != nil {
		return err
	}
	if _, err := c.writeRecord(recordTypeHandshake, mM); err != nil {
		return err
	}

	return nil
}

func (hs *serverHandshakeStateTLS13) readClientCertificate() error {
	c := hs.c

	if !hs.requestClientCert() {
		return nil
	}

	// If we requested a client certificate, then the client must send a
	// certificate message. If it's empty, no CertificateVerify is sent.

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	certMsg, ok := msg.(*certificateMsgTLS13)
	if !ok {
		_ = c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(certMsg, msg)
	}
	certMsgM, err := certMsg.marshal()
	if err != nil {
		return err
	}
	hs.transcript.Write(certMsgM)

	if err := c.processCertsFromClient(certMsg.certificate); err != nil {
		return err
	}

	if len(certMsg.certificate.Certificate) != 0 {
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
			return errors.New("tls: client certificate used with invalid signature algorithm")
		}
		sigType, sigHash, err := typeAndHashFromSignatureScheme(certVerify.signatureAlgorithm)
		if err != nil {
			return c.sendAlert(alertInternalError)
		}
		if sigType == signaturePKCS1v15 || sigHash == cryptofix.SHA1 {
			_ = c.sendAlert(alertIllegalParameter)
			return errors.New("tls: client certificate used with invalid signature algorithm")
		}
		signed, err := signedMessage(sigHash, clientSignatureContext, hs.transcript)
		if err != nil {
			return err
		}
		if err := verifyHandshakeSignature(sigType, c.peerCertificates[0].PublicKey,
			sigHash, signed, certVerify.signature); err != nil {
			_ = c.sendAlert(alertDecryptError)
			return errors.New("tls: invalid signature by the client certificate: " + err.Error())
		}
		certVerifyM, err := certVerify.marshal()
		if err != nil {
			return err
		}
		hs.transcript.Write(certVerifyM)
	}

	// If we waited until the client certificates to send session tickets, we
	// are ready to do it now.
	if err := hs.sendSessionTickets(); err != nil {
		return err
	}

	return nil
}

func (hs *serverHandshakeStateTLS13) readClientFinished() error {
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

	if !hmac.Equal(hs.clientFinished, finished.verifyData) {
		_ = c.sendAlert(alertDecryptError)
		return errors.New("tls: invalid client finished hash")
	}

	err = c.in.setTrafficSecret(hs.suite, hs.trafficSecret)
	if err != nil {
		return err
	}

	return nil
}
