// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// randomBytes is the entropy of request IDs, RelayState handles and
// browser-binding values: 256 bits, beyond the 160 bits Core §1.3.4
// recommends for identifiers.
const randomBytes = 32

// handleLen is the length of a base64url-encoded random value.
const handleLen = 43

// newRequestID returns an xs:ID-compatible AuthnRequest ID ("_" + 64 hex).
func newRequestID() string {
	return "_" + hex.EncodeToString(random())
}

// newHandle returns a random base64url value (RelayState handle or
// browser-binding cookie).
func newHandle() string {
	return base64.RawURLEncoding.EncodeToString(random())
}

// random returns randomBytes bytes from crypto/rand, which never fails
// (Go 1.24+: Read always fills the buffer or crashes the program).
func random() []byte {
	b := make([]byte, randomBytes)
	_, _ = rand.Read(b)

	return b
}

// isHandle reports whether s has the shape of newHandle's output.
func isHandle(s string) bool {
	if len(s) != handleLen {
		return false
	}

	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}

	return true
}

// digest is the domain-separated SHA-256 of the parts, joined by NUL bytes
// (no part can contain NUL: connection IDs are visible ASCII, handles are
// base64url, and XML forbids NUL in entity and assertion IDs).
func digest(parts ...string) string {
	h := sha256.New()

	for i, p := range parts {
		if i > 0 {
			_, _ = h.Write([]byte{0})
		}

		_, _ = h.Write([]byte(p))
	}

	return hex.EncodeToString(h.Sum(nil))
}

// transactionID derives the store key of a transaction from its connection
// and RelayState handle: a handle presented at another connection's ACS
// finds nothing.
func transactionID(connectionID, handle string) string {
	return digest("samlsp-v1/transaction", connectionID, handle)
}

// bindingHash derives the stored form of a browser-binding cookie value.
func bindingHash(cookie string) string {
	return digest("samlsp-v1/binding", cookie)
}

// replayKey derives the replay-cache key of an assertion accepted at a
// connection: assertion IDs are unique per issuer (Profiles §4.1.4.5), and
// the key is scoped by the connection, because an issuer is a claim of the
// connection: a connection whose IdP claims another tenant's entity ID
// must not share that tenant's replay namespace. Scoping loses nothing:
// Audience, Recipient and InResponseTo bind an assertion to one transaction
// of one connection.
func replayKey(connectionID, issuer, assertionID string) string {
	return digest("samlsp-v2/assertion", connectionID, issuer, assertionID)
}

// payloadVersion is the version of the transaction payload encoding.
const payloadVersion = 1

// transaction is the decoded payload of a TransactionRecord: what the SP
// asked for and must find again in the response.
type transaction struct {
	Version      int      `json:"v"`
	RequestID    string   `json:"req"`
	ConnectionID string   `json:"conn"`
	IdP          string   `json:"idp"`
	SP           string   `json:"sp"`
	ACS          string   `json:"acs"`
	IssuedAt     int64    `json:"iat"`
	NameIDFormat string   `json:"nidf,omitempty"`
	ForceAuthn   bool     `json:"fa,omitempty"`
	IsPassive    bool     `json:"ip,omitempty"`
	AuthnContext []string `json:"ac,omitempty"`
	AppState     string   `json:"app,omitempty"`
}

var errCorruptTransaction = errors.New("samlsp: corrupt transaction payload")

// encode renders the payload. Marshaling cannot fail: the struct only
// holds strings, integers and booleans.
func (t *transaction) encode() string {
	b, _ := json.Marshal(t)

	return string(b)
}

// decodeTransaction parses a payload written by encode.
func decodeTransaction(payload string) (*transaction, error) {
	var t transaction
	if err := json.Unmarshal([]byte(payload), &t); err != nil || t.Version != payloadVersion || t.RequestID == "" {
		return nil, errCorruptTransaction
	}

	return &t, nil
}

// issuedAt returns the AuthnRequest IssueInstant of the transaction.
func (t *transaction) issuedAt() time.Time {
	return time.Unix(t.IssuedAt, 0).UTC()
}
