// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient

import (
	"context"
	"fmt"
	"time"
	"unicode/utf8"
)

// ResponseMode is how the authorization response reaches the callback.
type ResponseMode string

const (
	// ResponseModeQuery returns the response in the query of a GET to the
	// redirect URI — the default for the code flow (OAuth 2.0 Multiple
	// Response Type Encoding Practices §2.1); response_mode is not sent.
	ResponseModeQuery ResponseMode = "query"
	// ResponseModeFormPost returns the response as a form auto-submitted
	// by the user agent in a POST to the redirect URI (OAuth 2.0 Form Post
	// Response Mode §2): the code stays out of URLs, browser history and
	// Referer headers.
	ResponseModeFormPost ResponseMode = "form_post"
)

// NoMaxAge is the Transaction.MaxAge of a request that sent no max_age.
const NoMaxAge int64 = -1

// Bounds of the Transaction fields (and of the configuration and options
// they come from).
const (
	hashHexLength      = 64
	maxConnectionIDLen = 255
	maxURILength       = 2048
	maxClientIDLength  = 2048
	maxACRValuesLength = 2048
	maxAppStateLength  = 4096
	maxMaxAge          = 1<<31 - 1
)

// Transaction is one pending login: the state of an authorization request
// that the callback consumes once. It holds no secret: it is keyed by a
// hash of the state, the browser binding is stored as a keyed hash, and
// the nonce and PKCE verifier are re-derived at the callback from the
// binding secret the user agent presents, so reading the store yields
// nothing that completes a login.
//
// Integrity, a MAC keyed by the binding secret, makes every field
// tamper-evident: Complete refuses a transaction altered in the store
// (ErrTransactionIntegrity). It protects a login against whoever does not
// hold its binding secret. The user agent that started the login holds
// it, though: an attacker who can write to the store can still relax the
// max_age and acr_values checks of logins it runs itself, with its own
// browser. When step-up authentication matters, protect the store's
// integrity (authentication, network isolation), as its availability.
//
// CreatedAt and ExpiresAt are whole seconds; stores return them in UTC.
type Transaction struct {
	// StateHash is hex(SHA-256(state)): 64 lowercase hex digits.
	StateHash string
	// BindingHash is hex(HMAC-SHA256(binding secret, label)): 64 lowercase
	// hex digits.
	BindingHash string
	// ConnectionID, Issuer, ClientID, RedirectURI and ResponseMode are the
	// Client's at Begin; Complete refuses a transaction whose values are not
	// its own.
	ConnectionID string
	Issuer       string
	ClientID     string
	RedirectURI  string
	ResponseMode ResponseMode
	// MaxAge is the max_age sent, in seconds, or NoMaxAge.
	MaxAge int64
	// ACRValues is the space-separated acr_values sent, or "".
	ACRValues string
	// AppState is the application's opaque state, returned in Identity.
	AppState string
	// CreatedAt is when Begin created the transaction.
	CreatedAt time.Time
	// ExpiresAt is when the transaction stops being usable.
	ExpiresAt time.Time
	// Integrity is hex(HMAC-SHA256(k, every other field, length-prefixed)),
	// k an HMAC-SHA256 of the binding secret under its own label: 64
	// lowercase hex digits.
	Integrity string
}

// Validate reports whether t is a transaction a store may persist. Stores
// call it before any I/O and refuse what it refuses. It requires: hashes
// and Integrity of 64 lowercase hex digits; a ConnectionID of 1 to 255 visible ASCII
// characters; an Issuer and a RedirectURI of 1 to 2048 visible ASCII
// characters; a ClientID of 1 to 2048 printable ASCII characters; a
// supported ResponseMode; a MaxAge between NoMaxAge and 2^31-1; ACRValues of
// at most 2048 printable ASCII characters; an AppState of at most 4096 bytes
// of UTF-8; CreatedAt and ExpiresAt set, whole seconds, ExpiresAt after
// CreatedAt. Every error matches ErrInvalidTransaction.
func (t *Transaction) Validate() error {
	if t == nil {
		return fmt.Errorf("%w: nil transaction", ErrInvalidTransaction)
	}

	if !isLowerHex(t.StateHash, hashHexLength) || !isLowerHex(t.BindingHash, hashHexLength) ||
		!isLowerHex(t.Integrity, hashHexLength) {
		return fmt.Errorf("%w: hashes and integrity must be 64 lowercase hex digits", ErrInvalidTransaction)
	}

	if err := t.validateBindings(); err != nil {
		return err
	}

	return t.validateTimes()
}

// validateBindings checks the values Complete compares with its Client's
// and the values it carries for the ID Token checks.
func (t *Transaction) validateBindings() error {
	switch {
	case !isASCII(t.ConnectionID, visibleASCII, maxConnectionIDLen):
		return fmt.Errorf("%w: connection ID", ErrInvalidTransaction)
	case !isASCII(t.Issuer, visibleASCII, maxURILength):
		return fmt.Errorf("%w: issuer", ErrInvalidTransaction)
	case !isASCII(t.ClientID, printableASCII, maxClientIDLength):
		return fmt.Errorf("%w: client ID", ErrInvalidTransaction)
	case !isASCII(t.RedirectURI, visibleASCII, maxURILength):
		return fmt.Errorf("%w: redirect URI", ErrInvalidTransaction)
	case t.ResponseMode != ResponseModeQuery && t.ResponseMode != ResponseModeFormPost:
		return fmt.Errorf("%w: response mode", ErrInvalidTransaction)
	case t.MaxAge < NoMaxAge || t.MaxAge > maxMaxAge:
		return fmt.Errorf("%w: max age", ErrInvalidTransaction)
	case t.ACRValues != "" && !isASCII(t.ACRValues, printableASCII, maxACRValuesLength):
		return fmt.Errorf("%w: acr values", ErrInvalidTransaction)
	case len(t.AppState) > maxAppStateLength || !utf8.ValidString(t.AppState):
		return fmt.Errorf("%w: app state", ErrInvalidTransaction)
	}

	return nil
}

func (t *Transaction) validateTimes() error {
	switch {
	case t.CreatedAt.IsZero() || t.ExpiresAt.IsZero():
		return fmt.Errorf("%w: missing timestamps", ErrInvalidTransaction)
	case t.CreatedAt.Nanosecond() != 0 || t.ExpiresAt.Nanosecond() != 0:
		return fmt.Errorf("%w: timestamps must be whole seconds", ErrInvalidTransaction)
	case !t.ExpiresAt.After(t.CreatedAt):
		return fmt.Errorf("%w: expires before it is created", ErrInvalidTransaction)
	}

	return nil
}

// TransactionStore persists pending logins. An implementation MUST be safe
// for concurrent use and shared by every instance that may serve the
// callback. Two operations make the protocol guarantees:
//
//   - Save never overwrites: a StateHash already stored fails with
//     ErrTransactionExists and leaves the stored transaction intact.
//   - Consume removes a transaction atomically: at most one caller ever
//     receives it, even under concurrency and across instances.
//
// Both refuse, before any I/O, what Transaction.Validate refuses, with an
// error matching ErrInvalidTransaction.
type TransactionStore interface {
	// Save persists tx under tx.StateHash.
	Save(ctx context.Context, tx *Transaction) error

	// Consume atomically removes and returns the transaction stored under
	// stateHash. It decides in this order:
	//
	//   - none stored (never saved, or already consumed) →
	//     ErrTransactionNotFound;
	//   - expired (now is not before ExpiresAt) → ErrTransactionNotFound,
	//     whatever the binding; the store may delete it;
	//   - BindingHash different from bindingHash → ErrBindingMismatch, and
	//     the transaction stays stored: a leaked state alone cannot burn a
	//     login;
	//   - otherwise the transaction, removed so that every later or
	//     concurrent call gets ErrTransactionNotFound.
	//
	// A backend failure returns another error, which the caller treats as
	// a failed login.
	Consume(ctx context.Context, stateHash, bindingHash string, now time.Time) (*Transaction, error)
}
