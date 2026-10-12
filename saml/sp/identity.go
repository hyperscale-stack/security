// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp

import "time"

// Identity is the verified identity asserted by an IdP. Every field comes
// from the signed assertion, except ConnectionID (the connection whose keys
// verified it).
//
// The IdP entity ID is a configured property of the connection, not an
// authenticated identity across connections: two connections may claim the
// same Issuer. External-identity keys MUST therefore include ConnectionID.
// For a persistent NameID the stable key is (ConnectionID, Issuer,
// NameQualifier or Issuer when empty, SPNameQualifier or Audience when
// empty, NameID.Value) (Core §8.3.7, errata E78). Transient NameIDs (Core
// §8.3.8), email addresses and other attributes are not stable keys: never
// link or create accounts from them alone, and never auto-link by email.
type Identity struct {
	// ConnectionID is the connection that verified the assertion.
	ConnectionID string

	// Issuer is the IdP entity ID (the assertion Issuer).
	Issuer string

	// Audience is the SP entity ID the assertion was issued for.
	Audience string

	// NameID is the subject identifier, exactly as asserted.
	NameID NameID

	// Attributes are the AttributeStatement attributes, in document order.
	Attributes []Attribute

	// SessionIndex is the AuthnStatement SessionIndex ("" when absent).
	SessionIndex string

	// AuthnInstant is when the IdP authenticated the user.
	AuthnInstant time.Time

	// SessionNotOnOrAfter, when not zero, bounds the application session
	// derived from this login (Profiles §4.1.4.3).
	SessionNotOnOrAfter time.Time

	// AuthnContextClassRef is the authentication context class ("" when
	// absent).
	AuthnContextClassRef string

	// AssertionID is the ID of the assertion (for audit logs).
	AssertionID string

	// ProxyRestriction, when not nil, is the assertion's ProxyRestriction
	// condition (Core §2.5.1.6). An application that issues assertions or
	// tokens of its own on the basis of this login (an identity broker)
	// MUST honor it: a Count of zero forbids issuing any to another party.
	ProxyRestriction *ProxyRestriction
}

// NameID is the asserted subject identifier (Core §2.2.3), preserved
// exactly: no trimming, no case folding.
type NameID struct {
	// Value is the identifier.
	Value string
	// Format is the NameID format URI ("" when absent, meaning unspecified).
	Format string
	// NameQualifier is the qualifying IdP namespace ("" when absent).
	NameQualifier string
	// SPNameQualifier is the qualifying SP namespace ("" when absent).
	SPNameQualifier string
}

// Attribute is one SAML attribute (Core §2.7.3.1). NameID-valued values
// (eduPersonTargetedID) are rendered as their NameID value; other complex
// values as their character data.
type Attribute struct {
	Name         string
	NameFormat   string
	FriendlyName string
	Values       []string
}

// ProxyRestriction is the ProxyRestriction condition (Core §2.5.1.6).
type ProxyRestriction struct {
	// Count is the maximum number of indirections; nil when the condition
	// sets none.
	Count *int
	// Audiences are the parties new assertions may be issued to (none means
	// unrestricted).
	Audiences []string
}

// AttributeValues returns the values of every attribute named name, in
// document order, whatever its NameFormat. It returns nil when there is
// none.
func (id *Identity) AttributeValues(name string) []string {
	var values []string

	for _, a := range id.Attributes {
		if a.Name == name {
			values = append(values, a.Values...)
		}
	}

	return values
}
