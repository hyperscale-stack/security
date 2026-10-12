// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp

import (
	"bytes"
	"context"
	"fmt"
)

// ServiceProvider is the SAML Service Provider. It is safe for concurrent
// use and keeps no per-request state: transactions and consumed assertions
// live in the configured stores, so any number of instances can serve the
// same users. Build one with [New].
type ServiceProvider struct {
	cfg Config
	// metadataCerts are the DER certificates published with use="signing":
	// the signing certificate first, then the additional ones.
	metadataCerts [][]byte
}

// New validates cfg, applies the defaults and returns a [ServiceProvider].
// It fails with an error matching [ErrInvalidConfig].
func New(cfg Config) (*ServiceProvider, error) {
	cfg = cfg.withDefaults()

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	// The ServiceProvider never shares key bytes with its caller.
	keys := make([][]byte, len(cfg.TransactionKeys))
	for i, key := range cfg.TransactionKeys {
		keys[i] = bytes.Clone(key)
	}

	cfg.TransactionKeys = keys

	sp := &ServiceProvider{cfg: cfg}

	if cfg.SigningCertificate != nil {
		sp.metadataCerts = append(sp.metadataCerts, cfg.SigningCertificate.Raw)

		for _, c := range cfg.AdditionalSigningCertificates {
			sp.metadataCerts = append(sp.metadataCerts, c.Raw)
		}
	}

	return sp, nil
}

// resolve returns the validated connection id. A malformed ID is an unknown
// connection; a resolver error is returned wrapped (ErrUnknownConnection
// stays matchable); a resolver answering with another connection, or with
// an invalid one, yields ErrInvalidConnection.
func (sp *ServiceProvider) resolve(ctx context.Context, id string) (*Connection, error) {
	if validateConnectionID(id) != nil {
		return nil, ErrUnknownConnection
	}

	conn, err := sp.cfg.Connections.ResolveConnection(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("samlsp: resolve connection: %w", err)
	}

	if conn == nil {
		return nil, ErrUnknownConnection
	}

	if conn.ID != id {
		return nil, fmt.Errorf("%w: resolver returned another connection", ErrInvalidConnection)
	}

	if err := conn.Validate(); err != nil {
		return nil, err
	}

	return conn, nil
}
