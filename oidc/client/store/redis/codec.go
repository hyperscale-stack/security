// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package redisstore

import (
	"encoding/json"
	"fmt"
	"time"

	oidcclient "github.com/hyperscale-stack/security/oidc/client"
)

// transactionDTO is the JSON payload of a transaction key. The state hash
// is the key itself. Timestamps are Unix seconds. The consume script reads
// binding_hash, expires_at and consumed_by through cjson and re-encodes
// the payload it consumes: cjson may escape "/" as "\/" and prints numbers
// with 14 significant digits — every value here has at most 10 — so Go
// decodes the re-encoded payload unchanged.
type transactionDTO struct {
	BindingHash  string `json:"binding_hash"`
	ConnectionID string `json:"connection_id"`
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	RedirectURI  string `json:"redirect_uri"`
	ResponseMode string `json:"response_mode"`
	MaxAge       int64  `json:"max_age"`
	ACRValues    string `json:"acr_values"`
	AppState     string `json:"app_state"`
	CreatedAt    int64  `json:"created_at"`
	ExpiresAt    int64  `json:"expires_at"`
	Integrity    string `json:"integrity"`
	// ConsumedBy is only written by the consume script: the nonce of the
	// call that consumed the transaction.
	ConsumedBy string `json:"consumed_by,omitempty"`
}

// encodeTransaction returns the payload of tx. A struct of strings and
// integers always marshals: the error is impossible.
func encodeTransaction(tx *oidcclient.Transaction) []byte {
	b, _ := json.Marshal(transactionDTO{
		BindingHash:  tx.BindingHash,
		ConnectionID: tx.ConnectionID,
		Issuer:       tx.Issuer,
		ClientID:     tx.ClientID,
		RedirectURI:  tx.RedirectURI,
		ResponseMode: string(tx.ResponseMode),
		MaxAge:       tx.MaxAge,
		ACRValues:    tx.ACRValues,
		AppState:     tx.AppState,
		CreatedAt:    tx.CreatedAt.Unix(),
		ExpiresAt:    tx.ExpiresAt.Unix(),
		Integrity:    tx.Integrity,
	})

	return b
}

func decodeTransaction(stateHash string, raw []byte) (*oidcclient.Transaction, error) {
	var d transactionDTO
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("redisstore: decode transaction: %w", err)
	}

	return &oidcclient.Transaction{
		StateHash:    stateHash,
		BindingHash:  d.BindingHash,
		ConnectionID: d.ConnectionID,
		Issuer:       d.Issuer,
		ClientID:     d.ClientID,
		RedirectURI:  d.RedirectURI,
		ResponseMode: oidcclient.ResponseMode(d.ResponseMode),
		MaxAge:       d.MaxAge,
		ACRValues:    d.ACRValues,
		AppState:     d.AppState,
		CreatedAt:    time.Unix(d.CreatedAt, 0).UTC(),
		ExpiresAt:    time.Unix(d.ExpiresAt, 0).UTC(),
		Integrity:    d.Integrity,
	}, nil
}
