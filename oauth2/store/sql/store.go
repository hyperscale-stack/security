// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
)

// Store is a database/sql-backed [oauth2.Storage]. Atomicity of the
// single-use operations (ConsumeAuthorizationCode, RotateRefreshToken) is
// guaranteed by transactions plus affected-row checks — no SELECT…FOR
// UPDATE is needed because the winning DELETE / UPDATE is the one that
// reports RowsAffected()==1.
type Store struct {
	db      *sql.DB
	dialect Dialect
}

// New returns a [Store] bound to db using the given [Dialect]. The
// caller owns db's lifecycle. Call [Store.Migrate] once at boot (or run
// the DDL from [Schema] through a migration tool).
func New(db *sql.DB, dialect Dialect) (*Store, error) {
	if db == nil {
		return nil, errors.New("sqlstore: New: nil *sql.DB")
	}

	if dialect == nil {
		return nil, errors.New("sqlstore: New: nil Dialect")
	}

	return &Store{db: db, dialect: dialect}, nil
}

// exec runs a non-query statement, rebinding placeholders for the dialect.
func (s *Store) exec(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return s.db.ExecContext(ctx, s.dialect.rebind(q), args...) //nolint:wrapcheck // wrapped by callers
}

// --- authorization codes -------------------------------------------------

// SaveAuthorizationCode implements [oauth2.AuthorizationCodeStore].
func (s *Store) SaveAuthorizationCode(ctx context.Context, code *oauth2.AuthorizationCode) error {
	if code.CodeHash == "" {
		return oauth2.ErrInvalidRequest.WithDescription("sqlstore: empty code hash")
	}

	const q = `INSERT INTO oauth2_auth_codes
		(code_hash, client_id, subject, redirect_uri, scope,
		 code_challenge, code_challenge_method, nonce, issued_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.exec(ctx, q,
		code.CodeHash, code.ClientID, code.Subject, code.RedirectURI, code.Scope,
		code.CodeChallenge, code.CodeChallengeMethod, code.Nonce,
		code.IssuedAt.Unix(), code.ExpiresAt.Unix())
	if err != nil {
		return fmt.Errorf("sqlstore: save authorization code: %w", err)
	}

	return nil
}

// ConsumeAuthorizationCode implements [oauth2.AuthorizationCodeStore]. The
// SELECT + DELETE run in one transaction; the DELETE's RowsAffected()
// decides the winner when two callers race, so the operation is atomic
// without SELECT…FOR UPDATE.
func (s *Store) ConsumeAuthorizationCode(ctx context.Context, codeHash string) (*oauth2.AuthorizationCode, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: begin: %w", err)
	}

	defer func() { _ = tx.Rollback() }()

	const sel = `SELECT client_id, subject, redirect_uri, scope,
		code_challenge, code_challenge_method, nonce, issued_at, expires_at
		FROM oauth2_auth_codes WHERE code_hash = ?`

	var (
		code              = &oauth2.AuthorizationCode{CodeHash: codeHash}
		issuedAt, expires int64
	)

	row := tx.QueryRowContext(ctx, s.dialect.rebind(sel), codeHash)
	if err := row.Scan(
		&code.ClientID, &code.Subject, &code.RedirectURI, &code.Scope,
		&code.CodeChallenge, &code.CodeChallengeMethod, &code.Nonce,
		&issuedAt, &expires,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, oauth2.ErrCodeAlreadyUsed
		}

		return nil, fmt.Errorf("sqlstore: select authorization code: %w", err)
	}

	res, err := tx.ExecContext(ctx, s.dialect.rebind(
		`DELETE FROM oauth2_auth_codes WHERE code_hash = ?`), codeHash)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: delete authorization code: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("sqlstore: rows affected: %w", err)
	}

	if affected != 1 {
		// A concurrent transaction consumed the code first.
		return nil, oauth2.ErrCodeAlreadyUsed
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("sqlstore: commit: %w", err)
	}

	code.IssuedAt = time.Unix(issuedAt, 0)
	code.ExpiresAt = time.Unix(expires, 0)

	return code, nil
}

// --- access tokens -------------------------------------------------------

// SaveAccessToken implements [oauth2.AccessTokenStore].
func (s *Store) SaveAccessToken(ctx context.Context, t *oauth2.AccessToken) error {
	if t.TokenHash == "" {
		return oauth2.ErrInvalidRequest.WithDescription("sqlstore: empty access token hash")
	}

	const q = `INSERT INTO oauth2_access_tokens
		(token_hash, client_id, subject, scope, family_id, audience, issued_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.exec(ctx, q,
		t.TokenHash, t.ClientID, t.Subject, t.Scope, t.FamilyID, t.Audience,
		t.IssuedAt.Unix(), t.ExpiresAt.Unix())
	if err != nil {
		return fmt.Errorf("sqlstore: save access token: %w", err)
	}

	return nil
}

// LookupAccessToken implements [oauth2.AccessTokenStore].
func (s *Store) LookupAccessToken(ctx context.Context, tokenHash string) (*oauth2.AccessToken, error) {
	const q = `SELECT client_id, subject, scope, family_id, audience, issued_at, expires_at
		FROM oauth2_access_tokens WHERE token_hash = ?`

	var (
		t                 = &oauth2.AccessToken{TokenHash: tokenHash}
		issuedAt, expires int64
	)

	row := s.db.QueryRowContext(ctx, s.dialect.rebind(q), tokenHash)
	if err := row.Scan(&t.ClientID, &t.Subject, &t.Scope, &t.FamilyID, &t.Audience,
		&issuedAt, &expires); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, oauth2.ErrInvalidGrant.WithDescription("access token not found")
		}

		return nil, fmt.Errorf("sqlstore: lookup access token: %w", err)
	}

	t.IssuedAt = time.Unix(issuedAt, 0)
	t.ExpiresAt = time.Unix(expires, 0)

	return t, nil
}

// RevokeAccessToken implements [oauth2.AccessTokenStore].
func (s *Store) RevokeAccessToken(ctx context.Context, tokenHash string) error {
	if _, err := s.exec(ctx, `DELETE FROM oauth2_access_tokens WHERE token_hash = ?`, tokenHash); err != nil {
		return fmt.Errorf("sqlstore: revoke access token: %w", err)
	}

	return nil
}

// --- refresh tokens ------------------------------------------------------

// SaveRefreshToken implements [oauth2.RefreshTokenStore].
func (s *Store) SaveRefreshToken(ctx context.Context, t *oauth2.RefreshToken) error {
	if t.TokenHash == "" {
		return oauth2.ErrInvalidRequest.WithDescription("sqlstore: empty refresh token hash")
	}

	const q = `INSERT INTO oauth2_refresh_tokens
		(token_hash, client_id, subject, scope, family_id, consumed, issued_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.exec(ctx, q,
		t.TokenHash, t.ClientID, t.Subject, t.Scope, t.FamilyID, boolToInt(t.Consumed),
		t.IssuedAt.Unix(), t.ExpiresAt.Unix())
	if err != nil {
		return fmt.Errorf("sqlstore: save refresh token: %w", err)
	}

	return nil
}

// LookupRefreshToken implements [oauth2.RefreshTokenStore].
func (s *Store) LookupRefreshToken(ctx context.Context, tokenHash string) (*oauth2.RefreshToken, error) {
	const q = `SELECT client_id, subject, scope, family_id, consumed, issued_at, expires_at
		FROM oauth2_refresh_tokens WHERE token_hash = ?`

	t, err := scanRefresh(s.db.QueryRowContext(ctx, s.dialect.rebind(q), tokenHash), tokenHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, oauth2.ErrInvalidGrant.WithDescription("refresh token not found")
		}

		return nil, fmt.Errorf("sqlstore: lookup refresh token: %w", err)
	}

	return t, nil
}

// RotateRefreshToken implements [oauth2.RefreshTokenStore]. The whole
// sequence runs in one transaction:
//
//  1. UPDATE the old token to consumed=1 WHERE consumed=0. The
//     RowsAffected()==1 check is the atomic gate — a concurrent rotation
//     that already flipped the row gets 0.
//  2. On 0 rows, the token was reused: revoke the family and return
//     ErrRefreshTokenReused.
//  3. On 1 row, INSERT the new token and commit.
func (s *Store) RotateRefreshToken(ctx context.Context, oldHash string, next *oauth2.RefreshToken) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlstore: begin: %w", err)
	}

	defer func() { _ = tx.Rollback() }()

	// Fetch family id (needed for the reuse-revocation path).
	var familyID string

	famRow := tx.QueryRowContext(ctx, s.dialect.rebind(
		`SELECT family_id FROM oauth2_refresh_tokens WHERE token_hash = ?`), oldHash)
	if err := famRow.Scan(&familyID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return oauth2.ErrInvalidGrant.WithDescription("refresh token not found")
		}

		return fmt.Errorf("sqlstore: select refresh token: %w", err)
	}

	res, err := tx.ExecContext(ctx, s.dialect.rebind(
		`UPDATE oauth2_refresh_tokens SET consumed = 1 WHERE token_hash = ? AND consumed = 0`), oldHash)
	if err != nil {
		return fmt.Errorf("sqlstore: consume refresh token: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlstore: rows affected: %w", err)
	}

	if affected != 1 {
		// Reuse: the token was already consumed. Revoke the family in a
		// separate transaction after rolling this one back.
		_ = tx.Rollback()
		_ = s.RevokeRefreshFamily(ctx, familyID)

		return oauth2.ErrRefreshTokenReused
	}

	if _, err := tx.ExecContext(ctx, s.dialect.rebind(
		`INSERT INTO oauth2_refresh_tokens
			(token_hash, client_id, subject, scope, family_id, consumed, issued_at, expires_at)
			VALUES (?, ?, ?, ?, ?, 0, ?, ?)`),
		next.TokenHash, next.ClientID, next.Subject, next.Scope, next.FamilyID,
		next.IssuedAt.Unix(), next.ExpiresAt.Unix(),
	); err != nil {
		return fmt.Errorf("sqlstore: insert rotated refresh token: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlstore: commit: %w", err)
	}

	return nil
}

// RevokeRefreshFamily implements [oauth2.RefreshTokenStore]: every refresh
// token of the family is marked consumed and every access token of the
// family is deleted.
func (s *Store) RevokeRefreshFamily(ctx context.Context, familyID string) error {
	if _, err := s.exec(ctx,
		`UPDATE oauth2_refresh_tokens SET consumed = 1 WHERE family_id = ?`, familyID); err != nil {
		return fmt.Errorf("sqlstore: revoke refresh family: %w", err)
	}

	if _, err := s.exec(ctx,
		`DELETE FROM oauth2_access_tokens WHERE family_id = ?`, familyID); err != nil {
		return fmt.Errorf("sqlstore: purge family access tokens: %w", err)
	}

	return nil
}

// rowScanner abstracts *sql.Row so scanRefresh works with QueryRow results.
type rowScanner interface {
	Scan(dest ...any) error
}

// scanRefresh decodes a refresh-token row.
func scanRefresh(row rowScanner, hash string) (*oauth2.RefreshToken, error) {
	var (
		t                 = &oauth2.RefreshToken{TokenHash: hash}
		consumed          int64
		issuedAt, expires int64
	)

	if err := row.Scan(&t.ClientID, &t.Subject, &t.Scope, &t.FamilyID,
		&consumed, &issuedAt, &expires); err != nil {
		return nil, err //nolint:wrapcheck // caller classifies sql.ErrNoRows
	}

	t.Consumed = consumed != 0
	t.IssuedAt = time.Unix(issuedAt, 0)
	t.ExpiresAt = time.Unix(expires, 0)

	return t, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}

	return 0
}

// Compile-time interface check.
var _ oauth2.Storage = (*Store)(nil)
