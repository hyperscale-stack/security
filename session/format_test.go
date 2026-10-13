// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// randomKey returns a fresh 32-byte key from crypto/rand.
func randomKey(t *testing.T) []byte {
	t.Helper()

	k := make([]byte, 32)
	_, err := rand.Read(k)
	require.NoError(t, err)

	return k
}

// v2Cookie seals plaintext the way the documented cookie format v2 does,
// independently of the package: AES-256-GCM under
// HKDF-SHA256(key, salt=∅, info=label), associated data
// version ‖ len16(name) ‖ name ‖ len16(purpose) ‖ purpose, value
// base64url(version ‖ nonce ‖ ciphertext‖tag).
func v2Cookie(t *testing.T, key []byte, version byte, adVersion byte, name, purpose string, plaintext []byte) string {
	t.Helper()

	derived, err := hkdf.Key(sha256.New, key, nil, "github.com/hyperscale-stack/security/session v2 AES-256-GCM", 32)
	require.NoError(t, err)

	block, err := aes.NewCipher(derived)
	require.NoError(t, err)

	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)

	ad := []byte{adVersion}
	ad = binary.BigEndian.AppendUint16(ad, uint16(len(name))) //nolint:gosec // test sizes
	ad = append(ad, name...)
	ad = binary.BigEndian.AppendUint16(ad, uint16(len(purpose))) //nolint:gosec // test sizes
	ad = append(ad, purpose...)

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	out := append([]byte{version}, nonce...)
	out = gcm.Seal(out, nonce, plaintext, ad)

	return base64.RawURLEncoding.EncodeToString(out)
}

// samplePayload is a v2 payload for sub alice, valid for an hour at now.
func samplePayload(t *testing.T, now time.Time) []byte {
	t.Helper()

	b, err := json.Marshal(map[string]any{
		"id": "sid-1", "v": map[string]any{"sub": "alice"}, "csrf": "csrf-1",
		"c": now, "a": now, "e": now.Add(time.Hour),
	})
	require.NoError(t, err)

	return b
}

// managerWithKeys builds a Manager on a fixed clock with the given keys.
func managerWithKeys(t *testing.T, now *time.Time, keys [][]byte, opts ...session.Option) *session.Manager {
	t.Helper()

	codec, err := session.NewCodec(keys...)
	require.NoError(t, err)

	return session.NewManager(codec, append([]session.Option{session.WithClock(func() time.Time { return *now })}, opts...)...)
}

// getWithCookie reads the session a browser presenting name=value carries.
func getWithCookie(mgr *session.Manager, name, value string) (*session.Session, error) {
	c := newCarrier()
	c.cookies[name] = value

	return mgr.Get(context.Background(), c)
}

// Audit CORE-04 (probe TestZZAuditSessionEmptyKeyForgery): NewCodec accepted
// an empty key — an unset environment variable — and derived the AES key
// with SHA-256, so anyone could mint a cookie for any subject; a passphrase
// ("changeme") could be brute-forced from one cookie. Decision 10: keys of
// at least 32 random bytes; a key that repeats one byte (a buffer never
// filled) is refused too.
func TestNewCodecRefusesShortKeys(t *testing.T) {
	t.Parallel()

	for name, keys := range map[string][][]byte{
		"no key":                 nil,
		"nil key":                {nil},
		"empty key":              {{}},
		"31 bytes":               {bytes.Repeat([]byte{7, 8}, 16)[:31]},
		"passphrase":             {[]byte("changeme")},
		"valid then short":       {randomKey(t), []byte("previous-key")},
		"32 zero bytes":          {make([]byte, 32)},
		"64 times the same byte": {bytes.Repeat([]byte{0x5a}, 64)},
	} {
		codec, err := session.NewCodec(keys...)

		require.ErrorIs(t, err, session.ErrInvalidKeys, name)
		assert.Nil(t, codec, name)
		assert.NotContains(t, err.Error(), "changeme", "the error never quotes a key")
	}

	assert.Equal(t, 32, session.MinKeySize)
}

func TestNewCodecAcceptsLongRandomKeys(t *testing.T) {
	t.Parallel()

	long := make([]byte, 64)
	_, err := rand.Read(long)
	require.NoError(t, err)

	for _, keys := range [][][]byte{{randomKey(t)}, {long}, {randomKey(t), randomKey(t)}} {
		codec, err := session.NewCodec(keys...)
		require.NoError(t, err)
		assert.NotNil(t, codec)
	}
}

// The documented cookie format v2 is pinned both ways: a cookie built from
// the documentation opens, and a cookie the Manager writes decodes with the
// documentation.
func TestCookieFormatV2(t *testing.T) {
	t.Parallel()

	key := randomKey(t)
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	mgr := managerWithKeys(t, &now, [][]byte{key})
	name := mgr.CookieName()

	s, err := getWithCookie(mgr, name, v2Cookie(t, key, 2, 2, name, "", samplePayload(t, now)))
	require.NoError(t, err)
	assert.Equal(t, "alice", s.GetString("sub"))
	assert.Equal(t, "sid-1", s.ID)
	assert.Equal(t, "csrf-1", s.CSRFToken)

	// The other way round: open a Manager cookie with the documented recipe.
	c := newCarrier()
	_, err = mgr.Login(context.Background(), c, principal{sub: "bob"})
	require.NoError(t, err)

	raw, err := base64.RawURLEncoding.DecodeString(c.replay().cookies[name])
	require.NoError(t, err)
	require.Equal(t, byte(2), raw[0], "version byte in clear")

	derived, err := hkdf.Key(sha256.New, key, nil, "github.com/hyperscale-stack/security/session v2 AES-256-GCM", 32)
	require.NoError(t, err)

	block, err := aes.NewCipher(derived)
	require.NoError(t, err)

	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)

	ad := []byte{2}
	ad = binary.BigEndian.AppendUint16(ad, uint16(len(name))) //nolint:gosec // test sizes
	ad = append(ad, name...)
	ad = binary.BigEndian.AppendUint16(ad, 0)

	plaintext, err := gcm.Open(nil, raw[1:13], raw[13:], ad)
	require.NoError(t, err)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(plaintext, &payload))
	assert.ElementsMatch(t, []string{"id", "v", "csrf", "c", "a", "e"}, keys(payload))
	assert.Equal(t, map[string]any{"sub": "bob"}, payload["v"])
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}

	return out
}

// Audit CORE-09 (probe TestZZAuditSessionNoAADBinding): without associated
// data, a cookie minted by the manager "shop_session" opened under
// "admin_session", and a value sealed by the same Codec for another purpose
// opened as a session. Decision 10: AD = version ‖ cookie name ‖ purpose.
func TestManagerBindsCookiesToTheirName(t *testing.T) {
	t.Parallel()

	key := randomKey(t)
	now := time.Now()
	shop := managerWithKeys(t, &now, [][]byte{key}, session.WithCookieName("shop_session"))
	admin := managerWithKeys(t, &now, [][]byte{key}, session.WithCookieName("admin_session"))

	c := newCarrier()
	_, err := shop.Login(context.Background(), c, principal{sub: "bob"})
	require.NoError(t, err)

	value := c.replay().cookies["shop_session"]

	_, err = getWithCookie(admin, "admin_session", value)
	require.ErrorIs(t, err, session.ErrNoSession)
	require.ErrorIs(t, err, session.ErrDecode)

	s, err := getWithCookie(shop, "shop_session", value)
	require.NoError(t, err, "control: the right manager opens it")
	assert.Equal(t, "bob", s.GetString("sub"))
}

func TestManagerBindsCookiesToTheirPurpose(t *testing.T) {
	t.Parallel()

	key := randomKey(t)
	now := time.Now()

	login := func(mgr *session.Manager) string {
		c := newCarrier()
		_, err := mgr.Login(context.Background(), c, principal{sub: "bob"})
		require.NoError(t, err)

		return c.replay().cookies[mgr.CookieName()]
	}

	appA := managerWithKeys(t, &now, [][]byte{key}, session.WithPurpose("app-a"))
	appB := managerWithKeys(t, &now, [][]byte{key}, session.WithPurpose("app-b"))
	noPurpose := managerWithKeys(t, &now, [][]byte{key})

	value := login(appA)

	for name, mgr := range map[string]*session.Manager{"other purpose": appB, "no purpose": noPurpose} {
		_, err := getWithCookie(mgr, mgr.CookieName(), value)
		require.ErrorIs(t, err, session.ErrNoSession, name)
	}

	_, err := getWithCookie(appA, appA.CookieName(), value)
	require.NoError(t, err, "control: the same purpose opens it")

	_, err = getWithCookie(appA, appA.CookieName(), login(noPurpose))
	require.ErrorIs(t, err, session.ErrNoSession, "and the other way round")
}

// The associated data is length-prefixed: shifting a byte from the cookie
// name to the purpose changes it.
func TestAssociatedDataIsUnambiguous(t *testing.T) {
	t.Parallel()

	key := randomKey(t)
	now := time.Now()
	a := managerWithKeys(t, &now, [][]byte{key}, session.WithCookieName("session"), session.WithPurpose("x"))
	b := managerWithKeys(t, &now, [][]byte{key}, session.WithCookieName("sessionx"))

	c := newCarrier()
	_, err := a.Login(context.Background(), c, principal{sub: "bob"})
	require.NoError(t, err)

	_, err = getWithCookie(b, "sessionx", c.replay().cookies["session"])
	require.ErrorIs(t, err, session.ErrNoSession)

	c = newCarrier()
	_, err = b.Login(context.Background(), c, principal{sub: "bob"})
	require.NoError(t, err)

	_, err = getWithCookie(a, "session", c.replay().cookies["sessionx"])
	require.ErrorIs(t, err, session.ErrNoSession)
}

func TestWithPurposeRefusesLongPurposes(t *testing.T) {
	t.Parallel()

	assert.Panics(t, func() { session.WithPurpose(string(bytes.Repeat([]byte("p"), 256))) })
	assert.NotPanics(t, func() { session.WithPurpose(string(bytes.Repeat([]byte("p"), 255))) })
}

// Decision 10: the cookies of the previous format — AES-256-GCM under
// SHA-256(key), no version, no associated data — no longer open: every
// user signs in once again.
func TestManagerRefusesV1Cookies(t *testing.T) {
	t.Parallel()

	key := randomKey(t)
	now := time.Now()
	mgr := managerWithKeys(t, &now, [][]byte{key})

	sum := sha256.Sum256(key)
	block, err := aes.NewCipher(sum[:])
	require.NoError(t, err)

	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)

	plaintext, err := json.Marshal(map[string]any{
		"ID": "sid", "Values": map[string]any{"sub": "alice"}, "CSRFToken": "x",
		"CreatedAt": now, "LastAccessed": now, "ExpiresAt": now.Add(time.Hour),
	})
	require.NoError(t, err)

	for range 32 { // the first byte of a v1 cookie is a random nonce byte: try many
		nonce := make([]byte, gcm.NonceSize())
		_, err = rand.Read(nonce)
		require.NoError(t, err)

		v1 := base64.RawURLEncoding.EncodeToString(gcm.Seal(nonce, nonce, plaintext, nil))

		_, err = getWithCookie(mgr, mgr.CookieName(), v1)
		require.ErrorIs(t, err, session.ErrNoSession)
	}
}

func TestManagerRefusesOtherFormatVersions(t *testing.T) {
	t.Parallel()

	key := randomKey(t)
	now := time.Now()
	mgr := managerWithKeys(t, &now, [][]byte{key})
	payload := samplePayload(t, now)
	cookie := mgr.CookieName()

	for name, value := range map[string]string{
		"version 3 everywhere":         v2Cookie(t, key, 3, 3, cookie, "", payload),
		"version 2 bound to version 3": v2Cookie(t, key, 2, 3, cookie, "", payload),
		"version 3 bound to version 2": v2Cookie(t, key, 3, 2, cookie, "", payload),
	} {
		_, err := getWithCookie(mgr, cookie, value)
		require.ErrorIs(t, err, session.ErrNoSession, name)
	}

	_, err := getWithCookie(mgr, cookie, v2Cookie(t, key, 2, 2, cookie, "", payload))
	require.NoError(t, err, "control")
}

// Audit §9 surviving mutant: the codec ignored JSON errors.
func TestManagerRefusesAnUndecodablePayload(t *testing.T) {
	t.Parallel()

	key := randomKey(t)
	now := time.Now()
	mgr := managerWithKeys(t, &now, [][]byte{key})

	for _, plaintext := range []string{"not json", `{"id":`, `[]`, `{"v":"not an object"}`} {
		_, err := getWithCookie(mgr, mgr.CookieName(), v2Cookie(t, key, 2, 2, mgr.CookieName(), "", []byte(plaintext)))
		require.ErrorIs(t, err, session.ErrNoSession, plaintext)
		require.ErrorIs(t, err, session.ErrDecode, plaintext)
	}
}

// Review nit 11: key rotation in the v2 format. A cookie sealed with the old
// key opens while the old key is kept after the new one, is refused once it
// is dropped, and is re-sealed with the new key by Touch and Rotate.
func TestKeyRotation(t *testing.T) {
	t.Parallel()

	oldKey, newKey := randomKey(t), randomKey(t)
	now := time.Now()
	before := managerWithKeys(t, &now, [][]byte{oldKey})
	during := managerWithKeys(t, &now, [][]byte{newKey, oldKey})
	after := managerWithKeys(t, &now, [][]byte{newKey})

	c := newCarrier()
	_, err := before.Login(context.Background(), c, principal{sub: "alice"})
	require.NoError(t, err)

	old := c.replay()

	_, err = after.Get(context.Background(), old)
	require.ErrorIs(t, err, session.ErrNoSession, "dropped key")

	s, err := during.Get(context.Background(), old)
	require.NoError(t, err)

	touched := newCarrier()
	require.NoError(t, during.Touch(context.Background(), touched, s))

	got, err := after.Get(context.Background(), touched.replay())
	require.NoError(t, err, "Touch re-sealed the cookie with the active key")
	assert.Equal(t, "alice", got.GetString("sub"))

	rotating := newCarrier()
	rotating.cookies = old.cookies

	_, err = during.Rotate(context.Background(), rotating)
	require.NoError(t, err)

	_, err = after.Get(context.Background(), rotating.replay())
	require.NoError(t, err, "Rotate re-sealed the cookie with the active key")
}

// The cookie value is bounded before it is decoded: a hostile megabyte of
// base64 costs no allocation. (Not parallel: it reads the process-wide
// allocation counter.)
func TestManagerBoundsTheCookieBeforeDecoding(t *testing.T) {
	now := time.Now()
	mgr := managerWithKeys(t, &now, [][]byte{testKey})
	huge := strings.Repeat("AAAA", 1<<18) // 1 MiB of valid base64url

	var before, after runtime.MemStats

	runtime.ReadMemStats(&before)

	_, err := getWithCookie(mgr, mgr.CookieName(), huge)

	runtime.ReadMemStats(&after)

	require.ErrorIs(t, err, session.ErrNoSession)
	assert.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(64<<10), "the cookie must be refused before being decoded")
}
