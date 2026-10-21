// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/hyperscale-stack/security/saml/sp/storage/memory"
	"github.com/stretchr/testify/require"
)

// Throwaway test keys, generated at run time: nothing secret is committed.

// t0 is the fixed instant of every test clock.
var t0 = time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC)

// testTransactionKeys are the transaction keys of the tests (a constant:
// nothing secret, and transactions survive a new ServiceProvider).
var testTransactionKeys = [][]byte{[]byte("samlsp test transaction key, 32+ bytes, test only")}

// keyPair is a test key with a self-signed certificate valid around t0.
type keyPair struct {
	signer crypto.Signer
	cert   *x509.Certificate
}

// testKeys holds the generated keys of the package's tests.
type testKeys struct {
	idpA, idpB, attacker, sp, spNext keyPair
	idpEC                            keyPair
	weakRSA                          keyPair // 1024 bits: below the policy
	expired                          keyPair // certificate expired before t0
}

var (
	keysOnce sync.Once
	keysVal  *testKeys
)

// keys returns the shared test keys, generating them once.
func keys(t testing.TB) *testKeys {
	t.Helper()

	keysOnce.Do(func() {
		keysVal = &testKeys{
			idpA:     newRSAPair(2048, "idp-a", t0.Add(-24*time.Hour), t0.Add(365*24*time.Hour)),
			idpB:     newRSAPair(2048, "idp-b", t0.Add(-24*time.Hour), t0.Add(365*24*time.Hour)),
			attacker: newRSAPair(2048, "attacker", t0.Add(-24*time.Hour), t0.Add(365*24*time.Hour)),
			sp:       newRSAPair(2048, "sp", t0.Add(-24*time.Hour), t0.Add(365*24*time.Hour)),
			spNext:   newRSAPair(2048, "sp-next", t0.Add(-24*time.Hour), t0.Add(365*24*time.Hour)),
			idpEC:    newECPair("idp-ec", t0.Add(-24*time.Hour), t0.Add(365*24*time.Hour)),
			weakRSA:  newRSAPair(1024, "weak", t0.Add(-24*time.Hour), t0.Add(365*24*time.Hour)),
			expired:  newRSAPair(2048, "expired", t0.Add(-48*time.Hour), t0.Add(-24*time.Hour)),
		}
	})

	return keysVal
}

func newRSAPair(bits int, cn string, notBefore, notAfter time.Time) keyPair {
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}

	return keyPair{signer: k, cert: selfSigned(k, cn, notBefore, notAfter)}
}

func newECPair(cn string, notBefore, notAfter time.Time) keyPair {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	return keyPair{signer: k, cert: selfSigned(k, cn, notBefore, notAfter)}
}

var serial atomic.Int64

func selfSigned(k crypto.Signer, cn string, notBefore, notAfter time.Time) *x509.Certificate {
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial.Add(1)),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, k.Public(), k)
	if err != nil {
		panic(err)
	}

	c, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}

	return c
}

// Test endpoints of connection "acme".
const (
	connID     = "acme"
	spEntityID = "https://sp.example.com/saml/acme"
	acsURL     = "https://sp.example.com/saml/acme/acs"
	acsPath    = "/saml/acme/acs"
	idpEntity  = "https://idp.example.com/acme"
	ssoURL     = "https://idp.example.com/sso?tenant=acme"
)

// newConnection returns a valid connection "acme" trusting idpA.
func newConnection(t testing.TB) *samlsp.Connection {
	t.Helper()

	return &samlsp.Connection{
		ID:         connID,
		SPEntityID: spEntityID,
		ACSURL:     acsURL,
		IdentityProvider: samlsp.IdentityProvider{
			EntityID:            idpEntity,
			SSOURL:              ssoURL,
			SigningCertificates: []*x509.Certificate{keys(t).idpA.cert},
		},
	}
}

// resolver is a concurrency-safe in-memory ConnectionResolver whose
// connections can be replaced during a test.
type resolver struct {
	mu    sync.Mutex
	conns map[string]*samlsp.Connection
	err   error
}

func newResolver(conns ...*samlsp.Connection) *resolver {
	r := &resolver{conns: map[string]*samlsp.Connection{}}
	for _, c := range conns {
		r.conns[c.ID] = c
	}

	return r
}

func (r *resolver) ResolveConnection(_ context.Context, id string) (*samlsp.Connection, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.err != nil {
		return nil, r.err
	}

	c, ok := r.conns[id]
	if !ok {
		return nil, samlsp.ErrUnknownConnection
	}

	cp := *c

	return &cp, nil
}

func (r *resolver) set(c *samlsp.Connection) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.conns[c.ID] = c
}

func (r *resolver) remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.conns, id)
}

// clock is a settable test clock.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock() *clock { return &clock{now: t0} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *clock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = t
}

// newMemoryStore returns the memory store of a test, sweeping its expired
// records on the test's clock. Every test store is built here: with the
// store's default clock, time.Now, the records the tests write around t0 —
// in the past — would be swept once 64 writes have happened.
func newMemoryStore(now func() time.Time) *memory.Store {
	return memory.New(memory.WithClock(now))
}

// atT0 is a clock stopped at t0, for a store built before its test env.
func atT0() time.Time { return t0 }

// env is a ready ServiceProvider over a memory store.
type env struct {
	sp       *samlsp.ServiceProvider
	store    *memory.Store
	resolver *resolver
	clock    *clock
	conn     *samlsp.Connection
}

// envOption customizes newEnv.
type envOption func(*samlsp.Config, *samlsp.Connection)

// newEnv builds a ServiceProvider with connection "acme" trusting idpA.
func newEnv(t testing.TB, opts ...envOption) *env {
	t.Helper()

	conn := newConnection(t)
	res := newResolver()
	clk := newClock()
	store := newMemoryStore(clk.Now)

	cfg := samlsp.Config{
		Connections:     res,
		Transactions:    store,
		ReplayCache:     store,
		TransactionKeys: testTransactionKeys,
		Now:             clk.Now,
	}

	for _, o := range opts {
		o(&cfg, conn)
	}

	res.set(conn)

	sp, err := samlsp.New(cfg)
	require.NoError(t, err)

	return &env{sp: sp, store: store, resolver: res, clock: clk, conn: conn}
}

// withSigningKey configures the SP signing key.
func withSigningKey(t testing.TB) envOption {
	return func(c *samlsp.Config, _ *samlsp.Connection) {
		c.SigningKey = keys(t).sp.signer
		c.SigningCertificate = keys(t).sp.cert
	}
}
