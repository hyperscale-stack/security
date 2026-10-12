// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package redisstore is a Redis implementation of
// oidcclient.TransactionStore, the store of pending OpenID Connect logins,
// for deployments whose instances share a Redis server. The single
// consumption of a transaction rests on a Lua script.
//
// # Key layout
//
// One key per transaction, {prefix}tx:{state hash} (WithKeyPrefix,
// "oidcclient:" by default), holding a JSON payload and expiring with the
// transaction; a consumed transaction stays, flagged, until then. The
// payload holds no secret: the browser binding is a keyed hash, and the
// nonce and PKCE verifier are derived from the binding secret only the
// user agent holds. Reading the keys yields nothing that completes a
// login; rewriting them can only make logins fail.
//
// # Deployment requirements
//
// The single-consumption guarantee holds under these conditions:
//
//   - Redis 6.0 or later: the consume script writes with SET … KEEPTTL,
//     which an older server refuses — failing closed.
//   - A standalone server, the primary of a Sentinel deployment, or Redis
//     Cluster: every command and script touches a single key.
//   - Every command reaches the primary: no replica reads, and no
//     client-side caching on the store's client.
//   - Durability is the server's: a consumption acknowledged by a primary
//     that fails before replicating or persisting it can be lost in a
//     failover, making the transaction consumable once more. Single use
//     then rests on the provider, which redeems an authorization code once,
//     and on the binding secret, which only the user agent of the login
//     holds.
//
// Eviction only ever fails logins: an evicted transaction is not found.
//
// Allowed dependencies:
//   - github.com/hyperscale-stack/security/oidc/client
//   - github.com/redis/go-redis/v9
//   - stdlib only
package redisstore
