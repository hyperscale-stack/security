// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package redisstore is a Redis implementation of samlsp.Storage: the login
// transactions of a SAML Service Provider and its assertion replay cache,
// shared by every instance of a deployment. Atomicity comes from Lua
// scripts (EVALSHA with EVAL fallback): a script runs without interleaving
// other commands.
//
// # Key layout
//
// Every key starts with the store prefix (WithKeyPrefix, "samlsp:" by
// default):
//
//   - tx:{id}: a transaction, as a hash with the fields b (binding digest),
//     p (opaque payload), e (expiry, Unix seconds), i (integrity MAC), n
//     (the nonce of the saving call) and, once consumed, c (the nonce of the
//     consuming call). The key expires at the transaction expiry
//     (PEXPIREAT: the Redis clock decides).
//   - as:{key}: a consumed assertion, holding the nonce of the recording
//     call, until its retention expiry.
//
// Every script touches a single key, so Redis Cluster is supported. Values
// are never re-encoded by the scripts (no cjson round trip).
//
// go-redis may resend a command whose reply was lost: each script records
// the calling nonce, so a resent save, consumption or replay mark is
// recognized as its own success rather than reported as a duplicate. Any
// other call is: a second save of an existing transaction, even with
// identical content, returns samlsp.ErrTransactionExists.
//
// # Deployment requirements
//
//   - Every instance uses the same Redis deployment and reads from its
//     primary: no replica reads, no client-side caching.
//   - maxmemory-policy noeviction. Every key carries a TTL, so volatile-*
//     policies may evict it: an evicted transaction fails closed (unknown
//     transaction); an evicted replay entry leaves the transaction's
//     single-use consumption as the replay defense.
//   - Durability is the server's: a consumption acknowledged by a primary
//     that fails before persisting or replicating it can be lost in a
//     failover. Choose the persistence settings accordingly.
//   - Clocks of the SP instances and of Redis should be synchronized: the
//     expiries are absolute instants.
//   - Give the SP an ACL limited to its key prefix: each transaction
//     carries a MAC under samlsp.Config.TransactionKeys, so Redis is trusted
//     for availability and single consumption only. A transaction saved
//     before the MAC existed (no field i) fails its login once.
//
// Allowed dependencies:
//   - github.com/hyperscale-stack/security/saml/sp
//   - github.com/redis/go-redis/v9
//   - stdlib only
package redisstore
