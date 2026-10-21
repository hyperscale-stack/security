// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package redisstore_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"testing"

	redisstore "github.com/hyperscale-stack/security/oauth2/store/redis"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewRefusesShardedClients: the scripts touch several keys — a token,
// its family, its replacement — that a Redis Cluster puts in different hash
// slots (CROSSSLOT) and a Ring on different shards (a token found only when
// it shares its family's shard): New refuses both clients, without I/O.
func TestNewRefusesShardedClients(t *testing.T) {
	t.Parallel()

	cluster := redis.NewClusterClient(&redis.ClusterOptions{Addrs: []string{"127.0.0.1:1"}})
	t.Cleanup(func() { _ = cluster.Close() })

	ring := redis.NewRing(&redis.RingOptions{Addrs: map[string]string{"a": "127.0.0.1:1", "b": "127.0.0.1:2"}})
	t.Cleanup(func() { _ = ring.Close() })

	for name, client := range map[string]redis.UniversalClient{"cluster": cluster, "ring": ring} {
		store, err := redisstore.New(client)
		require.ErrorIs(t, err, redisstore.ErrDeploymentRequirement, name)
		assert.Nil(t, store, name)
	}

	// A standalone or Sentinel (failover) client is a *redis.Client.
	failover := redis.NewFailoverClient(&redis.FailoverOptions{MasterName: "m", SentinelAddrs: []string{"127.0.0.1:1"}})
	t.Cleanup(func() { _ = failover.Close() })

	_, err := redisstore.New(failover)
	require.NoError(t, err)
}

// infoHook answers INFO from canned sections, or with err, without
// reaching a server: the INFO fields miniredis does not report.
type infoHook struct {
	sections map[string]string
	err      error
}

func (h infoHook) DialHook(next redis.DialHook) redis.DialHook { return next }

func (h infoHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func (h infoHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if cmd.Name() != "info" {
			return next(ctx, cmd)
		}

		info, ok := cmd.(*redis.StringCmd)
		if !ok {
			return next(ctx, cmd)
		}

		if h.err != nil {
			info.SetErr(h.err)

			return h.err
		}

		section, _ := cmd.Args()[1].(string)
		info.SetVal(h.sections[section])

		return nil
	}
}

// infoStore returns a store whose INFO replies are sections.
func infoStore(t *testing.T, sections map[string]string, err error) *redisstore.Store {
	t.Helper()

	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	client.AddHook(infoHook{sections: sections, err: err})
	t.Cleanup(func() { _ = client.Close() })

	store, nerr := redisstore.New(client)
	require.NoError(t, nerr)

	return store
}

// compliantInfo returns the INFO sections of a compliant server: Redis
// version, the noeviction policy, no cluster mode.
func compliantInfo(version, policy, cluster string) map[string]string {
	return map[string]string{
		"server":  "# Server\r\nredis_version:" + version + "\r\nredis_mode:standalone\r\n",
		"memory":  "# Memory\r\nused_memory:1000\r\nmaxmemory:0\r\nmaxmemory_policy:" + policy + "\r\n",
		"cluster": "# Cluster\r\ncluster_enabled:" + cluster + "\r\n",
	}
}

// TestCheckDeployment checks the INFO fields against the requirements:
// Redis 6.0 or later, maxmemory-policy noeviction, no cluster mode; every
// requirement not met is reported, each matching ErrDeploymentRequirement.
func TestCheckDeployment(t *testing.T) {
	t.Parallel()

	for _, version := range []string{"6.0.0", "6.2.14", "7.2.4", "7.4.11", "10.0.1", "8.0.0-rc1", "7"} {
		require.NoError(t, infoStore(t, compliantInfo(version, "noeviction", "0"), nil).CheckDeployment(t.Context()), version)
	}

	for name, c := range map[string]struct {
		sections map[string]string
		want     []string
	}{
		"Redis 5":      {compliantInfo("5.0.14", "noeviction", "0"), []string{"Redis 5.0.14 is older than 6.0"}},
		"Redis 4.0":    {compliantInfo("4.0.0", "noeviction", "0"), []string{"Redis 4.0.0 is older than 6.0"}},
		"no version":   {compliantInfo("unknown", "noeviction", "0"), []string{"redis_version unknown is not a version"}},
		"no major":     {compliantInfo(".5", "noeviction", "0"), []string{"redis_version .5 is not a version"}},
		"allkeys-lru":  {compliantInfo("7.4.11", "allkeys-lru", "0"), []string{"maxmemory_policy is allkeys-lru, not noeviction"}},
		"volatile-lru": {compliantInfo("7.4.11", "volatile-lru", "0"), []string{"maxmemory_policy is volatile-lru, not noeviction"}},
		"cluster":      {compliantInfo("7.4.11", "noeviction", "1"), []string{"cluster_enabled is 1"}},
		"all three": {compliantInfo("5.0.14", "volatile-ttl", "1"), []string{
			"older than 6.0", "maxmemory_policy is volatile-ttl", "cluster_enabled is 1",
		}},
		"not reported": {map[string]string{"server": "# Server\r\n", "memory": "", "cluster": "# Cluster\r\n"}, []string{
			"redis_version not reported", "maxmemory_policy not reported", "cluster_enabled not reported",
		}},
	} {
		err := infoStore(t, c.sections, nil).CheckDeployment(t.Context())
		require.ErrorIs(t, err, redisstore.ErrDeploymentRequirement, name)

		for _, want := range c.want {
			assert.Contains(t, err.Error(), want, name)
		}
	}
}

// TestCheckDeploymentReturnsBackendErrors: when INFO fails — a user
// without +info gets NOPERM, a server reports no such section — the error
// is the backend's, not a requirement found unmet.
func TestCheckDeploymentReturnsBackendErrors(t *testing.T) {
	t.Parallel()

	noperm := errors.New("NOPERM User app has no permissions to run the 'info' command")

	err := infoStore(t, nil, noperm).CheckDeployment(t.Context())
	require.ErrorIs(t, err, noperm)
	require.NotErrorIs(t, err, redisstore.ErrDeploymentRequirement)

	// miniredis answers INFO for its clients and stats sections only.
	store, ok := newRedisStore(t).(*redisstore.Store)
	require.True(t, ok)

	err = store.CheckDeployment(t.Context())
	require.Error(t, err)
	require.NotErrorIs(t, err, redisstore.ErrDeploymentRequirement)
}

// TestCheckDeploymentRealServer runs the check on a real server
// (OAUTH2_TEST_REDIS_ADDR), which meets the requirements, and as a
// least-privilege ACL user without +info, which gets NOPERM.
func TestCheckDeploymentRealServer(t *testing.T) {
	addr := os.Getenv(envRedisAddr)
	if addr == "" {
		t.Skipf("set %s to run against a real Redis (opt-in)", envRedisAddr)
	}

	ctx := context.Background()
	admin := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() { _ = admin.Close() })

	store, err := redisstore.New(admin)
	require.NoError(t, err)
	require.NoError(t, store.CheckDeployment(ctx))

	b := make([]byte, 8)
	_, _ = rand.Read(b)
	user, password := "oauth2-check-"+hex.EncodeToString(b), hex.EncodeToString(b)

	require.NoError(t, admin.Do(ctx, "ACL", "SETUSER", user, "on", ">"+password, "~oauth2:*",
		"+@read", "+@write", "+@scripting", "+@connection").Err())
	t.Cleanup(func() { _ = admin.Do(context.Background(), "ACL", "DELUSER", user).Err() })

	limited := redis.NewClient(&redis.Options{Addr: addr, Username: user, Password: password})
	t.Cleanup(func() { _ = limited.Close() })

	store, err = redisstore.New(limited)
	require.NoError(t, err)

	err = store.CheckDeployment(ctx)
	require.Error(t, err)
	require.NotErrorIs(t, err, redisstore.ErrDeploymentRequirement)
	require.Contains(t, err.Error(), "NOPERM")
}
