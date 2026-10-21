// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package redisstore

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/redis/go-redis/v9"
)

// ErrDeploymentRequirement reports a deployment requirement of the package
// documentation that the Redis client or server does not meet: [New]
// returns it for a client that spreads keys over several servers,
// [Store.CheckDeployment] for each requirement the server does not meet.
var ErrDeploymentRequirement = errors.New("redisstore: deployment requirement not met")

// shardedClient reports why rdb cannot serve the store, or nil: the
// scripts touch several keys — a token, its family, its replacement — that
// a Redis Cluster puts in different hash slots (CROSSSLOT), and a Ring on
// different shards, where a token is found only when it shares its
// family's shard.
func shardedClient(rdb redis.UniversalClient) error {
	switch rdb.(type) {
	case *redis.ClusterClient:
		return fmt.Errorf("%w: a Redis Cluster client: the scripts touch keys of several hash slots", ErrDeploymentRequirement)
	case *redis.Ring:
		return fmt.Errorf("%w: a Redis Ring client: the scripts touch keys of several shards", ErrDeploymentRequirement)
	default:
		return nil
	}
}

// infoSections are the INFO sections CheckDeployment reads, one at a time:
// several sections in one INFO need Redis 7.
var infoSections = []string{"server", "memory", "cluster"}

// CheckDeployment verifies, through INFO, the deployment requirements of
// the package documentation that the server reports:
//
//   - Redis 6.0 or later (redis_version): the scripts write with SET …
//     KEEPTTL;
//   - maxmemory-policy noeviction (maxmemory_policy): every other policy
//     may evict a family key, and a "revoked" one lost within its retention
//     lets the next issuance revive the family;
//   - no cluster mode (cluster_enabled 0).
//
// It returns every requirement not met, each matching
// [ErrDeploymentRequirement] — a field the server does not report counts
// as not met: verify that requirement by hand and skip the call. When INFO
// itself fails it returns that error, which does not match the sentinel:
// INFO is in the @dangerous ACL category, so a least-privilege user needs
// +info to run the check (NOPERM otherwise). Call it at boot, before
// serving traffic. A proxy sharding keys behind one endpoint (twemproxy, a
// non-OSS cluster policy) reports cluster_enabled 0: the scripts then fail
// at runtime, closed.
func (s *Store) CheckDeployment(ctx context.Context) error {
	fields := map[string]string{}

	for _, section := range infoSections {
		reply, err := s.rdb.Info(ctx, section).Result()
		if err != nil {
			return fmt.Errorf("redisstore: check deployment: INFO %s: %w", section, err)
		}

		parseInfo(reply, fields)
	}

	return checkInfo(fields)
}

// parseInfo adds the "field:value" lines of an INFO reply to fields.
func parseInfo(reply string, fields map[string]string) {
	for line := range strings.Lines(reply) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if field, value, ok := strings.Cut(line, ":"); ok {
			fields[field] = value
		}
	}
}

// checkInfo checks the INFO fields against the requirements and returns
// every one not met.
func checkInfo(fields map[string]string) error {
	var errs []error

	version, ok := fields["redis_version"]
	major, valid := versionMajor(version)

	switch {
	case !ok:
		errs = append(errs, notReported("redis_version"))
	case !valid:
		errs = append(errs, fmt.Errorf("%w: redis_version %s is not a version", ErrDeploymentRequirement, version))
	case major < 6:
		errs = append(errs, fmt.Errorf("%w: Redis %s is older than 6.0 (SET … KEEPTTL)", ErrDeploymentRequirement, version))
	}

	switch policy, ok := fields["maxmemory_policy"]; {
	case !ok:
		errs = append(errs, notReported("maxmemory_policy"))
	case policy != "noeviction":
		errs = append(errs, fmt.Errorf("%w: maxmemory_policy is %s, not noeviction: a revoked token family may be evicted",
			ErrDeploymentRequirement, policy))
	}

	switch cluster, ok := fields["cluster_enabled"]; {
	case !ok:
		errs = append(errs, notReported("cluster_enabled"))
	case cluster != "0":
		errs = append(errs, fmt.Errorf("%w: cluster_enabled is %s: Redis Cluster is not supported", ErrDeploymentRequirement, cluster))
	}

	return errors.Join(errs...)
}

// notReported is the requirement on field, which the server did not report.
func notReported(field string) error {
	return fmt.Errorf("%w: %s not reported by the server", ErrDeploymentRequirement, field)
}

// versionMajor returns the major number of a version — "7.2.4",
// "8.0.0-rc1" — and whether it has one.
func versionMajor(version string) (int, bool) {
	major, _, _ := strings.Cut(version, ".")
	n, err := strconv.Atoi(major)

	return n, err == nil
}
