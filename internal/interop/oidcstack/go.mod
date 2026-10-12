module github.com/hyperscale-stack/security/internal/interop/oidcstack

go 1.26.5

replace github.com/hyperscale-stack/security => ../../../

replace github.com/hyperscale-stack/security/oidc/client => ../../../oidc/client

replace github.com/hyperscale-stack/security/oidc/client/store/sql => ../../../oidc/client/store/sql

replace github.com/hyperscale-stack/security/oidc/client/store/redis => ../../../oidc/client/store/redis

require (
	github.com/go-sql-driver/mysql v1.10.1
	github.com/hyperscale-stack/security/oidc/client v0.0.0-00010101000000-000000000000
	github.com/hyperscale-stack/security/oidc/client/store/redis v0.0.0-00010101000000-000000000000
	github.com/hyperscale-stack/security/oidc/client/store/sql v0.0.0-00010101000000-000000000000
	github.com/jackc/pgx/v5 v5.11.0
	github.com/redis/go-redis/v9 v9.22.0
	github.com/stretchr/testify v1.12.1
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-jose/go-jose/v4 v4.1.5 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/hyperscale-stack/security v0.0.0-00010101000000-000000000000 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel v1.46.0 // indirect
	go.opentelemetry.io/otel/metric v1.46.0 // indirect
	go.opentelemetry.io/otel/trace v1.46.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)
