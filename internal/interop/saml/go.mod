module github.com/hyperscale-stack/security/internal/interop/saml

go 1.26.5

replace github.com/hyperscale-stack/security/saml/sp => ../../../saml/sp

replace github.com/hyperscale-stack/security => ../../../

require (
	github.com/alicebob/miniredis/v2 v2.39.0
	github.com/crewjam/saml v0.5.1
	github.com/go-sql-driver/mysql v1.10.1
	github.com/hyperscale-stack/security v0.0.0-00010101000000-000000000000
	github.com/hyperscale-stack/security/saml/sp v0.0.0-00010101000000-000000000000
	github.com/jackc/pgx/v5 v5.11.0
	github.com/redis/go-redis/v9 v9.23.0
	github.com/stretchr/testify v1.12.1
	modernc.org/sqlite v1.60.1
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/yuin/gopher-lua v1.1.1 // indirect
	go.opentelemetry.io/otel/log v1.47.0 // indirect
	go.uber.org/atomic v1.12.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	modernc.org/libc v1.77.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)

require (
	github.com/beevik/etree v1.8.1
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/hyperscale-stack/security/saml/sp/store/redis v0.0.0-00010101000000-000000000000
	github.com/hyperscale-stack/security/saml/sp/store/sql v0.0.0-00010101000000-000000000000
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	github.com/russellhaering/gosaml2 v0.12.0 // indirect
	github.com/russellhaering/goxmldsig v1.6.1 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel v1.47.0 // indirect
	go.opentelemetry.io/otel/metric v1.47.0 // indirect
	go.opentelemetry.io/otel/trace v1.47.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.58.0 // indirect
)

replace github.com/hyperscale-stack/security/saml/sp/store/sql => ../../../saml/sp/store/sql

replace github.com/hyperscale-stack/security/saml/sp/store/redis => ../../../saml/sp/store/redis
