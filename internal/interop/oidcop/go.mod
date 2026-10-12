module github.com/hyperscale-stack/security/internal/interop/oidcop

go 1.26.0

require (
	github.com/coreos/go-oidc/v3 v3.21.0
	github.com/hyperscale-stack/security/jwt v0.0.0-00010101000000-000000000000
	github.com/hyperscale-stack/security/oauth2 v0.0.0-00010101000000-000000000000
	github.com/hyperscale-stack/security/oidc/provider v0.0.0-00010101000000-000000000000
	github.com/stretchr/testify v1.12.1
	golang.org/x/oauth2 v0.37.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-jose/go-jose/v4 v4.1.5 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/hyperscale-stack/security v0.0.0-00010101000000-000000000000 // indirect
	github.com/hyperscale-stack/security/bearer v0.0.0-00010101000000-000000000000 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel v1.46.0 // indirect
	go.opentelemetry.io/otel/metric v1.46.0 // indirect
	go.opentelemetry.io/otel/trace v1.46.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
)

replace github.com/hyperscale-stack/security => ../../../

replace github.com/hyperscale-stack/security/bearer => ../../../bearer

replace github.com/hyperscale-stack/security/jwt => ../../../jwt

replace github.com/hyperscale-stack/security/oauth2 => ../../../oauth2

replace github.com/hyperscale-stack/security/oidc/provider => ../../../oidc/provider
