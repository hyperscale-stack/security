module github.com/hyperscale-stack/security/basic

go 1.26

require (
	github.com/hyperscale-stack/security v0.0.0-00010101000000-000000000000
	github.com/hyperscale-stack/security/password v0.0.0-00010101000000-000000000000
	github.com/stretchr/testify v1.12.1
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel v1.46.0 // indirect
	go.opentelemetry.io/otel/metric v1.46.0 // indirect
	go.opentelemetry.io/otel/trace v1.46.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

replace github.com/hyperscale-stack/security => ../

replace github.com/hyperscale-stack/security/password => ../password
