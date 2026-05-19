module github.com/hyperscale-stack/security/oauth2/storage/memory

go 1.25.0

require github.com/hyperscale-stack/security/oauth2 v0.0.0-00010101000000-000000000000

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/hyperscale-stack/security v0.0.0-00010101000000-000000000000 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel v1.43.0 // indirect
	go.opentelemetry.io/otel/metric v1.43.0 // indirect
	go.opentelemetry.io/otel/trace v1.43.0 // indirect
)

replace github.com/hyperscale-stack/security/oauth2 => ../../

replace github.com/hyperscale-stack/security => ../../../
