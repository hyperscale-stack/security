module github.com/hyperscale-stack/security/internal/interop/oidcrp

go 1.27.3

require (
	github.com/chromedp/cdproto v0.157.9
	github.com/chromedp/chromedp v0.20.1
	github.com/hyperscale-stack/security v0.0.0-00010101000000-000000000000
	github.com/hyperscale-stack/security/oidc/client v0.0.0-00010101000000-000000000000
	github.com/stretchr/testify v1.12.1
	github.com/zitadel/oidc/v3 v3.51.16
)

require (
	github.com/bmatcuk/doublestar/v4 v4.10.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-chi/chi/v5 v5.5.0 // indirect
	github.com/go-jose/go-jose/v4 v4.1.6 // indirect
	github.com/go-json-experiment/json v0.0.0-20260623181947-01eb4420fa68 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/securecookie v1.1.2 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/muhlemmer/gu v0.3.1 // indirect
	github.com/muhlemmer/httpforwarded v0.1.0 // indirect
	github.com/rogpeppe/go-internal v1.15.0 // indirect
	github.com/rs/cors v1.11.1 // indirect
	github.com/zitadel/schema v1.3.2 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel v1.47.0 // indirect
	go.opentelemetry.io/otel/log v1.47.0 // indirect
	go.opentelemetry.io/otel/metric v1.47.0 // indirect
	go.opentelemetry.io/otel/trace v1.47.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/oauth2 v0.37.0 // indirect
	golang.org/x/text v0.43.0 // indirect
)

replace github.com/hyperscale-stack/security => ../../../

replace github.com/hyperscale-stack/security/oidc/client => ../../../oidc/client
