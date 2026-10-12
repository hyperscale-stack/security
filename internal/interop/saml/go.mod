module github.com/hyperscale-stack/security/internal/interop/saml

go 1.26.0

replace github.com/hyperscale-stack/security/saml/sp => ../../../saml/sp

replace github.com/hyperscale-stack/security => ../../../

require (
	github.com/crewjam/saml v0.5.1
	github.com/hyperscale-stack/security/saml/sp v0.0.0-00010101000000-000000000000
	github.com/stretchr/testify v1.12.1
)

require (
	github.com/beevik/etree v1.8.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/hyperscale-stack/security v0.0.0-00010101000000-000000000000 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	github.com/russellhaering/gosaml2 v0.12.0 // indirect
	github.com/russellhaering/goxmldsig v1.6.1 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel v1.46.0 // indirect
	go.opentelemetry.io/otel/metric v1.46.0 // indirect
	go.opentelemetry.io/otel/trace v1.46.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.56.0 // indirect
)
