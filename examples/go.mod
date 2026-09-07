module github.com/hyperscale-stack/security/examples

go 1.26.0

// Examples may depend on every other module of the workspace.
replace github.com/hyperscale-stack/security => ../

replace github.com/hyperscale-stack/security/http => ../http

replace github.com/hyperscale-stack/security/grpc => ../grpc

replace github.com/hyperscale-stack/security/connectrpc => ../connectrpc

replace github.com/hyperscale-stack/security/basic => ../basic

replace github.com/hyperscale-stack/security/bearer => ../bearer

replace github.com/hyperscale-stack/security/password => ../password

replace github.com/hyperscale-stack/security/jwt => ../jwt

replace github.com/hyperscale-stack/security/session => ../session

replace github.com/hyperscale-stack/security/oauth2 => ../oauth2

require (
	connectrpc.com/connect v1.20.0
	connectrpc.com/grpchealth v1.5.0
	github.com/hyperscale-stack/security v0.0.0-00010101000000-000000000000
	github.com/hyperscale-stack/security/basic v0.0.0-00010101000000-000000000000
	github.com/hyperscale-stack/security/bearer v0.0.0-00010101000000-000000000000
	github.com/hyperscale-stack/security/connectrpc v0.0.0-00010101000000-000000000000
	github.com/hyperscale-stack/security/grpc v0.0.0-00010101000000-000000000000
	github.com/hyperscale-stack/security/http v0.0.0-00010101000000-000000000000
	github.com/hyperscale-stack/security/jwt v0.0.0-00010101000000-000000000000
	github.com/hyperscale-stack/security/oauth2 v0.0.0-00010101000000-000000000000
	github.com/hyperscale-stack/security/password v0.0.0-00010101000000-000000000000
	github.com/hyperscale-stack/security/session v0.0.0-00010101000000-000000000000
	github.com/stretchr/testify v1.12.1
	google.golang.org/grpc v1.83.2
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel v1.46.0 // indirect
	go.opentelemetry.io/otel/metric v1.46.0 // indirect
	go.opentelemetry.io/otel/trace v1.46.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.56.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
