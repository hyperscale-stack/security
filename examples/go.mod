module github.com/hyperscale-stack/security/examples

go 1.26

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
	connectrpc.com/grpchealth v1.4.0
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
	github.com/stretchr/testify v1.11.1
	google.golang.org/grpc v1.81.1
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel v1.44.0 // indirect
	go.opentelemetry.io/otel/metric v1.44.0 // indirect
	go.opentelemetry.io/otel/trace v1.44.0 // indirect
	golang.org/x/crypto v0.53.0 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.38.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260226221140-a57be14db171 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
