module github.com/elastic/opentelemetry-lib

go 1.22.7

require (
	github.com/elastic/go-elasticsearch/v8 v8.17.0
	github.com/elastic/opentelemetry-lib/common v0.1.0
	github.com/elastic/opentelemetry-lib/elasticattributes v0.0.0
	github.com/google/go-cmp v0.6.0
	github.com/open-telemetry/opentelemetry-collector-contrib/pkg/golden v0.117.0
	github.com/open-telemetry/opentelemetry-collector-contrib/pkg/pdatatest v0.117.0
	github.com/stretchr/testify v1.10.0
	go.opentelemetry.io/collector/pdata v1.23.0
	go.opentelemetry.io/collector/semconv v0.117.0
	go.opentelemetry.io/proto/otlp v1.5.0
	go.uber.org/zap v1.27.0
	google.golang.org/grpc v1.69.4
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/elastic/elastic-transport-go/v8 v8.6.0 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/open-telemetry/opentelemetry-collector-contrib/pkg/pdatautil v0.117.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	go.opentelemetry.io/otel v1.31.0 // indirect
	go.opentelemetry.io/otel/metric v1.31.0 // indirect
	go.opentelemetry.io/otel/trace v1.31.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/net v0.33.0 // indirect
	golang.org/x/sys v0.29.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250102185135-69823020774d // indirect
	google.golang.org/protobuf v1.36.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/elastic/opentelemetry-lib/elasticattributes => ./elasticattributes
