// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package elastic

import (
	"crypto/md5"
	"encoding/hex"
	"net/http"
	"testing"
	"time"

	"github.com/elastic/opentelemetry-lib/enrichments/trace/config"
	"github.com/google/go-cmp/cmp"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/pdatatest/ptracetest"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	semconv "go.opentelemetry.io/collector/semconv/v1.25.0"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/grpc/codes"
)

// Tests the enrichment logic for elastic's transaction definition.
func TestElasticTransactionEnrich(t *testing.T) {
	now := time.Unix(3600, 0)
	expectedDuration := time.Minute
	endTs := pcommon.NewTimestampFromTime(now)
	startTs := pcommon.NewTimestampFromTime(now.Add(-1 * expectedDuration))
	getElasticTxn := func() ptrace.Span {
		span := ptrace.NewSpan()
		span.SetSpanID([8]byte{1})
		span.SetStartTimestamp(startTs)
		span.SetEndTimestamp(endTs)
		return span
	}
	for _, tc := range []struct {
		name              string
		input             ptrace.Span
		config            config.ElasticTransactionConfig
		enrichedAttrs     map[string]any
		expectedSpanLinks *ptrace.SpanLinkSlice
	}{
		{
			// test case gives a summary of what is emitted by default
			name:   "empty",
			input:  ptrace.NewSpan(),
			config: config.Enabled().Transaction,
			enrichedAttrs: map[string]any{
				AttributeTimestampUs:                    int64(0),
				AttributeTransactionSampled:             true,
				AttributeTransactionRoot:                true,
				AttributeTransactionID:                  "",
				AttributeTransactionName:                "",
				AttributeProcessorEvent:                 "transaction",
				AttributeTransactionRepresentativeCount: float64(1),
				AttributeTransactionDurationUs:          int64(0),
				AttributeEventOutcome:                   "success",
				AttributeSuccessCount:                   int64(1),
				AttributeTransactionResult:              "Success",
				AttributeTransactionType:                "unknown",
			},
		},
		{
			name:          "all_disabled",
			input:         getElasticTxn(),
			enrichedAttrs: map[string]any{},
		},
		{
			name: "with_pvalue",
			input: func() ptrace.Span {
				span := ptrace.NewSpan()
				span.TraceState().FromRaw("ot=p:8;")
				return span
			}(),
			config: config.Enabled().Transaction,
			enrichedAttrs: map[string]any{
				AttributeTimestampUs:                    int64(0),
				AttributeTransactionSampled:             true,
				AttributeTransactionRoot:                true,
				AttributeTransactionID:                  "",
				AttributeTransactionName:                "",
				AttributeProcessorEvent:                 "transaction",
				AttributeTransactionRepresentativeCount: float64(256),
				AttributeTransactionDurationUs:          int64(0),
				AttributeEventOutcome:                   "success",
				AttributeSuccessCount:                   int64(256),
				AttributeTransactionResult:              "Success",
				AttributeTransactionType:                "unknown",
			},
		},
		{
			name: "http_status_ok",
			input: func() ptrace.Span {
				span := getElasticTxn()
				span.SetName("testtxn")
				span.Attributes().PutInt(semconv.AttributeHTTPStatusCode, http.StatusOK)
				return span
			}(),
			config: config.Enabled().Transaction,
			enrichedAttrs: map[string]any{
				AttributeTimestampUs:                    startTs.AsTime().UnixMicro(),
				AttributeTransactionSampled:             true,
				AttributeTransactionRoot:                true,
				AttributeTransactionID:                  "0100000000000000",
				AttributeTransactionName:                "testtxn",
				AttributeProcessorEvent:                 "transaction",
				AttributeTransactionRepresentativeCount: float64(1),
				AttributeTransactionDurationUs:          expectedDuration.Microseconds(),
				AttributeEventOutcome:                   "success",
				AttributeSuccessCount:                   int64(1),
				AttributeTransactionResult:              "HTTP 2xx",
				AttributeTransactionType:                "request",
			},
		},
		{
			name: "http_status_1xx",
			input: func() ptrace.Span {
				span := getElasticTxn()
				span.SetName("testtxn")
				span.SetSpanID([8]byte{1})
				// attributes should be preferred over span status for txn result
				span.Status().SetCode(ptrace.StatusCodeOk)
				span.Attributes().PutInt(
					semconv.AttributeHTTPResponseStatusCode,
					http.StatusProcessing,
				)
				return span
			}(),
			config: config.Enabled().Transaction,
			enrichedAttrs: map[string]any{
				AttributeTimestampUs:                    startTs.AsTime().UnixMicro(),
				AttributeTransactionSampled:             true,
				AttributeTransactionRoot:                true,
				AttributeTransactionID:                  "0100000000000000",
				AttributeTransactionName:                "testtxn",
				AttributeProcessorEvent:                 "transaction",
				AttributeTransactionRepresentativeCount: float64(1),
				AttributeTransactionDurationUs:          expectedDuration.Microseconds(),
				AttributeEventOutcome:                   "success",
				AttributeSuccessCount:                   int64(1),
				AttributeTransactionResult:              "HTTP 1xx",
				AttributeTransactionType:                "request",
			},
		},
		{
			name: "http_status_5xx",
			input: func() ptrace.Span {
				span := getElasticTxn()
				span.SetName("testtxn")
				span.SetSpanID([8]byte{1})
				// span status code should take precedence over http status attributes
				// for setting event.outcome
				span.Status().SetCode(ptrace.StatusCodeOk)
				span.Attributes().PutInt(
					semconv.AttributeHTTPStatusCode, http.StatusInternalServerError)
				return span
			}(),
			config: config.Enabled().Transaction,
			enrichedAttrs: map[string]any{
				AttributeTimestampUs:                    startTs.AsTime().UnixMicro(),
				AttributeTransactionSampled:             true,
				AttributeTransactionRoot:                true,
				AttributeTransactionID:                  "0100000000000000",
				AttributeTransactionName:                "testtxn",
				AttributeProcessorEvent:                 "transaction",
				AttributeTransactionRepresentativeCount: float64(1),
				AttributeTransactionDurationUs:          expectedDuration.Microseconds(),
				AttributeEventOutcome:                   "success",
				AttributeSuccessCount:                   int64(1),
				AttributeTransactionResult:              "HTTP 5xx",
				AttributeTransactionType:                "request",
			},
		},
		{
			name: "grpc_status_ok",
			input: func() ptrace.Span {
				span := getElasticTxn()
				span.SetName("testtxn")
				span.SetSpanID([8]byte{1})
				// attributes should be preferred over span status for txn result
				span.Status().SetCode(ptrace.StatusCodeOk)
				span.Attributes().PutInt(
					semconv.AttributeRPCGRPCStatusCode,
					int64(codes.OK),
				)
				return span
			}(),
			config: config.Enabled().Transaction,
			enrichedAttrs: map[string]any{
				AttributeTimestampUs:                    startTs.AsTime().UnixMicro(),
				AttributeTransactionSampled:             true,
				AttributeTransactionRoot:                true,
				AttributeTransactionID:                  "0100000000000000",
				AttributeTransactionName:                "testtxn",
				AttributeProcessorEvent:                 "transaction",
				AttributeTransactionRepresentativeCount: float64(1),
				AttributeTransactionDurationUs:          expectedDuration.Microseconds(),
				AttributeEventOutcome:                   "success",
				AttributeSuccessCount:                   int64(1),
				AttributeTransactionResult:              "OK",
				AttributeTransactionType:                "request",
			},
		},
		{
			name: "grpc_status_internal_error",
			input: func() ptrace.Span {
				span := getElasticTxn()
				span.SetName("testtxn")
				span.SetSpanID([8]byte{1})
				// attributes should be preferred over span status for txn result
				span.Status().SetCode(ptrace.StatusCodeOk)
				span.Attributes().PutInt(
					semconv.AttributeRPCGRPCStatusCode,
					int64(codes.Internal),
				)
				return span
			}(),
			config: config.Enabled().Transaction,
			enrichedAttrs: map[string]any{
				AttributeTimestampUs:                    startTs.AsTime().UnixMicro(),
				AttributeTransactionSampled:             true,
				AttributeTransactionRoot:                true,
				AttributeTransactionID:                  "0100000000000000",
				AttributeTransactionName:                "testtxn",
				AttributeProcessorEvent:                 "transaction",
				AttributeTransactionRepresentativeCount: float64(1),
				AttributeTransactionDurationUs:          expectedDuration.Microseconds(),
				AttributeEventOutcome:                   "success",
				AttributeSuccessCount:                   int64(1),
				AttributeTransactionResult:              "Internal",
				AttributeTransactionType:                "request",
			},
		},
		{
			name: "span_status_ok",
			input: func() ptrace.Span {
				span := getElasticTxn()
				span.SetName("testtxn")
				span.SetSpanID([8]byte{1})
				span.Status().SetCode(ptrace.StatusCodeOk)
				return span
			}(),
			config: config.Enabled().Transaction,
			enrichedAttrs: map[string]any{
				AttributeTimestampUs:                    startTs.AsTime().UnixMicro(),
				AttributeTransactionSampled:             true,
				AttributeTransactionRoot:                true,
				AttributeTransactionID:                  "0100000000000000",
				AttributeTransactionName:                "testtxn",
				AttributeProcessorEvent:                 "transaction",
				AttributeTransactionRepresentativeCount: float64(1),
				AttributeTransactionDurationUs:          expectedDuration.Microseconds(),
				AttributeEventOutcome:                   "success",
				AttributeSuccessCount:                   int64(1),
				AttributeTransactionResult:              "Success",
				AttributeTransactionType:                "unknown",
			},
		},
		{
			name: "span_status_error",
			input: func() ptrace.Span {
				span := getElasticTxn()
				span.SetName("testtxn")
				span.SetSpanID([8]byte{1})
				span.Status().SetCode(ptrace.StatusCodeError)
				return span
			}(),
			config: config.Enabled().Transaction,
			enrichedAttrs: map[string]any{
				AttributeTimestampUs:                    startTs.AsTime().UnixMicro(),
				AttributeTransactionSampled:             true,
				AttributeTransactionRoot:                true,
				AttributeTransactionID:                  "0100000000000000",
				AttributeTransactionName:                "testtxn",
				AttributeProcessorEvent:                 "transaction",
				AttributeTransactionRepresentativeCount: float64(1),
				AttributeTransactionDurationUs:          expectedDuration.Microseconds(),
				AttributeEventOutcome:                   "failure",
				AttributeSuccessCount:                   int64(0),
				AttributeTransactionResult:              "Error",
				AttributeTransactionType:                "unknown",
			},
		},
		{
			name: "messaging_type_kafka",
			input: func() ptrace.Span {
				span := getElasticTxn()
				span.SetName("testtxn")
				span.SetSpanID([8]byte{1})
				span.Attributes().PutStr(semconv.AttributeMessagingSystem, "kafka")
				return span
			}(),
			config: config.Enabled().Transaction,
			enrichedAttrs: map[string]any{
				AttributeTimestampUs:                    startTs.AsTime().UnixMicro(),
				AttributeTransactionSampled:             true,
				AttributeTransactionRoot:                true,
				AttributeTransactionID:                  "0100000000000000",
				AttributeTransactionName:                "testtxn",
				AttributeProcessorEvent:                 "transaction",
				AttributeTransactionRepresentativeCount: float64(1),
				AttributeTransactionDurationUs:          expectedDuration.Microseconds(),
				AttributeEventOutcome:                   "success",
				AttributeSuccessCount:                   int64(1),
				AttributeTransactionResult:              "Success",
				AttributeTransactionType:                "messaging",
			},
		},
		{
			name: "inferred_spans",
			input: func() ptrace.Span {
				span := getElasticTxn()
				span.SetName("testtxn")
				span.SetSpanID([8]byte{1})
				normalLink := span.Links().AppendEmpty()
				normalLink.SetSpanID([8]byte{2})

				childLink := span.Links().AppendEmpty()
				childLink.SetSpanID([8]byte{3})
				childLink.Attributes().PutBool("is_child", true)

				childLink2 := span.Links().AppendEmpty()
				childLink2.SetSpanID([8]byte{4})
				childLink2.Attributes().PutBool("elastic.is_child", true)
				return span
			}(),
			config: config.Enabled().Transaction,
			enrichedAttrs: map[string]any{
				AttributeTimestampUs:                    startTs.AsTime().UnixMicro(),
				AttributeTransactionSampled:             true,
				AttributeTransactionRoot:                true,
				AttributeTransactionID:                  "0100000000000000",
				AttributeTransactionName:                "testtxn",
				AttributeProcessorEvent:                 "transaction",
				AttributeTransactionRepresentativeCount: float64(1),
				AttributeTransactionDurationUs:          expectedDuration.Microseconds(),
				AttributeEventOutcome:                   "success",
				AttributeSuccessCount:                   int64(1),
				AttributeTransactionResult:              "Success",
				AttributeTransactionType:                "unknown",
				AttributeChildIDs:                       []any{"0300000000000000", "0400000000000000"},
			},
			expectedSpanLinks: func() *ptrace.SpanLinkSlice {
				spanLinks := ptrace.NewSpanLinkSlice()
				// Only the span link without `is_child` or `elastic.is_child` is expected
				spanLinks.AppendEmpty().SetSpanID([8]byte{2})
				return &spanLinks
			}(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expectedSpan := ptrace.NewSpan()
			tc.input.CopyTo(expectedSpan)

			// Merge with the expected attributes and override the span links.
			for k, v := range tc.enrichedAttrs {
				expectedSpan.Attributes().PutEmpty(k).FromRaw(v)
			}
			// Override span links
			if tc.expectedSpanLinks != nil {
				tc.expectedSpanLinks.CopyTo(expectedSpan.Links())
			} else {
				expectedSpan.Links().RemoveIf(func(_ ptrace.SpanLink) bool { return true })
			}

			EnrichSpan(tc.input, config.Config{
				Transaction: tc.config,
			})
			assert.NoError(t, ptracetest.CompareSpan(expectedSpan, tc.input))
		})
	}
}

// Tests root spans that represent a dependency and are mapped to a transaction.
func TestRootSpanAsDependencyEnrich(t *testing.T) {
	for _, tc := range []struct {
		name              string
		input             ptrace.Span
		config            config.Config
		enrichedAttrs     map[string]any
		expectedSpanLinks *ptrace.SpanLinkSlice
	}{
		{
			name: "outgoing_http_root_span",
			input: func() ptrace.Span {
				span := ptrace.NewSpan()
				span.SetName("rootClientSpan")
				span.SetSpanID([8]byte{1})
				span.SetKind(ptrace.SpanKindClient)
				span.Attributes().PutStr(semconv.AttributeHTTPMethod, "GET")
				span.Attributes().PutStr(semconv.AttributeHTTPURL, "http://localhost:8080")
				span.Attributes().PutInt(semconv.AttributeHTTPResponseStatusCode, 200)
				span.Attributes().PutStr(semconv.AttributeNetworkProtocolVersion, "1.1")
				return span
			}(),
			config: config.Enabled(),
			enrichedAttrs: map[string]any{
				AttributeTimestampUs:                    int64(0),
				AttributeTransactionName:                "rootClientSpan",
				AttributeProcessorEvent:                 "transaction",
				AttributeSpanType:                       "external",
				AttributeSpanSubtype:                    "http",
				AttributeSpanDestinationServiceResource: "localhost:8080",
				AttributeSpanName:                       "rootClientSpan",
				AttributeEventOutcome:                   "success",
				AttributeSuccessCount:                   int64(1),
				AttributeServiceTargetName:              "localhost:8080",
				AttributeServiceTargetType:              "http",
				AttributeTransactionID:                  "0100000000000000",
				AttributeTransactionDurationUs:          int64(0),
				AttributeTransactionRepresentativeCount: float64(1),
				AttributeTransactionResult:              "HTTP 2xx",
				AttributeTransactionType:                "external.http",
				AttributeTransactionSampled:             true,
				AttributeTransactionRoot:                true,
			},
		},
		{
			name: "db_root_span",
			input: func() ptrace.Span {
				span := ptrace.NewSpan()
				span.SetName("rootClientSpan")
				span.SetSpanID([8]byte{1})
				span.SetKind(ptrace.SpanKindClient)
				span.Attributes().PutStr(semconv.AttributeDBSystem, "mssql")

				span.Attributes().PutStr(semconv.AttributeDBName, "myDb")
				span.Attributes().PutStr(semconv.AttributeDBOperation, "SELECT")
				span.Attributes().PutStr(semconv.AttributeDBStatement, "SELECT * FROM wuser_table")
				return span
			}(),
			config: config.Enabled(),
			enrichedAttrs: map[string]any{
				AttributeTimestampUs:                    int64(0),
				AttributeTransactionName:                "rootClientSpan",
				AttributeProcessorEvent:                 "transaction",
				AttributeSpanType:                       "db",
				AttributeSpanSubtype:                    "mssql",
				AttributeSpanDestinationServiceResource: "mssql",
				AttributeSpanName:                       "rootClientSpan",
				AttributeEventOutcome:                   "success",
				AttributeSuccessCount:                   int64(1),
				AttributeServiceTargetName:              "myDb",
				AttributeServiceTargetType:              "mssql",
				AttributeTransactionID:                  "0100000000000000",
				AttributeTransactionDurationUs:          int64(0),
				AttributeTransactionRepresentativeCount: float64(1),
				AttributeTransactionResult:              "Success",
				AttributeTransactionType:                "db.mssql",
				AttributeTransactionSampled:             true,
				AttributeTransactionRoot:                true,
			},
		},
		{
			name: "producer_messaging_span",
			input: func() ptrace.Span {
				span := ptrace.NewSpan()
				span.SetName("rootClientSpan")
				span.SetSpanID([8]byte{1})
				span.SetKind(ptrace.SpanKindProducer)

				span.Attributes().PutStr(semconv.AttributeServerAddress, "myServer")
				span.Attributes().PutStr(semconv.AttributeServerPort, "1234")
				span.Attributes().PutStr(semconv.AttributeMessagingSystem, "rabbitmq")
				span.Attributes().PutStr(semconv.AttributeMessagingDestinationName, "T")
				span.Attributes().PutStr(semconv.AttributeMessagingOperation, "publish")
				span.Attributes().PutStr(semconv.AttributeMessagingClientID, "a")
				return span
			}(),
			config: config.Enabled(),
			enrichedAttrs: map[string]any{
				AttributeTimestampUs:                    int64(0),
				AttributeTransactionName:                "rootClientSpan",
				AttributeProcessorEvent:                 "transaction",
				AttributeSpanType:                       "messaging",
				AttributeSpanSubtype:                    "rabbitmq",
				AttributeSpanDestinationServiceResource: "rabbitmq/T",
				AttributeSpanName:                       "rootClientSpan",
				AttributeEventOutcome:                   "success",
				AttributeSuccessCount:                   int64(1),
				AttributeServiceTargetName:              "T",
				AttributeServiceTargetType:              "rabbitmq",
				AttributeTransactionID:                  "0100000000000000",
				AttributeTransactionDurationUs:          int64(0),
				AttributeTransactionRepresentativeCount: float64(1),
				AttributeTransactionResult:              "Success",
				AttributeTransactionType:                "messaging.rabbitmq",
				AttributeTransactionSampled:             true,
				AttributeTransactionRoot:                true,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expectedSpan := ptrace.NewSpan()
			tc.input.CopyTo(expectedSpan)

			// Merge with the expected attributes and override the span links.
			for k, v := range tc.enrichedAttrs {
				expectedSpan.Attributes().PutEmpty(k).FromRaw(v)
			}
			// Override span links
			if tc.expectedSpanLinks != nil {
				tc.expectedSpanLinks.CopyTo(expectedSpan.Links())
			} else {
				expectedSpan.Links().RemoveIf(func(_ ptrace.SpanLink) bool { return true })
			}

			EnrichSpan(tc.input, tc.config)
			assert.NoError(t, ptracetest.CompareSpan(expectedSpan, tc.input))
		})
	}
}

// Tests the enrichment logic for elastic's span definition.
func TestElasticSpanEnrich(t *testing.T) {
	now := time.Unix(3600, 0)
	expectedDuration := time.Minute
	endTs := pcommon.NewTimestampFromTime(now)
	startTs := pcommon.NewTimestampFromTime(now.Add(-1 * expectedDuration))
	getElasticSpan := func() ptrace.Span {
		span := ptrace.NewSpan()
		span.SetParentSpanID([8]byte{8, 9, 10, 11, 12, 13, 14})
		span.SetStartTimestamp(startTs)
		span.SetEndTimestamp(endTs)
		return span
	}
	for _, tc := range []struct {
		name              string
		input             ptrace.Span
		config            config.ElasticSpanConfig
		enrichedAttrs     map[string]any
		expectedSpanLinks *ptrace.SpanLinkSlice
	}{
		{
			// test case gives a summary of what is emitted by default
			name: "empty",
			input: func() ptrace.Span {
				span := ptrace.NewSpan()
				span.SetParentSpanID([8]byte{1})
				return span
			}(),
			config: config.Enabled().Span,
			enrichedAttrs: map[string]any{
				AttributeTimestampUs:             int64(0),
				AttributeSpanName:                "",
				AttributeProcessorEvent:          "span",
				AttributeSpanRepresentativeCount: float64(1),
				AttributeSpanType:                "unknown",
				AttributeSpanDurationUs:          int64(0),
				AttributeEventOutcome:            "success",
				AttributeSuccessCount:            int64(1),
			},
		},
		{
			name:          "all_disabled",
			input:         getElasticSpan(),
			enrichedAttrs: map[string]any{},
		},
		{
			name: "internal_span",
			input: func() ptrace.Span {
				span := ptrace.NewSpan()
				span.SetParentSpanID([8]byte{1})
				span.SetKind(ptrace.SpanKindInternal)
				return span
			}(),
			config: config.Enabled().Span,
			enrichedAttrs: map[string]any{
				AttributeTimestampUs:             int64(0),
				AttributeSpanName:                "",
				AttributeProcessorEvent:          "span",
				AttributeSpanRepresentativeCount: float64(1),
				AttributeSpanType:                "app",
				AttributeSpanSubtype:             "internal",
				AttributeSpanDurationUs:          int64(0),
				AttributeEventOutcome:            "success",
				AttributeSuccessCount:            int64(1),
			},
		},
		{
			name: "peer_service",
			input: func() ptrace.Span {
				span := getElasticSpan()
				span.SetName("testspan")
				span.Attributes().PutStr(semconv.AttributePeerService, "testsvc")
				return span
			}(),
			config: config.Enabled().Span,
			enrichedAttrs: map[string]any{
				AttributeTimestampUs:                    startTs.AsTime().UnixMicro(),
				AttributeSpanName:                       "testspan",
				AttributeProcessorEvent:                 "span",
				AttributeSpanRepresentativeCount:        float64(1),
				AttributeSpanType:                       "unknown",
				AttributeSpanDurationUs:                 expectedDuration.Microseconds(),
				AttributeEventOutcome:                   "success",
				AttributeSuccessCount:                   int64(1),
				AttributeServiceTargetName:              "testsvc",
				AttributeServiceTargetType:              "",
				AttributeSpanDestinationServiceResource: "testsvc",
			},
		},
		{
			name: "http_span_basic",
			input: func() ptrace.Span {
				span := getElasticSpan()
				span.SetName("testspan")
				span.Attributes().PutStr(semconv.AttributePeerService, "testsvc")
				span.Attributes().PutInt(
					semconv.AttributeHTTPResponseStatusCode,
					http.StatusOK,
				)
				return span
			}(),
			config: config.Enabled().Span,
			enrichedAttrs: map[string]any{
				AttributeTimestampUs:                    startTs.AsTime().UnixMicro(),
				AttributeSpanName:                       "testspan",
				AttributeProcessorEvent:                 "span",
				AttributeSpanRepresentativeCount:        float64(1),
				AttributeSpanType:                       "external",
				AttributeSpanSubtype:                    "http",
				AttributeSpanDurationUs:                 expectedDuration.Microseconds(),
				AttributeEventOutcome:                   "success",
				AttributeSuccessCount:                   int64(1),
				AttributeServiceTargetType:              "http",
				AttributeServiceTargetName:              "testsvc",
				AttributeSpanDestinationServiceResource: "testsvc",
			},
		},
		{
			name: "http_span_full_url",
			input: func() ptrace.Span {
				span := getElasticSpan()
				span.SetName("testspan")
				// peer.service should be ignored if more specific deductions
				// can be made about the service target.
				span.Attributes().PutStr(semconv.AttributePeerService, "testsvc")
				span.Attributes().PutInt(
					semconv.AttributeHTTPResponseStatusCode,
					http.StatusOK,
				)
				span.Attributes().PutStr(
					semconv.AttributeURLFull,
					"https://www.foo.bar:443/search?q=OpenTelemetry#SemConv",
				)
				return span
			}(),
			config: config.Enabled().Span,
			enrichedAttrs: map[string]any{
				AttributeTimestampUs:                    startTs.AsTime().UnixMicro(),
				AttributeSpanName:                       "testspan",
				AttributeProcessorEvent:                 "span",
				AttributeSpanRepresentativeCount:        float64(1),
				AttributeSpanType:                       "external",
				AttributeSpanSubtype:                    "http",
				AttributeSpanDurationUs:                 expectedDuration.Microseconds(),
				AttributeEventOutcome:                   "success",
				AttributeSuccessCount:                   int64(1),
				AttributeServiceTargetType:              "http",
				AttributeServiceTargetName:              "www.foo.bar:443",
				AttributeSpanDestinationServiceResource: "testsvc",
			},
		},
		{
			name: "http_span_deprecated_http_url",
			input: func() ptrace.Span {
				span := getElasticSpan()
				span.SetName("testspan")
				// peer.service should be ignored if more specific deductions
				// can be made about the service target.
				span.Attributes().PutStr(semconv.AttributePeerService, "testsvc")
				span.Attributes().PutInt(
					semconv.AttributeHTTPResponseStatusCode,
					http.StatusOK,
				)
				span.Attributes().PutStr(
					semconv.AttributeHTTPURL,
					"https://www.foo.bar:443/search?q=OpenTelemetry#SemConv",
				)
				return span
			}(),
			config: config.Enabled().Span,
			enrichedAttrs: map[string]any{
				AttributeTimestampUs:                    startTs.AsTime().UnixMicro(),
				AttributeSpanName:                       "testspan",
				AttributeProcessorEvent:                 "span",
				AttributeSpanRepresentativeCount:        float64(1),
				AttributeSpanType:                       "external",
				AttributeSpanSubtype:                    "http",
				AttributeSpanDurationUs:                 expectedDuration.Microseconds(),
				AttributeEventOutcome:                   "success",
				AttributeSuccessCount:                   int64(1),
				AttributeServiceTargetType:              "http",
				AttributeServiceTargetName:              "www.foo.bar:443",
				AttributeSpanDestinationServiceResource: "testsvc",
			},
		},
		{
			name: "http_span_no_full_url",
			input: func() ptrace.Span {
				span := getElasticSpan()
				span.SetName("testspan")
				// peer.service should be ignored if more specific deductions
				// can be made about the service target.
				span.Attributes().PutStr(semconv.AttributePeerService, "testsvc")
				span.Attributes().PutInt(
					semconv.AttributeHTTPResponseStatusCode,
					http.StatusOK,
				)
				span.Attributes().PutStr(semconv.AttributeURLDomain, "www.foo.bar")
				span.Attributes().PutInt(semconv.AttributeURLPort, 443)
				return span
			}(),
			config: config.Enabled().Span,
			enrichedAttrs: map[string]any{
				AttributeTimestampUs:                    startTs.AsTime().UnixMicro(),
				AttributeSpanName:                       "testspan",
				AttributeProcessorEvent:                 "span",
				AttributeSpanRepresentativeCount:        float64(1),
				AttributeSpanType:                       "external",
				AttributeSpanSubtype:                    "http",
				AttributeSpanDurationUs:                 expectedDuration.Microseconds(),
				AttributeEventOutcome:                   "success",
				AttributeSuccessCount:                   int64(1),
				AttributeServiceTargetType:              "http",
				AttributeServiceTargetName:              "www.foo.bar:443",
				AttributeSpanDestinationServiceResource: "testsvc",
			},
		},
		{
			name: "rpc_span_grpc",
			input: func() ptrace.Span {
				span := getElasticSpan()
				span.SetName("testspan")
				span.Attributes().PutStr(semconv.AttributePeerService, "testsvc")
				span.Attributes().PutInt(
					semconv.AttributeRPCGRPCStatusCode,
					int64(codes.OK),
				)
				return span
			}(),
			config: config.Enabled().Span,
			enrichedAttrs: map[string]any{
				AttributeTimestampUs:                    startTs.AsTime().UnixMicro(),
				AttributeSpanName:                       "testspan",
				AttributeProcessorEvent:                 "span",
				AttributeSpanRepresentativeCount:        float64(1),
				AttributeSpanType:                       "external",
				AttributeSpanSubtype:                    "grpc",
				AttributeSpanDurationUs:                 expectedDuration.Microseconds(),
				AttributeEventOutcome:                   "success",
				AttributeSuccessCount:                   int64(1),
				AttributeServiceTargetType:              "grpc",
				AttributeServiceTargetName:              "testsvc",
				AttributeSpanDestinationServiceResource: "testsvc",
			},
		},
		{
			name: "rpc_span_system",
			input: func() ptrace.Span {
				span := getElasticSpan()
				span.SetName("testspan")
				span.Attributes().PutStr(semconv.AttributePeerService, "testsvc")
				span.Attributes().PutStr(semconv.AttributeRPCSystem, "xmlrpc")
				return span
			}(),
			config: config.Enabled().Span,
			enrichedAttrs: map[string]any{
				AttributeTimestampUs:                    startTs.AsTime().UnixMicro(),
				AttributeSpanName:                       "testspan",
				AttributeProcessorEvent:                 "span",
				AttributeSpanRepresentativeCount:        float64(1),
				AttributeSpanType:                       "external",
				AttributeSpanSubtype:                    "xmlrpc",
				AttributeSpanDurationUs:                 expectedDuration.Microseconds(),
				AttributeEventOutcome:                   "success",
				AttributeSuccessCount:                   int64(1),
				AttributeServiceTargetType:              "xmlrpc",
				AttributeServiceTargetName:              "testsvc",
				AttributeSpanDestinationServiceResource: "testsvc",
			},
		},
		{
			name: "rpc_span_service",
			input: func() ptrace.Span {
				span := getElasticSpan()
				span.SetName("testspan")
				// peer.service should be ignored if more specific deductions
				// can be made about the service target.
				span.Attributes().PutStr(semconv.AttributePeerService, "testsvc")
				span.Attributes().PutStr(semconv.AttributeRPCService, "service.Test")
				return span
			}(),
			config: config.Enabled().Span,
			enrichedAttrs: map[string]any{
				AttributeTimestampUs:                    startTs.AsTime().UnixMicro(),
				AttributeSpanName:                       "testspan",
				AttributeProcessorEvent:                 "span",
				AttributeSpanRepresentativeCount:        float64(1),
				AttributeSpanType:                       "external",
				AttributeSpanDurationUs:                 expectedDuration.Microseconds(),
				AttributeEventOutcome:                   "success",
				AttributeSuccessCount:                   int64(1),
				AttributeServiceTargetType:              "external",
				AttributeServiceTargetName:              "service.Test",
				AttributeSpanDestinationServiceResource: "testsvc",
			},
		},
		{
			name: "rpc_span_service.{address, port}",
			input: func() ptrace.Span {
				span := getElasticSpan()
				span.SetName("testspan")
				// No peer.service is set
				span.Attributes().PutStr(semconv.AttributeRPCService, "service.Test")
				span.Attributes().PutStr(semconv.AttributeServerAddress, "10.2.20.18")
				span.Attributes().PutInt(semconv.AttributeServerPort, 8081)
				return span
			}(),
			config: config.Enabled().Span,
			enrichedAttrs: map[string]any{
				AttributeTimestampUs:                    startTs.AsTime().UnixMicro(),
				AttributeSpanName:                       "testspan",
				AttributeProcessorEvent:                 "span",
				AttributeSpanRepresentativeCount:        float64(1),
				AttributeSpanType:                       "external",
				AttributeSpanDurationUs:                 expectedDuration.Microseconds(),
				AttributeEventOutcome:                   "success",
				AttributeSuccessCount:                   int64(1),
				AttributeServiceTargetType:              "external",
				AttributeServiceTargetName:              "service.Test",
				AttributeSpanDestinationServiceResource: "10.2.20.18:8081",
			},
		},
		{
			name: "rpc_span_net.peer.{address, port}_fallback",
			input: func() ptrace.Span {
				span := getElasticSpan()
				span.SetName("testspan")
				// No peer.service is set
				span.Attributes().PutStr(semconv.AttributeRPCService, "service.Test")
				span.Attributes().PutStr(semconv.AttributeNetPeerName, "10.2.20.18")
				span.Attributes().PutInt(semconv.AttributeNetPeerPort, 8081)
				return span
			}(),
			config: config.Enabled().Span,
			enrichedAttrs: map[string]any{
				AttributeTimestampUs:                    startTs.AsTime().UnixMicro(),
				AttributeSpanName:                       "testspan",
				AttributeProcessorEvent:                 "span",
				AttributeSpanRepresentativeCount:        float64(1),
				AttributeSpanType:                       "external",
				AttributeSpanDurationUs:                 expectedDuration.Microseconds(),
				AttributeEventOutcome:                   "success",
				AttributeSuccessCount:                   int64(1),
				AttributeServiceTargetType:              "external",
				AttributeServiceTargetName:              "service.Test",
				AttributeSpanDestinationServiceResource: "10.2.20.18:8081",
			},
		},
		{
			name: "messaging_basic",
			input: func() ptrace.Span {
				span := getElasticSpan()
				span.SetName("testspan")
				span.Attributes().PutStr(semconv.AttributePeerService, "testsvc")
				span.Attributes().PutStr(semconv.AttributeMessagingSystem, "kafka")
				return span
			}(),
			config: config.Enabled().Span,
			enrichedAttrs: map[string]any{
				AttributeTimestampUs:                    startTs.AsTime().UnixMicro(),
				AttributeSpanName:                       "testspan",
				AttributeProcessorEvent:                 "span",
				AttributeSpanRepresentativeCount:        float64(1),
				AttributeSpanType:                       "messaging",
				AttributeSpanSubtype:                    "kafka",
				AttributeSpanDurationUs:                 expectedDuration.Microseconds(),
				AttributeEventOutcome:                   "success",
				AttributeSuccessCount:                   int64(1),
				AttributeServiceTargetType:              "kafka",
				AttributeServiceTargetName:              "testsvc",
				AttributeSpanDestinationServiceResource: "testsvc",
			},
		},
		{
			name: "messaging_destination",
			input: func() ptrace.Span {
				span := getElasticSpan()
				span.SetName("testspan")
				span.Attributes().PutStr(semconv.AttributePeerService, "testsvc")
				span.Attributes().PutStr(semconv.AttributeMessagingDestinationName, "t1")
				return span
			}(),
			config: config.Enabled().Span,
			enrichedAttrs: map[string]any{
				AttributeTimestampUs:                    startTs.AsTime().UnixMicro(),
				AttributeSpanName:                       "testspan",
				AttributeProcessorEvent:                 "span",
				AttributeSpanRepresentativeCount:        float64(1),
				AttributeSpanType:                       "messaging",
				AttributeSpanDurationUs:                 expectedDuration.Microseconds(),
				AttributeEventOutcome:                   "success",
				AttributeSuccessCount:                   int64(1),
				AttributeServiceTargetType:              "messaging",
				AttributeServiceTargetName:              "t1",
				AttributeSpanDestinationServiceResource: "testsvc/t1",
			},
		},
		{
			name: "messaging_temp_destination",
			input: func() ptrace.Span {
				span := getElasticSpan()
				span.SetName("testspan")
				span.Attributes().PutStr(semconv.AttributePeerService, "testsvc")
				span.Attributes().PutBool(semconv.AttributeMessagingDestinationTemporary, true)
				span.Attributes().PutStr(semconv.AttributeMessagingDestinationName, "t1")
				return span
			}(),
			config: config.Enabled().Span,
			enrichedAttrs: map[string]any{
				AttributeTimestampUs:                    startTs.AsTime().UnixMicro(),
				AttributeSpanName:                       "testspan",
				AttributeProcessorEvent:                 "span",
				AttributeSpanRepresentativeCount:        float64(1),
				AttributeSpanType:                       "messaging",
				AttributeSpanDurationUs:                 expectedDuration.Microseconds(),
				AttributeEventOutcome:                   "success",
				AttributeSuccessCount:                   int64(1),
				AttributeServiceTargetType:              "messaging",
				AttributeServiceTargetName:              "testsvc",
				AttributeSpanDestinationServiceResource: "testsvc/t1",
			},
		},
		{
			name: "db_over_http",
			input: func() ptrace.Span {
				span := getElasticSpan()
				span.SetName("testspan")
				span.Attributes().PutStr(semconv.AttributePeerService, "testsvc")
				span.Attributes().PutStr(
					semconv.AttributeURLFull,
					"https://localhost:9200/index/_search?q=user.id:kimchy",
				)
				span.Attributes().PutStr(
					semconv.AttributeDBSystem,
					semconv.AttributeDBSystemElasticsearch,
				)
				return span
			}(),
			config: config.Enabled().Span,
			enrichedAttrs: map[string]any{
				AttributeTimestampUs:                    startTs.AsTime().UnixMicro(),
				AttributeSpanName:                       "testspan",
				AttributeProcessorEvent:                 "span",
				AttributeSpanRepresentativeCount:        float64(1),
				AttributeSpanType:                       "db",
				AttributeSpanSubtype:                    "elasticsearch",
				AttributeSpanDurationUs:                 expectedDuration.Microseconds(),
				AttributeEventOutcome:                   "success",
				AttributeSuccessCount:                   int64(1),
				AttributeServiceTargetType:              "elasticsearch",
				AttributeServiceTargetName:              "testsvc",
				AttributeSpanDestinationServiceResource: "testsvc",
			},
		},
		{
			name: "db_over_rpc",
			input: func() ptrace.Span {
				span := getElasticSpan()
				span.SetName("testspan")
				span.Attributes().PutStr(semconv.AttributePeerService, "testsvc")
				span.Attributes().PutStr(
					semconv.AttributeRPCSystem,
					semconv.AttributeRPCSystemGRPC,
				)
				span.Attributes().PutStr(semconv.AttributeRPCService, "cassandra.API")
				span.Attributes().PutStr(
					semconv.AttributeRPCGRPCStatusCode,
					semconv.AttributeRPCGRPCStatusCodeOk,
				)
				span.Attributes().PutStr(
					semconv.AttributeDBSystem,
					semconv.AttributeDBSystemCassandra,
				)
				return span
			}(),
			config: config.Enabled().Span,
			enrichedAttrs: map[string]any{
				AttributeTimestampUs:                    startTs.AsTime().UnixMicro(),
				AttributeSpanName:                       "testspan",
				AttributeProcessorEvent:                 "span",
				AttributeSpanRepresentativeCount:        float64(1),
				AttributeSpanType:                       "db",
				AttributeSpanSubtype:                    "cassandra",
				AttributeSpanDurationUs:                 expectedDuration.Microseconds(),
				AttributeEventOutcome:                   "success",
				AttributeSuccessCount:                   int64(1),
				AttributeServiceTargetType:              "cassandra",
				AttributeServiceTargetName:              "testsvc",
				AttributeSpanDestinationServiceResource: "testsvc",
			},
		},
		{
			name: "inferred_spans",
			input: func() ptrace.Span {
				span := getElasticSpan()
				span.SetName("testspan")
				span.SetSpanID([8]byte{1})
				normalLink := span.Links().AppendEmpty()
				normalLink.SetSpanID([8]byte{2})

				childLink := span.Links().AppendEmpty()
				childLink.SetSpanID([8]byte{3})
				childLink.Attributes().PutBool("is_child", true)

				childLink2 := span.Links().AppendEmpty()
				childLink2.SetSpanID([8]byte{4})
				childLink2.Attributes().PutBool("elastic.is_child", true)
				return span
			}(),
			config: config.Enabled().Span,
			enrichedAttrs: map[string]any{
				AttributeTimestampUs:             startTs.AsTime().UnixMicro(),
				AttributeSpanName:                "testspan",
				AttributeProcessorEvent:          "span",
				AttributeSpanRepresentativeCount: float64(1),
				AttributeSpanType:                "unknown",
				AttributeSpanDurationUs:          expectedDuration.Microseconds(),
				AttributeEventOutcome:            "success",
				AttributeSuccessCount:            int64(1),
				AttributeChildIDs:                []any{"0300000000000000", "0400000000000000"},
			},
			expectedSpanLinks: func() *ptrace.SpanLinkSlice {
				spanLinks := ptrace.NewSpanLinkSlice()
				// Only the span link without `is_child` or `elastic.is_child` is expected
				spanLinks.AppendEmpty().SetSpanID([8]byte{2})
				return &spanLinks
			}(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expectedSpan := ptrace.NewSpan()
			tc.input.CopyTo(expectedSpan)

			// Merge with the expected attributes and override the span links.
			for k, v := range tc.enrichedAttrs {
				expectedSpan.Attributes().PutEmpty(k).FromRaw(v)
			}
			// Override span links
			if tc.expectedSpanLinks != nil {
				tc.expectedSpanLinks.CopyTo(expectedSpan.Links())
			} else {
				expectedSpan.Links().RemoveIf(func(_ ptrace.SpanLink) bool { return true })
			}

			EnrichSpan(tc.input, config.Config{
				Span: tc.config,
			})
			assert.NoError(t, ptracetest.CompareSpan(expectedSpan, tc.input))
		})
	}
}

func TestSpanEventEnrich(t *testing.T) {
	now := time.Unix(3600, 0)
	ts := pcommon.NewTimestampFromTime(now)
	for _, tc := range []struct {
		name          string
		parent        ptrace.Span
		input         ptrace.SpanEvent
		config        config.SpanEventConfig
		errorID       bool // indicates if the error ID should be present in the result
		enrichedAttrs map[string]any
	}{
		{
			name:   "not_exception",
			parent: ptrace.NewSpan(),
			input: func() ptrace.SpanEvent {
				event := ptrace.NewSpanEvent()
				event.SetTimestamp(ts)
				return event
			}(),
			config:  config.Enabled().SpanEvent,
			errorID: false, // error ID is only present for exceptions
			enrichedAttrs: map[string]any{
				AttributeTimestampUs: ts.AsTime().UnixMicro(),
			},
		},
		{
			name: "exception_with_elastic_txn",
			parent: func() ptrace.Span {
				// No parent, elastic txn
				span := ptrace.NewSpan()
				return span
			}(),
			input: func() ptrace.SpanEvent {
				event := ptrace.NewSpanEvent()
				event.SetName("exception")
				event.SetTimestamp(ts)
				event.Attributes().PutStr(semconv.AttributeExceptionType, "java.net.ConnectionError")
				event.Attributes().PutStr(semconv.AttributeExceptionMessage, "something is wrong")
				event.Attributes().PutStr(semconv.AttributeExceptionStacktrace, `Exception in thread "main" java.lang.RuntimeException: Test exception\\n at com.example.GenerateTrace.methodB(GenerateTrace.java:13)\\n at com.example.GenerateTrace.methodA(GenerateTrace.java:9)\\n at com.example.GenerateTrace.main(GenerateTrace.java:5)`)
				return event
			}(),
			config:  config.Enabled().SpanEvent,
			errorID: true,
			enrichedAttrs: map[string]any{
				AttributeTimestampUs:           ts.AsTime().UnixMicro(),
				AttributeProcessorEvent:        "error",
				AttributeErrorExceptionHandled: true,
				AttributeErrorGroupingKey: func() string {
					hash := md5.New()
					hash.Write([]byte("java.net.ConnectionError"))
					return hex.EncodeToString(hash.Sum(nil))
				}(),
				AttributeErrorGroupingName:  "something is wrong",
				AttributeTransactionSampled: true,
				AttributeTransactionType:    "unknown",
			},
		},
		{
			name: "exception_with_elastic_span",
			parent: func() ptrace.Span {
				// Parent, elastic span
				span := ptrace.NewSpan()
				span.SetParentSpanID([8]byte{8, 9, 10, 11, 12, 13, 14})
				return span
			}(),
			input: func() ptrace.SpanEvent {
				event := ptrace.NewSpanEvent()
				event.SetName("exception")
				event.SetTimestamp(ts)
				event.Attributes().PutStr(semconv.AttributeExceptionType, "java.net.ConnectionError")
				event.Attributes().PutStr(semconv.AttributeExceptionMessage, "something is wrong")
				event.Attributes().PutStr(semconv.AttributeExceptionStacktrace, `Exception in thread "main" java.lang.RuntimeException: Test exception\\n at com.example.GenerateTrace.methodB(GenerateTrace.java:13)\\n at com.example.GenerateTrace.methodA(GenerateTrace.java:9)\\n at com.example.GenerateTrace.main(GenerateTrace.java:5)`)
				return event
			}(),
			config:  config.Enabled().SpanEvent,
			errorID: true,
			enrichedAttrs: map[string]any{
				AttributeTimestampUs:           ts.AsTime().UnixMicro(),
				AttributeProcessorEvent:        "error",
				AttributeErrorExceptionHandled: true,
				AttributeErrorGroupingKey: func() string {
					hash := md5.New()
					hash.Write([]byte("java.net.ConnectionError"))
					return hex.EncodeToString(hash.Sum(nil))
				}(),
				AttributeErrorGroupingName: "something is wrong",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Merge existing input attrs with the attrs added
			// by enrichment to get the expected attributes.
			expectedAttrs := tc.input.Attributes().AsRaw()
			for k, v := range tc.enrichedAttrs {
				expectedAttrs[k] = v
			}

			tc.input.MoveTo(tc.parent.Events().AppendEmpty())
			EnrichSpan(tc.parent, config.Config{
				SpanEvent: tc.config,
			})

			actual := tc.parent.Events().At(0).Attributes()
			errorID, ok := actual.Get(AttributeErrorID)
			assert.Equal(t, tc.errorID, ok, "error_id must be present for exception and must not be present for non-exception")
			if tc.errorID {
				assert.NotEmpty(t, errorID, "error_id must not be empty")
			}
			// Ignore error in actual diff since it is randomly generated
			actual.Remove(AttributeErrorID)
			assert.Empty(t, cmp.Diff(expectedAttrs, actual.AsRaw()))
		})
	}
}

func TestIsElasticTransaction(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input ptrace.Span
		isTxn bool
	}{
		{
			name:  "no_parent_span",
			input: ptrace.NewSpan(),
			isTxn: true,
		},
		{
			name: "parent_span",
			input: func() ptrace.Span {
				span := ptrace.NewSpan()
				span.SetParentSpanID([8]byte{8, 9, 10, 11, 12, 13, 14})
				return span
			}(),
			isTxn: false,
		},
		{
			name: "remote_parent_span",
			input: func() ptrace.Span {
				span := ptrace.NewSpan()
				span.SetParentSpanID([8]byte{8, 9, 10, 11, 12, 13, 14})
				flags := tracepb.SpanFlags_SPAN_FLAGS_CONTEXT_HAS_IS_REMOTE_MASK
				flags = flags | tracepb.SpanFlags_SPAN_FLAGS_CONTEXT_IS_REMOTE_MASK
				span.SetFlags(uint32(flags))
				return span
			}(),
			isTxn: true,
		},
		{
			name: "local_parent_span",
			input: func() ptrace.Span {
				span := ptrace.NewSpan()
				span.SetParentSpanID([8]byte{8, 9, 10, 11, 12, 13, 14})
				flags := tracepb.SpanFlags_SPAN_FLAGS_CONTEXT_HAS_IS_REMOTE_MASK
				span.SetFlags(uint32(flags))
				return span
			}(),
			isTxn: false,
		},
		{
			name: "unknown_parent_span_kind_server",
			input: func() ptrace.Span {
				span := ptrace.NewSpan()
				span.SetParentSpanID([8]byte{8, 9, 10, 11, 12, 13, 14})
				span.SetKind(ptrace.SpanKindServer)
				return span
			}(),
			isTxn: true,
		},
		{
			name: "unknown_parent_span_kind_consumer",
			input: func() ptrace.Span {
				span := ptrace.NewSpan()
				span.SetParentSpanID([8]byte{8, 9, 10, 11, 12, 13, 14})
				span.SetKind(ptrace.SpanKindConsumer)
				return span
			}(),
			isTxn: true,
		},
		{
			name: "unknown_parent_span_kind_producer",
			input: func() ptrace.Span {
				span := ptrace.NewSpan()
				span.SetParentSpanID([8]byte{8, 9, 10, 11, 12, 13, 14})
				span.SetKind(ptrace.SpanKindProducer)
				return span
			}(),
			isTxn: false,
		},
		{
			name: "unknown_parent_span_kind_unspecified",
			input: func() ptrace.Span {
				span := ptrace.NewSpan()
				span.SetParentSpanID([8]byte{8, 9, 10, 11, 12, 13, 14})
				return span
			}(),
			isTxn: false,
		},
		{
			name: "unknown_parent_span_kind_internal",
			input: func() ptrace.Span {
				span := ptrace.NewSpan()
				span.SetParentSpanID([8]byte{8, 9, 10, 11, 12, 13, 14})
				span.SetKind(ptrace.SpanKindInternal)
				return span
			}(),
			isTxn: false,
		},
	} {
		assert.Equal(t, tc.isTxn, isElasticTransaction(tc.input))
	}
}
