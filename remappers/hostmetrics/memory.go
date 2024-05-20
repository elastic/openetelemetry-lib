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

package hostmetrics

import (
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"

	remappers "github.com/elastic/opentelemetry-lib/remappers/internal"
)

func remapMemoryMetrics(
	src, out pmetric.MetricSlice,
	_ pcommon.Resource,
	dataset string,
) error {
	var timestamp pcommon.Timestamp
	var total, free, cached, usedBytes, actualFree, actualUsedBytes int64
	var usedPercent, actualUsedPercent float64

	for i := 0; i < src.Len(); i++ {
		metric := src.At(i)
		switch metric.Name() {
		case "system.memory.usage":
			dataPoints := metric.Sum().DataPoints()
			for j := 0; j < dataPoints.Len(); j++ {
				dp := dataPoints.At(j)
				if timestamp == 0 {
					timestamp = dp.Timestamp()
				}

				value := dp.IntValue()
				if state, ok := dp.Attributes().Get("state"); ok {
					switch state.Str() {
					case "cached":
						cached = value
						total += value
					case "free":
						free = value
						usedBytes -= value
						total += value
					case "used":
						total += value
						actualUsedBytes += value
					case "buffered":
						total += value
						actualUsedBytes += value
					case "slab_unreclaimable":
						actualUsedBytes += value
					case "slab_reclaimable":
						actualUsedBytes += value
					}
				}
			}
		case "system.memory.utilization":
			dataPoints := metric.Gauge().DataPoints()
			for j := 0; j < dataPoints.Len(); j++ {
				dp := dataPoints.At(j)
				if timestamp == 0 {
					timestamp = dp.Timestamp()
				}

				value := dp.DoubleValue()
				if state, ok := dp.Attributes().Get("state"); ok {
					switch state.Str() {
					case "free":
						usedPercent = 1 - value
					case "used":
						actualUsedPercent += value
					case "buffered":
						actualUsedPercent += value
					case "slab_unreclaimable":
						actualUsedPercent += value
					case "slab_reclaimable":
						actualUsedPercent += value
					}
				}
			}
		}
	}

	usedBytes += total
	actualFree = total - actualUsedBytes

	remappers.AddMetrics(out, dataset, remappers.EmptyMutator,
		remappers.Metric{
			DataType:  pmetric.MetricTypeSum,
			Name:      "system.memory.total",
			Timestamp: timestamp,
			IntValue:  &total,
		},
		remappers.Metric{
			DataType:  pmetric.MetricTypeSum,
			Name:      "system.memory.free",
			Timestamp: timestamp,
			IntValue:  &free,
		},
		remappers.Metric{
			DataType:  pmetric.MetricTypeSum,
			Name:      "system.memory.cached",
			Timestamp: timestamp,
			IntValue:  &cached,
		},
		remappers.Metric{
			DataType:  pmetric.MetricTypeSum,
			Name:      "system.memory.used.bytes",
			Timestamp: timestamp,
			IntValue:  &usedBytes,
		},
		remappers.Metric{
			DataType:  pmetric.MetricTypeSum,
			Name:      "system.memory.actual.used.bytes",
			Timestamp: timestamp,
			IntValue:  &actualUsedBytes,
		},
		remappers.Metric{
			DataType:  pmetric.MetricTypeSum,
			Name:      "system.memory.actual.free",
			Timestamp: timestamp,
			IntValue:  &actualFree,
		},
		remappers.Metric{
			DataType:    pmetric.MetricTypeGauge,
			Name:        "system.memory.used.pct",
			Timestamp:   timestamp,
			DoubleValue: &usedPercent,
		},
		remappers.Metric{
			DataType:    pmetric.MetricTypeGauge,
			Name:        "system.memory.actual.used.pct",
			Timestamp:   timestamp,
			DoubleValue: &actualUsedPercent,
		},
	)

	return nil
}
