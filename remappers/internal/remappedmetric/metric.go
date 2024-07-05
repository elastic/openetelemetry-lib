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

package remappedmetric

import (
	"github.com/elastic/opentelemetry-lib/remappers/common"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

const (
	// minAttributeCapacity is the capacity allocated to the datapoint
	// attributes to prevent reallocation.
	minAttributeCapacity = 10
)

// Metric is a simplified representation of a remapped OTel metric.
type Metric struct {
	IntValue       *int64
	DoubleValue    *float64
	Name           string
	Timestamp      pcommon.Timestamp
	StartTimestamp pcommon.Timestamp
	DataType       pmetric.MetricType
}

// Valid returns true if the metric is valid and set properly. A
// metric is properly set if the value and the timestamp are set.
// In addition, only gauge and sum metric are considered valid
// as these are the only two currently supported metric type.
func (m *Metric) Valid() bool {
	if m == nil {
		return false
	}
	if m.Name == "" {
		return false
	}
	if m.IntValue == nil && m.DoubleValue == nil {
		return false
	}
	if m.Timestamp == 0 {
		return false
	}
	switch m.DataType {
	case pmetric.MetricTypeGauge, pmetric.MetricTypeSum:
		return true
	}
	return false
}

// Add adds a list of remapped OTel metric to the give MetricSlice.
func Add(
	ms pmetric.MetricSlice,
	mutator func(dp pmetric.NumberDataPoint),
	metrics ...Metric,
) {
	ms.EnsureCapacity(ms.Len() + len(metrics))

	for _, metric := range metrics {

		if !metric.Valid() {
			continue
		}

		m := ms.AppendEmpty()
		m.SetName(metric.Name)

		var dp pmetric.NumberDataPoint
		switch metric.DataType {
		case pmetric.MetricTypeGauge:
			dp = m.SetEmptyGauge().DataPoints().AppendEmpty()
		case pmetric.MetricTypeSum:
			dp = m.SetEmptySum().DataPoints().AppendEmpty()
		}

		if metric.IntValue != nil {
			dp.SetIntValue(*metric.IntValue)
		} else if metric.DoubleValue != nil {
			dp.SetDoubleValue(*metric.DoubleValue)
		}

		dp.SetTimestamp(metric.Timestamp)
		if metric.StartTimestamp != 0 {
			dp.SetStartTimestamp(metric.StartTimestamp)
		}

		dp.Attributes().EnsureCapacity(minAttributeCapacity)
		dp.Attributes().PutBool(common.OTelRemappedLabel, true)
		mutator(dp)
	}
}
