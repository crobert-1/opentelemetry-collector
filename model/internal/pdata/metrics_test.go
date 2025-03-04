// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pdata

import (
	"testing"

	gogoproto "github.com/gogo/protobuf/proto"
	"github.com/stretchr/testify/assert"
	goproto "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"

	otlpcommon "go.opentelemetry.io/collector/model/internal/data/protogen/common/v1"
	otlpmetrics "go.opentelemetry.io/collector/model/internal/data/protogen/metrics/v1"
	otlpresource "go.opentelemetry.io/collector/model/internal/data/protogen/resource/v1"
)

const (
	startTime = uint64(12578940000000012345)
	endTime   = uint64(12578940000000054321)
)

func TestMetricDataTypeString(t *testing.T) {
	assert.Equal(t, "None", MetricDataTypeNone.String())
	assert.Equal(t, "Gauge", MetricDataTypeGauge.String())
	assert.Equal(t, "Sum", MetricDataTypeSum.String())
	assert.Equal(t, "Histogram", MetricDataTypeHistogram.String())
	assert.Equal(t, "ExponentialHistogram", MetricDataTypeExponentialHistogram.String())
	assert.Equal(t, "Summary", MetricDataTypeSummary.String())
	assert.Equal(t, "", (MetricDataTypeSummary + 1).String())
}

func TestPointMetricValueTypeString(t *testing.T) {
	assert.Equal(t, "None", MetricValueTypeNone.String())
	assert.Equal(t, "Int", MetricValueTypeInt.String())
	assert.Equal(t, "Double", MetricValueTypeDouble.String())
	assert.Equal(t, "", (MetricValueTypeDouble + 1).String())
}

func TestResourceMetricsWireCompatibility(t *testing.T) {
	// This test verifies that OTLP ProtoBufs generated using goproto lib in
	// opentelemetry-proto repository OTLP ProtoBufs generated using gogoproto lib in
	// this repository are wire compatible.

	// Generate ResourceMetrics as pdata struct.
	metrics := generateTestResourceMetrics()

	// Marshal its underlying ProtoBuf to wire.
	wire1, err := gogoproto.Marshal(metrics.orig)
	assert.NoError(t, err)
	assert.NotNil(t, wire1)

	// Unmarshal from the wire to OTLP Protobuf in goproto's representation.
	var goprotoMessage emptypb.Empty
	err = goproto.Unmarshal(wire1, &goprotoMessage)
	assert.NoError(t, err)

	// Marshal to the wire again.
	wire2, err := goproto.Marshal(&goprotoMessage)
	assert.NoError(t, err)
	assert.NotNil(t, wire2)

	// Unmarshal from the wire into gogoproto's representation.
	var gogoprotoRM otlpmetrics.ResourceMetrics
	err = gogoproto.Unmarshal(wire2, &gogoprotoRM)
	assert.NoError(t, err)

	// Now compare that the original and final ProtoBuf messages are the same.
	// This proves that goproto and gogoproto marshaling/unmarshaling are wire compatible.
	assert.True(t, assert.EqualValues(t, metrics.orig, &gogoprotoRM))
}

func TestMetricCount(t *testing.T) {
	md := NewMetrics()
	assert.EqualValues(t, 0, md.MetricCount())

	rms := md.ResourceMetrics()
	rms.EnsureCapacity(3)
	rm := rms.AppendEmpty()
	assert.EqualValues(t, 0, md.MetricCount())

	ilm := rm.ScopeMetrics().AppendEmpty()
	assert.EqualValues(t, 0, md.MetricCount())

	ilm.Metrics().AppendEmpty()
	assert.EqualValues(t, 1, md.MetricCount())

	rms.AppendEmpty().ScopeMetrics().AppendEmpty()
	ilmm := rms.AppendEmpty().ScopeMetrics().AppendEmpty().Metrics()
	ilmm.EnsureCapacity(5)
	for i := 0; i < 5; i++ {
		ilmm.AppendEmpty()
	}
	// 5 + 1 (from rms.At(0) initialized first)
	assert.EqualValues(t, 6, md.MetricCount())
}

func TestMetricCountWithEmpty(t *testing.T) {
	assert.EqualValues(t, 0, generateMetricsEmptyResource().MetricCount())
	assert.EqualValues(t, 0, generateMetricsEmptyInstrumentation().MetricCount())
	assert.EqualValues(t, 1, generateMetricsEmptyMetrics().MetricCount())
}

func TestMetricAndDataPointCount(t *testing.T) {
	md := NewMetrics()
	dps := md.DataPointCount()
	assert.EqualValues(t, 0, dps)

	rms := md.ResourceMetrics()
	rms.AppendEmpty()
	dps = md.DataPointCount()
	assert.EqualValues(t, 0, dps)

	ilms := md.ResourceMetrics().At(0).ScopeMetrics()
	ilms.AppendEmpty()
	dps = md.DataPointCount()
	assert.EqualValues(t, 0, dps)

	ilms.At(0).Metrics().AppendEmpty()
	dps = md.DataPointCount()
	assert.EqualValues(t, 0, dps)
	ilms.At(0).Metrics().At(0).SetDataType(MetricDataTypeSum)
	intSum := ilms.At(0).Metrics().At(0).Sum()
	intSum.DataPoints().AppendEmpty()
	intSum.DataPoints().AppendEmpty()
	intSum.DataPoints().AppendEmpty()
	assert.EqualValues(t, 3, md.DataPointCount())

	md = NewMetrics()
	rms = md.ResourceMetrics()
	rms.EnsureCapacity(3)
	rms.AppendEmpty().ScopeMetrics().AppendEmpty().Metrics().AppendEmpty()
	rms.AppendEmpty().ScopeMetrics().AppendEmpty()
	rms.AppendEmpty().ScopeMetrics().AppendEmpty()
	ilms = rms.At(2).ScopeMetrics()
	ilm := ilms.At(0).Metrics()
	for i := 0; i < 5; i++ {
		ilm.AppendEmpty()
	}
	assert.EqualValues(t, 0, md.DataPointCount())

	ilm.At(0).SetDataType(MetricDataTypeGauge)
	ilm.At(0).Gauge().DataPoints().AppendEmpty()
	assert.EqualValues(t, 1, md.DataPointCount())

	ilm.At(1).SetDataType(MetricDataTypeSum)
	ilm.At(1).Sum().DataPoints().AppendEmpty()
	assert.EqualValues(t, 2, md.DataPointCount())

	ilm.At(2).SetDataType(MetricDataTypeHistogram)
	ilm.At(2).Histogram().DataPoints().AppendEmpty()
	assert.EqualValues(t, 3, md.DataPointCount())

	ilm.At(3).SetDataType(MetricDataTypeExponentialHistogram)
	ilm.At(3).ExponentialHistogram().DataPoints().AppendEmpty()
	assert.EqualValues(t, 4, md.DataPointCount())

	ilm.At(4).SetDataType(MetricDataTypeSummary)
	ilm.At(4).Summary().DataPoints().AppendEmpty()
	assert.EqualValues(t, 5, md.DataPointCount())
}

func TestDataPointCountWithEmpty(t *testing.T) {
	assert.EqualValues(t, 0, generateMetricsEmptyResource().DataPointCount())
	assert.EqualValues(t, 0, generateMetricsEmptyInstrumentation().DataPointCount())
	assert.EqualValues(t, 0, generateMetricsEmptyMetrics().DataPointCount())
	assert.EqualValues(t, 1, generateMetricsEmptyDataPoints().DataPointCount())
}

func TestDataPointCountWithNilDataPoints(t *testing.T) {
	metrics := NewMetrics()
	ilm := metrics.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty()
	doubleGauge := ilm.Metrics().AppendEmpty()
	doubleGauge.SetDataType(MetricDataTypeGauge)
	doubleHistogram := ilm.Metrics().AppendEmpty()
	doubleHistogram.SetDataType(MetricDataTypeHistogram)
	doubleSum := ilm.Metrics().AppendEmpty()
	doubleSum.SetDataType(MetricDataTypeSum)
	assert.EqualValues(t, 0, metrics.DataPointCount())
}

func TestHistogramWithNilSum(t *testing.T) {
	metrics := NewMetrics()
	ilm := metrics.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty()
	histo := ilm.Metrics().AppendEmpty()
	histo.SetDataType(MetricDataTypeHistogram)
	histogramDataPoints := histo.Histogram().DataPoints()
	histogramDataPoints.AppendEmpty()
	dest := ilm.Metrics().AppendEmpty()
	histo.CopyTo(dest)
	assert.EqualValues(t, histo, dest)
}

func TestHistogramWithValidSum(t *testing.T) {
	metrics := NewMetrics()
	ilm := metrics.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty()
	histo := ilm.Metrics().AppendEmpty()
	histo.SetDataType(MetricDataTypeHistogram)
	histogramDataPoints := histo.Histogram().DataPoints()
	histogramDataPoints.AppendEmpty()
	histogramDataPoints.At(0).SetSum(10)
	dest := ilm.Metrics().AppendEmpty()
	histo.CopyTo(dest)
	assert.EqualValues(t, histo, dest)
}

func TestMetricsMoveTo(t *testing.T) {
	metrics := NewMetrics()
	fillTestResourceMetricsSlice(metrics.ResourceMetrics())
	dest := NewMetrics()
	metrics.MoveTo(dest)
	assert.EqualValues(t, NewMetrics(), metrics)
	assert.EqualValues(t, generateTestResourceMetricsSlice(), dest.ResourceMetrics())
}

func TestOtlpToInternalReadOnly(t *testing.T) {
	md := Metrics{orig: &otlpmetrics.MetricsData{
		ResourceMetrics: []*otlpmetrics.ResourceMetrics{
			{
				Resource: generateTestProtoResource(),
				ScopeMetrics: []*otlpmetrics.ScopeMetrics{
					{
						Scope:   generateTestProtoInstrumentationScope(),
						Metrics: []*otlpmetrics.Metric{generateTestProtoGaugeMetric(), generateTestProtoSumMetric(), generateTestProtoDoubleHistogramMetric()},
					},
				},
			},
		},
	}}
	resourceMetrics := md.ResourceMetrics()
	assert.EqualValues(t, 1, resourceMetrics.Len())

	resourceMetric := resourceMetrics.At(0)
	assert.EqualValues(t, NewMapFromRaw(map[string]interface{}{
		"string": "string-resource",
	}), resourceMetric.Resource().Attributes())
	metrics := resourceMetric.ScopeMetrics().At(0).Metrics()
	assert.EqualValues(t, 3, metrics.Len())

	// Check int64 metric
	metricInt := metrics.At(0)
	assert.EqualValues(t, "my_metric_int", metricInt.Name())
	assert.EqualValues(t, "My metric", metricInt.Description())
	assert.EqualValues(t, "ms", metricInt.Unit())
	assert.EqualValues(t, MetricDataTypeGauge, metricInt.DataType())
	gaugeDataPoints := metricInt.Gauge().DataPoints()
	assert.EqualValues(t, 2, gaugeDataPoints.Len())
	// First point
	assert.EqualValues(t, startTime, gaugeDataPoints.At(0).StartTimestamp())
	assert.EqualValues(t, endTime, gaugeDataPoints.At(0).Timestamp())
	assert.EqualValues(t, 123.1, gaugeDataPoints.At(0).DoubleVal())
	assert.EqualValues(t, NewMapFromRaw(map[string]interface{}{"key0": "value0"}), gaugeDataPoints.At(0).Attributes())
	// Second point
	assert.EqualValues(t, startTime, gaugeDataPoints.At(1).StartTimestamp())
	assert.EqualValues(t, endTime, gaugeDataPoints.At(1).Timestamp())
	assert.EqualValues(t, 456.1, gaugeDataPoints.At(1).DoubleVal())
	assert.EqualValues(t, NewMapFromRaw(map[string]interface{}{"key1": "value1"}), gaugeDataPoints.At(1).Attributes())

	// Check double metric
	metricDouble := metrics.At(1)
	assert.EqualValues(t, "my_metric_double", metricDouble.Name())
	assert.EqualValues(t, "My metric", metricDouble.Description())
	assert.EqualValues(t, "ms", metricDouble.Unit())
	assert.EqualValues(t, MetricDataTypeSum, metricDouble.DataType())
	dsd := metricDouble.Sum()
	assert.EqualValues(t, MetricAggregationTemporalityCumulative, dsd.AggregationTemporality())
	sumDataPoints := dsd.DataPoints()
	assert.EqualValues(t, 2, sumDataPoints.Len())
	// First point
	assert.EqualValues(t, startTime, sumDataPoints.At(0).StartTimestamp())
	assert.EqualValues(t, endTime, sumDataPoints.At(0).Timestamp())
	assert.EqualValues(t, 123.1, sumDataPoints.At(0).DoubleVal())
	assert.EqualValues(t, NewMapFromRaw(map[string]interface{}{"key0": "value0"}), sumDataPoints.At(0).Attributes())
	// Second point
	assert.EqualValues(t, startTime, sumDataPoints.At(1).StartTimestamp())
	assert.EqualValues(t, endTime, sumDataPoints.At(1).Timestamp())
	assert.EqualValues(t, 456.1, sumDataPoints.At(1).DoubleVal())
	assert.EqualValues(t, NewMapFromRaw(map[string]interface{}{"key1": "value1"}), sumDataPoints.At(1).Attributes())

	// Check histogram metric
	metricHistogram := metrics.At(2)
	assert.EqualValues(t, "my_metric_histogram", metricHistogram.Name())
	assert.EqualValues(t, "My metric", metricHistogram.Description())
	assert.EqualValues(t, "ms", metricHistogram.Unit())
	assert.EqualValues(t, MetricDataTypeHistogram, metricHistogram.DataType())
	dhd := metricHistogram.Histogram()
	assert.EqualValues(t, MetricAggregationTemporalityDelta, dhd.AggregationTemporality())
	histogramDataPoints := dhd.DataPoints()
	assert.EqualValues(t, 2, histogramDataPoints.Len())
	// First point
	assert.EqualValues(t, startTime, histogramDataPoints.At(0).StartTimestamp())
	assert.EqualValues(t, endTime, histogramDataPoints.At(0).Timestamp())
	assert.EqualValues(t, []float64{1, 2}, histogramDataPoints.At(0).ExplicitBounds())
	assert.EqualValues(t, NewMapFromRaw(map[string]interface{}{"key0": "value0"}), histogramDataPoints.At(0).Attributes())
	assert.EqualValues(t, []uint64{10, 15, 1}, histogramDataPoints.At(0).BucketCounts())
	// Second point
	assert.EqualValues(t, startTime, histogramDataPoints.At(1).StartTimestamp())
	assert.EqualValues(t, endTime, histogramDataPoints.At(1).Timestamp())
	assert.EqualValues(t, []float64{1}, histogramDataPoints.At(1).ExplicitBounds())
	assert.EqualValues(t, NewMapFromRaw(map[string]interface{}{"key1": "value1"}), histogramDataPoints.At(1).Attributes())
	assert.EqualValues(t, []uint64{10, 1}, histogramDataPoints.At(1).BucketCounts())
}

func TestOtlpToFromInternalReadOnly(t *testing.T) {
	md := MetricsFromOtlp(&otlpmetrics.MetricsData{
		ResourceMetrics: []*otlpmetrics.ResourceMetrics{
			{
				Resource: generateTestProtoResource(),
				ScopeMetrics: []*otlpmetrics.ScopeMetrics{
					{
						Scope:   generateTestProtoInstrumentationScope(),
						Metrics: []*otlpmetrics.Metric{generateTestProtoGaugeMetric(), generateTestProtoSumMetric(), generateTestProtoDoubleHistogramMetric()},
					},
				},
			},
		},
	})
	// Test that nothing changed
	assert.EqualValues(t, &otlpmetrics.MetricsData{
		ResourceMetrics: []*otlpmetrics.ResourceMetrics{
			{
				Resource: generateTestProtoResource(),
				ScopeMetrics: []*otlpmetrics.ScopeMetrics{
					{
						Scope:   generateTestProtoInstrumentationScope(),
						Metrics: []*otlpmetrics.Metric{generateTestProtoGaugeMetric(), generateTestProtoSumMetric(), generateTestProtoDoubleHistogramMetric()},
					},
				},
			},
		},
	}, MetricsToOtlp(md))
}

func TestOtlpToFromInternalGaugeMutating(t *testing.T) {
	newAttributes := NewMapFromRaw(map[string]interface{}{"k": "v"})

	md := MetricsFromOtlp(&otlpmetrics.MetricsData{
		ResourceMetrics: []*otlpmetrics.ResourceMetrics{
			{
				Resource: generateTestProtoResource(),
				ScopeMetrics: []*otlpmetrics.ScopeMetrics{
					{
						Scope:   generateTestProtoInstrumentationScope(),
						Metrics: []*otlpmetrics.Metric{generateTestProtoGaugeMetric()},
					},
				},
			},
		},
	})
	resourceMetrics := md.ResourceMetrics()
	metric := resourceMetrics.At(0).ScopeMetrics().At(0).Metrics().At(0)
	// Mutate MetricDescriptor
	metric.SetName("new_my_metric_int")
	assert.EqualValues(t, "new_my_metric_int", metric.Name())
	metric.SetDescription("My new metric")
	assert.EqualValues(t, "My new metric", metric.Description())
	metric.SetUnit("1")
	assert.EqualValues(t, "1", metric.Unit())
	// Mutate DataPoints
	igd := metric.Gauge()
	assert.EqualValues(t, 2, igd.DataPoints().Len())
	metric.SetDataType(MetricDataTypeGauge)
	gaugeDataPoints := metric.Gauge().DataPoints()
	gaugeDataPoints.AppendEmpty()
	assert.EqualValues(t, 1, gaugeDataPoints.Len())
	gaugeDataPoints.At(0).SetStartTimestamp(Timestamp(startTime + 1))
	assert.EqualValues(t, startTime+1, gaugeDataPoints.At(0).StartTimestamp())
	gaugeDataPoints.At(0).SetTimestamp(Timestamp(endTime + 1))
	assert.EqualValues(t, endTime+1, gaugeDataPoints.At(0).Timestamp())
	gaugeDataPoints.At(0).SetDoubleVal(124.1)
	assert.EqualValues(t, 124.1, gaugeDataPoints.At(0).DoubleVal())
	gaugeDataPoints.At(0).Attributes().Remove("key0")
	gaugeDataPoints.At(0).Attributes().UpsertString("k", "v")
	assert.EqualValues(t, newAttributes, gaugeDataPoints.At(0).Attributes())

	// Test that everything is updated.
	assert.EqualValues(t, &otlpmetrics.MetricsData{
		ResourceMetrics: []*otlpmetrics.ResourceMetrics{
			{
				Resource: generateTestProtoResource(),
				ScopeMetrics: []*otlpmetrics.ScopeMetrics{
					{
						Scope: generateTestProtoInstrumentationScope(),
						Metrics: []*otlpmetrics.Metric{
							{
								Name:        "new_my_metric_int",
								Description: "My new metric",
								Unit:        "1",
								Data: &otlpmetrics.Metric_Gauge{
									Gauge: &otlpmetrics.Gauge{
										DataPoints: []*otlpmetrics.NumberDataPoint{
											{
												Attributes: []otlpcommon.KeyValue{
													{
														Key:   "k",
														Value: otlpcommon.AnyValue{Value: &otlpcommon.AnyValue_StringValue{StringValue: "v"}},
													},
												},
												StartTimeUnixNano: startTime + 1,
												TimeUnixNano:      endTime + 1,
												Value: &otlpmetrics.NumberDataPoint_AsDouble{
													AsDouble: 124.1,
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}, MetricsToOtlp(md))
}

func TestOtlpToFromInternalSumMutating(t *testing.T) {
	newAttributes := NewMapFromRaw(map[string]interface{}{"k": "v"})

	md := MetricsFromOtlp(&otlpmetrics.MetricsData{
		ResourceMetrics: []*otlpmetrics.ResourceMetrics{
			{
				Resource: generateTestProtoResource(),
				ScopeMetrics: []*otlpmetrics.ScopeMetrics{
					{
						Scope:   generateTestProtoInstrumentationScope(),
						Metrics: []*otlpmetrics.Metric{generateTestProtoSumMetric()},
					},
				},
			},
		},
	})
	resourceMetrics := md.ResourceMetrics()
	metric := resourceMetrics.At(0).ScopeMetrics().At(0).Metrics().At(0)
	// Mutate MetricDescriptor
	metric.SetName("new_my_metric_double")
	assert.EqualValues(t, "new_my_metric_double", metric.Name())
	metric.SetDescription("My new metric")
	assert.EqualValues(t, "My new metric", metric.Description())
	metric.SetUnit("1")
	assert.EqualValues(t, "1", metric.Unit())
	// Mutate DataPoints
	dsd := metric.Sum()
	assert.EqualValues(t, 2, dsd.DataPoints().Len())
	metric.SetDataType(MetricDataTypeSum)
	doubleDataPoints := metric.Sum().DataPoints()
	metric.Sum().SetAggregationTemporality(MetricAggregationTemporalityCumulative)
	doubleDataPoints.AppendEmpty()
	assert.EqualValues(t, 1, doubleDataPoints.Len())
	doubleDataPoints.At(0).SetStartTimestamp(Timestamp(startTime + 1))
	assert.EqualValues(t, startTime+1, doubleDataPoints.At(0).StartTimestamp())
	doubleDataPoints.At(0).SetTimestamp(Timestamp(endTime + 1))
	assert.EqualValues(t, endTime+1, doubleDataPoints.At(0).Timestamp())
	doubleDataPoints.At(0).SetDoubleVal(124.1)
	assert.EqualValues(t, 124.1, doubleDataPoints.At(0).DoubleVal())
	doubleDataPoints.At(0).Attributes().Remove("key0")
	doubleDataPoints.At(0).Attributes().UpsertString("k", "v")
	assert.EqualValues(t, newAttributes, doubleDataPoints.At(0).Attributes())

	// Test that everything is updated.
	assert.EqualValues(t, &otlpmetrics.MetricsData{
		ResourceMetrics: []*otlpmetrics.ResourceMetrics{
			{
				Resource: generateTestProtoResource(),
				ScopeMetrics: []*otlpmetrics.ScopeMetrics{
					{
						Scope: generateTestProtoInstrumentationScope(),
						Metrics: []*otlpmetrics.Metric{
							{
								Name:        "new_my_metric_double",
								Description: "My new metric",
								Unit:        "1",
								Data: &otlpmetrics.Metric_Sum{
									Sum: &otlpmetrics.Sum{
										AggregationTemporality: otlpmetrics.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE,
										DataPoints: []*otlpmetrics.NumberDataPoint{
											{
												Attributes: []otlpcommon.KeyValue{
													{
														Key:   "k",
														Value: otlpcommon.AnyValue{Value: &otlpcommon.AnyValue_StringValue{StringValue: "v"}},
													},
												},
												StartTimeUnixNano: startTime + 1,
												TimeUnixNano:      endTime + 1,
												Value: &otlpmetrics.NumberDataPoint_AsDouble{
													AsDouble: 124.1,
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}, MetricsToOtlp(md))
}

func TestOtlpToFromInternalHistogramMutating(t *testing.T) {
	newAttributes := NewMapFromRaw(map[string]interface{}{"k": "v"})

	md := MetricsFromOtlp(&otlpmetrics.MetricsData{
		ResourceMetrics: []*otlpmetrics.ResourceMetrics{
			{
				Resource: generateTestProtoResource(),
				ScopeMetrics: []*otlpmetrics.ScopeMetrics{
					{
						Scope:   generateTestProtoInstrumentationScope(),
						Metrics: []*otlpmetrics.Metric{generateTestProtoDoubleHistogramMetric()},
					},
				},
			},
		},
	})
	resourceMetrics := md.ResourceMetrics()
	metric := resourceMetrics.At(0).ScopeMetrics().At(0).Metrics().At(0)
	// Mutate MetricDescriptor
	metric.SetName("new_my_metric_histogram")
	assert.EqualValues(t, "new_my_metric_histogram", metric.Name())
	metric.SetDescription("My new metric")
	assert.EqualValues(t, "My new metric", metric.Description())
	metric.SetUnit("1")
	assert.EqualValues(t, "1", metric.Unit())
	// Mutate DataPoints
	dhd := metric.Histogram()
	assert.EqualValues(t, 2, dhd.DataPoints().Len())
	metric.SetDataType(MetricDataTypeHistogram)
	metric.Histogram().SetAggregationTemporality(MetricAggregationTemporalityDelta)
	histogramDataPoints := metric.Histogram().DataPoints()
	histogramDataPoints.AppendEmpty()
	assert.EqualValues(t, 1, histogramDataPoints.Len())
	histogramDataPoints.At(0).SetStartTimestamp(Timestamp(startTime + 1))
	assert.EqualValues(t, startTime+1, histogramDataPoints.At(0).StartTimestamp())
	histogramDataPoints.At(0).SetTimestamp(Timestamp(endTime + 1))
	assert.EqualValues(t, endTime+1, histogramDataPoints.At(0).Timestamp())
	histogramDataPoints.At(0).Attributes().Remove("key0")
	histogramDataPoints.At(0).Attributes().UpsertString("k", "v")
	assert.EqualValues(t, newAttributes, histogramDataPoints.At(0).Attributes())
	histogramDataPoints.At(0).SetExplicitBounds([]float64{1})
	assert.EqualValues(t, []float64{1}, histogramDataPoints.At(0).ExplicitBounds())
	histogramDataPoints.At(0).SetBucketCounts([]uint64{21, 32})
	// Test that everything is updated.
	assert.EqualValues(t, &otlpmetrics.MetricsData{
		ResourceMetrics: []*otlpmetrics.ResourceMetrics{
			{
				Resource: generateTestProtoResource(),
				ScopeMetrics: []*otlpmetrics.ScopeMetrics{
					{
						Scope: generateTestProtoInstrumentationScope(),
						Metrics: []*otlpmetrics.Metric{
							{
								Name:        "new_my_metric_histogram",
								Description: "My new metric",
								Unit:        "1",
								Data: &otlpmetrics.Metric_Histogram{
									Histogram: &otlpmetrics.Histogram{
										AggregationTemporality: otlpmetrics.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA,
										DataPoints: []*otlpmetrics.HistogramDataPoint{
											{
												Attributes: []otlpcommon.KeyValue{
													{
														Key:   "k",
														Value: otlpcommon.AnyValue{Value: &otlpcommon.AnyValue_StringValue{StringValue: "v"}},
													},
												},
												StartTimeUnixNano: startTime + 1,
												TimeUnixNano:      endTime + 1,
												BucketCounts:      []uint64{21, 32},
												ExplicitBounds:    []float64{1},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}, MetricsToOtlp(md))
}

func TestOtlpToFromInternalExponentialHistogramMutating(t *testing.T) {
	newAttributes := NewMapFromRaw(map[string]interface{}{"k": "v"})

	md := MetricsFromOtlp(&otlpmetrics.MetricsData{
		ResourceMetrics: []*otlpmetrics.ResourceMetrics{
			{
				Resource: generateTestProtoResource(),
				ScopeMetrics: []*otlpmetrics.ScopeMetrics{
					{
						Scope:   generateTestProtoInstrumentationScope(),
						Metrics: []*otlpmetrics.Metric{generateTestProtoDoubleHistogramMetric()},
					},
				},
			},
		},
	})
	resourceMetrics := md.ResourceMetrics()
	metric := resourceMetrics.At(0).ScopeMetrics().At(0).Metrics().At(0)
	// Mutate MetricDescriptor
	metric.SetName("new_my_metric_exponential_histogram")
	assert.EqualValues(t, "new_my_metric_exponential_histogram", metric.Name())
	metric.SetDescription("My new metric")
	assert.EqualValues(t, "My new metric", metric.Description())
	metric.SetUnit("1")
	assert.EqualValues(t, "1", metric.Unit())
	// Mutate DataPoints
	dhd := metric.Histogram()
	assert.EqualValues(t, 2, dhd.DataPoints().Len())
	metric.SetDataType(MetricDataTypeExponentialHistogram)
	metric.ExponentialHistogram().SetAggregationTemporality(MetricAggregationTemporalityDelta)
	histogramDataPoints := metric.ExponentialHistogram().DataPoints()
	histogramDataPoints.AppendEmpty()
	assert.EqualValues(t, 1, histogramDataPoints.Len())
	histogramDataPoints.At(0).SetStartTimestamp(Timestamp(startTime + 1))
	assert.EqualValues(t, startTime+1, histogramDataPoints.At(0).StartTimestamp())
	histogramDataPoints.At(0).SetTimestamp(Timestamp(endTime + 1))
	assert.EqualValues(t, endTime+1, histogramDataPoints.At(0).Timestamp())
	histogramDataPoints.At(0).Attributes().Remove("key0")
	histogramDataPoints.At(0).Attributes().UpsertString("k", "v")
	assert.EqualValues(t, newAttributes, histogramDataPoints.At(0).Attributes())
	// Test that everything is updated.
	assert.EqualValues(t, &otlpmetrics.MetricsData{
		ResourceMetrics: []*otlpmetrics.ResourceMetrics{
			{
				Resource: generateTestProtoResource(),
				ScopeMetrics: []*otlpmetrics.ScopeMetrics{
					{
						Scope: generateTestProtoInstrumentationScope(),
						Metrics: []*otlpmetrics.Metric{
							{
								Name:        "new_my_metric_exponential_histogram",
								Description: "My new metric",
								Unit:        "1",
								Data: &otlpmetrics.Metric_ExponentialHistogram{
									ExponentialHistogram: &otlpmetrics.ExponentialHistogram{
										AggregationTemporality: otlpmetrics.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA,
										DataPoints: []*otlpmetrics.ExponentialHistogramDataPoint{
											{
												Attributes: []otlpcommon.KeyValue{
													{
														Key:   "k",
														Value: otlpcommon.AnyValue{Value: &otlpcommon.AnyValue_StringValue{StringValue: "v"}},
													},
												},
												StartTimeUnixNano: startTime + 1,
												TimeUnixNano:      endTime + 1,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}, MetricsToOtlp(md))
}

func TestMetricsClone(t *testing.T) {
	metrics := NewMetrics()
	fillTestResourceMetricsSlice(metrics.ResourceMetrics())
	assert.EqualValues(t, metrics, metrics.Clone())
}

func TestMetricsDataPointFlags(t *testing.T) {
	gauge := generateTestGauge()

	gauge.DataPoints().At(0).SetFlags(NewMetricDataPointFlags())
	assert.True(t, gauge.DataPoints().At(0).Flags() == MetricDataPointFlagsNone)
	assert.False(t, gauge.DataPoints().At(0).Flags().HasFlag(MetricDataPointFlagNoRecordedValue))
	assert.Equal(t, "FLAG_NONE", gauge.DataPoints().At(0).Flags().String())

	gauge.DataPoints().At(0).SetFlags(NewMetricDataPointFlags(MetricDataPointFlagNoRecordedValue))
	assert.False(t, gauge.DataPoints().At(0).Flags() == MetricDataPointFlagsNone)
	assert.True(t, gauge.DataPoints().At(0).Flags().HasFlag(MetricDataPointFlagNoRecordedValue))
	assert.Equal(t, "FLAG_NO_RECORDED_VALUE", gauge.DataPoints().At(0).Flags().String())
}

func BenchmarkMetricsClone(b *testing.B) {
	metrics := NewMetrics()
	fillTestResourceMetricsSlice(metrics.ResourceMetrics())
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		clone := metrics.Clone()
		if clone.ResourceMetrics().Len() != metrics.ResourceMetrics().Len() {
			b.Fail()
		}
	}
}

func BenchmarkOtlpToFromInternal_PassThrough(b *testing.B) {
	req := &otlpmetrics.MetricsData{
		ResourceMetrics: []*otlpmetrics.ResourceMetrics{
			{
				Resource: generateTestProtoResource(),
				ScopeMetrics: []*otlpmetrics.ScopeMetrics{
					{
						Scope:   generateTestProtoInstrumentationScope(),
						Metrics: []*otlpmetrics.Metric{generateTestProtoGaugeMetric(), generateTestProtoSumMetric(), generateTestProtoDoubleHistogramMetric()},
					},
				},
			},
		},
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		md := MetricsFromOtlp(req)
		newReq := MetricsToOtlp(md)
		if len(req.ResourceMetrics) != len(newReq.ResourceMetrics) {
			b.Fail()
		}
	}
}

func BenchmarkOtlpToFromInternal_Gauge_MutateOneLabel(b *testing.B) {
	req := &otlpmetrics.MetricsData{
		ResourceMetrics: []*otlpmetrics.ResourceMetrics{
			{
				Resource: generateTestProtoResource(),
				ScopeMetrics: []*otlpmetrics.ScopeMetrics{
					{
						Scope:   generateTestProtoInstrumentationScope(),
						Metrics: []*otlpmetrics.Metric{generateTestProtoGaugeMetric()},
					},
				},
			},
		},
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		md := MetricsFromOtlp(req)
		md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0).Gauge().DataPoints().At(0).Attributes().UpsertString("key0", "value2")
		newReq := MetricsToOtlp(md)
		if len(req.ResourceMetrics) != len(newReq.ResourceMetrics) {
			b.Fail()
		}
	}
}

func BenchmarkOtlpToFromInternal_Sum_MutateOneLabel(b *testing.B) {
	req := &otlpmetrics.MetricsData{
		ResourceMetrics: []*otlpmetrics.ResourceMetrics{
			{
				Resource: generateTestProtoResource(),
				ScopeMetrics: []*otlpmetrics.ScopeMetrics{
					{
						Scope:   generateTestProtoInstrumentationScope(),
						Metrics: []*otlpmetrics.Metric{generateTestProtoSumMetric()},
					},
				},
			},
		},
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		md := MetricsFromOtlp(req)
		md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0).Sum().DataPoints().At(0).Attributes().UpsertString("key0", "value2")
		newReq := MetricsToOtlp(md)
		if len(req.ResourceMetrics) != len(newReq.ResourceMetrics) {
			b.Fail()
		}
	}
}

func BenchmarkOtlpToFromInternal_HistogramPoints_MutateOneLabel(b *testing.B) {
	req := &otlpmetrics.MetricsData{
		ResourceMetrics: []*otlpmetrics.ResourceMetrics{
			{
				Resource: generateTestProtoResource(),
				ScopeMetrics: []*otlpmetrics.ScopeMetrics{
					{
						Scope:   generateTestProtoInstrumentationScope(),
						Metrics: []*otlpmetrics.Metric{generateTestProtoDoubleHistogramMetric()},
					},
				},
			},
		},
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		md := MetricsFromOtlp(req)
		md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0).Histogram().DataPoints().At(0).Attributes().UpsertString("key0", "value2")
		newReq := MetricsToOtlp(md)
		if len(req.ResourceMetrics) != len(newReq.ResourceMetrics) {
			b.Fail()
		}
	}
}

func generateTestProtoResource() otlpresource.Resource {
	return otlpresource.Resource{
		Attributes: []otlpcommon.KeyValue{
			{
				Key:   "string",
				Value: otlpcommon.AnyValue{Value: &otlpcommon.AnyValue_StringValue{StringValue: "string-resource"}},
			},
		},
	}
}

func generateTestProtoInstrumentationScope() otlpcommon.InstrumentationScope {
	return otlpcommon.InstrumentationScope{
		Name:    "test",
		Version: "",
	}
}

func generateTestProtoGaugeMetric() *otlpmetrics.Metric {
	return &otlpmetrics.Metric{
		Name:        "my_metric_int",
		Description: "My metric",
		Unit:        "ms",
		Data: &otlpmetrics.Metric_Gauge{
			Gauge: &otlpmetrics.Gauge{
				DataPoints: []*otlpmetrics.NumberDataPoint{
					{
						Attributes: []otlpcommon.KeyValue{
							{
								Key:   "key0",
								Value: otlpcommon.AnyValue{Value: &otlpcommon.AnyValue_StringValue{StringValue: "value0"}},
							},
						},
						StartTimeUnixNano: startTime,
						TimeUnixNano:      endTime,
						Value: &otlpmetrics.NumberDataPoint_AsDouble{
							AsDouble: 123.1,
						},
					},
					{
						Attributes: []otlpcommon.KeyValue{
							{
								Key:   "key1",
								Value: otlpcommon.AnyValue{Value: &otlpcommon.AnyValue_StringValue{StringValue: "value1"}},
							},
						},
						StartTimeUnixNano: startTime,
						TimeUnixNano:      endTime,
						Value: &otlpmetrics.NumberDataPoint_AsDouble{
							AsDouble: 456.1,
						},
					},
				},
			},
		},
	}
}
func generateTestProtoSumMetric() *otlpmetrics.Metric {
	return &otlpmetrics.Metric{
		Name:        "my_metric_double",
		Description: "My metric",
		Unit:        "ms",
		Data: &otlpmetrics.Metric_Sum{
			Sum: &otlpmetrics.Sum{
				AggregationTemporality: otlpmetrics.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE,
				DataPoints: []*otlpmetrics.NumberDataPoint{
					{
						Attributes: []otlpcommon.KeyValue{
							{
								Key:   "key0",
								Value: otlpcommon.AnyValue{Value: &otlpcommon.AnyValue_StringValue{StringValue: "value0"}},
							},
						},
						StartTimeUnixNano: startTime,
						TimeUnixNano:      endTime,
						Value: &otlpmetrics.NumberDataPoint_AsDouble{
							AsDouble: 123.1,
						},
					},
					{
						Attributes: []otlpcommon.KeyValue{
							{
								Key:   "key1",
								Value: otlpcommon.AnyValue{Value: &otlpcommon.AnyValue_StringValue{StringValue: "value1"}},
							},
						},
						StartTimeUnixNano: startTime,
						TimeUnixNano:      endTime,
						Value: &otlpmetrics.NumberDataPoint_AsDouble{
							AsDouble: 456.1,
						},
					},
				},
			},
		},
	}
}

func generateTestProtoDoubleHistogramMetric() *otlpmetrics.Metric {
	return &otlpmetrics.Metric{
		Name:        "my_metric_histogram",
		Description: "My metric",
		Unit:        "ms",
		Data: &otlpmetrics.Metric_Histogram{
			Histogram: &otlpmetrics.Histogram{
				AggregationTemporality: otlpmetrics.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA,
				DataPoints: []*otlpmetrics.HistogramDataPoint{
					{
						Attributes: []otlpcommon.KeyValue{
							{
								Key:   "key0",
								Value: otlpcommon.AnyValue{Value: &otlpcommon.AnyValue_StringValue{StringValue: "value0"}},
							},
						},
						StartTimeUnixNano: startTime,
						TimeUnixNano:      endTime,
						BucketCounts:      []uint64{10, 15, 1},
						ExplicitBounds:    []float64{1, 2},
					},
					{
						Attributes: []otlpcommon.KeyValue{
							{
								Key:   "key1",
								Value: otlpcommon.AnyValue{Value: &otlpcommon.AnyValue_StringValue{StringValue: "value1"}},
							},
						},
						StartTimeUnixNano: startTime,
						TimeUnixNano:      endTime,
						BucketCounts:      []uint64{10, 1},
						ExplicitBounds:    []float64{1},
					},
				},
			},
		},
	}
}

func generateMetricsEmptyResource() Metrics {
	return Metrics{orig: &otlpmetrics.MetricsData{
		ResourceMetrics: []*otlpmetrics.ResourceMetrics{{}},
	}}
}

func generateMetricsEmptyInstrumentation() Metrics {
	return Metrics{orig: &otlpmetrics.MetricsData{
		ResourceMetrics: []*otlpmetrics.ResourceMetrics{
			{
				ScopeMetrics: []*otlpmetrics.ScopeMetrics{{}},
			},
		},
	}}
}

func generateMetricsEmptyMetrics() Metrics {
	return Metrics{orig: &otlpmetrics.MetricsData{
		ResourceMetrics: []*otlpmetrics.ResourceMetrics{
			{
				ScopeMetrics: []*otlpmetrics.ScopeMetrics{
					{
						Metrics: []*otlpmetrics.Metric{{}},
					},
				},
			},
		},
	}}
}

func generateMetricsEmptyDataPoints() Metrics {
	return Metrics{orig: &otlpmetrics.MetricsData{
		ResourceMetrics: []*otlpmetrics.ResourceMetrics{
			{
				ScopeMetrics: []*otlpmetrics.ScopeMetrics{
					{
						Metrics: []*otlpmetrics.Metric{
							{
								Data: &otlpmetrics.Metric_Gauge{
									Gauge: &otlpmetrics.Gauge{
										DataPoints: []*otlpmetrics.NumberDataPoint{
											{},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}}
}
