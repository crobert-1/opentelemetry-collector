// Code generated by mdatagen. DO NOT EDIT.

package metadatatest

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/metric/metricdata/metricdatatest"

	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/scraper/scraperhelper/internal/metadata"
)

func TestSetupTelemetry(t *testing.T) {
	testTel := componenttest.NewTelemetry()
	tb, err := metadata.NewTelemetryBuilder(testTel.NewTelemetrySettings())
	require.NoError(t, err)
	defer tb.Shutdown()
	tb.RecordScraperErroredLogRecords(context.Background(), 1)
	tb.RecordScraperErroredMetricPoints(context.Background(), 1)
	tb.RecordScraperScrapedLogRecords(context.Background(), 1)
	tb.RecordScraperScrapedMetricPoints(context.Background(), 1)
	AssertEqualScraperErroredLogRecords(t, testTel,
		[]metricdata.DataPoint[int64]{{Value: 1}},
		metricdatatest.IgnoreTimestamp())
	AssertEqualScraperErroredMetricPoints(t, testTel,
		[]metricdata.DataPoint[int64]{{Value: 1}},
		metricdatatest.IgnoreTimestamp())
	AssertEqualScraperScrapedLogRecords(t, testTel,
		[]metricdata.DataPoint[int64]{{Value: 1}},
		metricdatatest.IgnoreTimestamp())
	AssertEqualScraperScrapedMetricPoints(t, testTel,
		[]metricdata.DataPoint[int64]{{Value: 1}},
		metricdatatest.IgnoreTimestamp())

	require.NoError(t, testTel.Shutdown(context.Background()))
}
