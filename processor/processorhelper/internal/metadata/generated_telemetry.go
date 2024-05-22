// Code generated by mdatagen. DO NOT EDIT.

package metadata

import (
	"errors"

	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/collector/component"
)

func Meter(settings component.TelemetrySettings) metric.Meter {
	return settings.MeterProvider.Meter("go.opentelemetry.io/collector/processor/processorhelper")
}

func Tracer(settings component.TelemetrySettings) trace.Tracer {
	return settings.TracerProvider.Tracer("go.opentelemetry.io/collector/processor/processorhelper")
}

// TelemetryBuilder provides an interface for components to report telemetry
// as defined in metadata and user config.
type TelemetryBuilder struct {
	ProcessorAcceptedLogRecords   metric.Int64Counter
	ProcessorAcceptedMetricPoints metric.Int64Counter
	ProcessorAcceptedSpans        metric.Int64Counter
	ProcessorDroppedLogRecords    metric.Int64Counter
	ProcessorDroppedMetricPoints  metric.Int64Counter
	ProcessorDroppedSpans         metric.Int64Counter
	ProcessorRefusedLogRecords    metric.Int64Counter
	ProcessorRefusedMetricPoints  metric.Int64Counter
	ProcessorRefusedSpans         metric.Int64Counter
}

// telemetryBuilderOption applies changes to default builder.
type telemetryBuilderOption func(*TelemetryBuilder)

// NewTelemetryBuilder provides a struct with methods to update all internal telemetry
// for a component
func NewTelemetryBuilder(settings component.TelemetrySettings, options ...telemetryBuilderOption) (*TelemetryBuilder, error) {
	builder := TelemetryBuilder{}
	for _, op := range options {
		op(&builder)
	}
	var err, errs error
	meter := Meter(settings)
	builder.ProcessorAcceptedLogRecords, err = meter.Int64Counter(
		"processor_accepted_log_records",
		metric.WithDescription("Number of log records successfully pushed into the next component in the pipeline."),
		metric.WithUnit("1"),
	)
	errs = errors.Join(errs, err)
	builder.ProcessorAcceptedMetricPoints, err = meter.Int64Counter(
		"processor_accepted_metric_points",
		metric.WithDescription("Number of metric points successfully pushed into the next component in the pipeline."),
		metric.WithUnit("1"),
	)
	errs = errors.Join(errs, err)
	builder.ProcessorAcceptedSpans, err = meter.Int64Counter(
		"processor_accepted_spans",
		metric.WithDescription("Number of spans successfully pushed into the next component in the pipeline."),
		metric.WithUnit("1"),
	)
	errs = errors.Join(errs, err)
	builder.ProcessorDroppedLogRecords, err = meter.Int64Counter(
		"processor_dropped_log_records",
		metric.WithDescription("Number of log records that were dropped."),
		metric.WithUnit("1"),
	)
	errs = errors.Join(errs, err)
	builder.ProcessorDroppedMetricPoints, err = meter.Int64Counter(
		"processor_dropped_metric_points",
		metric.WithDescription("Number of metric points that were dropped."),
		metric.WithUnit("1"),
	)
	errs = errors.Join(errs, err)
	builder.ProcessorDroppedSpans, err = meter.Int64Counter(
		"processor_dropped_spans",
		metric.WithDescription("Number of spans that were dropped."),
		metric.WithUnit("1"),
	)
	errs = errors.Join(errs, err)
	builder.ProcessorRefusedLogRecords, err = meter.Int64Counter(
		"processor_refused_log_records",
		metric.WithDescription("Number of log records that were rejected by the next component in the pipeline."),
		metric.WithUnit("1"),
	)
	errs = errors.Join(errs, err)
	builder.ProcessorRefusedMetricPoints, err = meter.Int64Counter(
		"processor_refused_metric_points",
		metric.WithDescription("Number of metric points that were rejected by the next component in the pipeline."),
		metric.WithUnit("1"),
	)
	errs = errors.Join(errs, err)
	builder.ProcessorRefusedSpans, err = meter.Int64Counter(
		"processor_refused_spans",
		metric.WithDescription("Number of spans that were rejected by the next component in the pipeline."),
		metric.WithUnit("1"),
	)
	errs = errors.Join(errs, err)
	return &builder, errs
}
