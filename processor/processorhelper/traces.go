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

package processorhelper // import "go.opentelemetry.io/collector/processor/processorhelper"

import (
	"context"
	"errors"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenterror"
	"go.opentelemetry.io/collector/config"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/model/pdata"
)

// ProcessTracesFunc is a helper function that processes the incoming data and returns the data to be sent to the next component.
// If error is returned then returned data are ignored. It MUST not call the next component.
type ProcessTracesFunc func(context.Context, pdata.Traces) (pdata.Traces, error)

type tracesProcessor struct {
	component.StartFunc
	component.ShutdownFunc
	consumer.Traces
}

// NewTracesProcessor creates a TracesProcessor that ensure context propagation and the right tags are set.
// TODO: Add observability metrics support
func NewTracesProcessor(
	cfg config.Processor,
	nextConsumer consumer.Traces,
	tracesFunc ProcessTracesFunc,
	options ...Option,
) (component.TracesProcessor, error) {
	if tracesFunc == nil {
		return nil, errors.New("nil tracesFunc")
	}

	if nextConsumer == nil {
		return nil, componenterror.ErrNilNextConsumer
	}

	eventOptions := spanAttributes(cfg.ID())
	bs := fromOptions(options)
	traceConsumer, err := consumer.NewTraces(func(ctx context.Context, td pdata.Traces) error {
		span := trace.SpanFromContext(ctx)
		span.AddEvent("Start processing.", eventOptions)
		var err error
		td, err = tracesFunc(ctx, td)
		span.AddEvent("End processing.", eventOptions)
		if err != nil {
			if errors.Is(err, ErrSkipProcessingData) {
				return nil
			}
			return err
		}
		return nextConsumer.ConsumeTraces(ctx, td)
	}, bs.consumerOptions...)

	if err != nil {
		return nil, err
	}

	return &tracesProcessor{
		StartFunc:    bs.StartFunc,
		ShutdownFunc: bs.ShutdownFunc,
		Traces:       traceConsumer,
	}, nil
}
