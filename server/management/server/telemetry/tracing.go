// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package telemetry

import (
	"context"
	"fmt"
	"os"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// NewTracerProvider builds Karst's server-side trace provider (plans/phase-6
// /08-observability.md §3.4/§5 W5) and a shutdown func to flush it on exit.
//
// Off by default, the same consent posture §3.1 gives karstd's own opt-in
// metrics listener: deploy/compose/ runs no OTLP collector today, and
// constructing an otlptracegrpc exporter unconditionally would mean this
// process spends the rest of its life retrying against localhost:4317 with
// nothing on the other end. So this only builds a real exporter when an
// operator has actually set one of the OTel SDK's own standard endpoint env
// vars; otherwise every span created against the returned provider is a
// genuine no-op — Tracer() call sites throughout internals/karst never need
// their own "is tracing configured" branch, they just always call
// otel.Tracer(...).Start(...).
func NewTracerProvider(ctx context.Context) (trace.TracerProvider, func(context.Context) error, error) {
	if os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") == "" && os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" {
		return noop.NewTracerProvider(), func(context.Context) error { return nil }, nil
	}

	// otlptracegrpc.New with no options reads the same standard env vars
	// already checked above (plus OTEL_EXPORTER_OTLP_[TRACES_]INSECURE/
	// HEADERS/etc.) to configure itself — nothing here duplicates that
	// parsing.
	exporter, err := otlptracegrpc.New(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("karst: otlp trace exporter: %w", err)
	}

	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(
		semconv.ServiceName("karst-control"),
	))
	if err != nil {
		return nil, nil, fmt.Errorf("karst: trace resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	return tp, tp.Shutdown, nil
}
