// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package telemetry

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// newTestKarstMetrics wires a KarstMetrics against a ManualReader so a test
// can Collect() and inspect exactly what a scrape would see, without a real
// exporter or a network round trip.
func newTestKarstMetrics(t *testing.T) (*KarstMetrics, *sdkmetric.ManualReader) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() {
		_ = provider.Shutdown(context.Background())
	})
	m, err := NewKarstMetrics(context.Background(), provider.Meter("karst_metrics_test"))
	require.NoError(t, err)
	return m, reader
}

// gaugePoints collects a scrape and returns the int64 gauge data points for
// the named instrument, keyed by their account_id attribute (empty string
// for a point with none, as pskEpochAgeGauge always has).
func gaugePoints(t *testing.T, reader *sdkmetric.ManualReader, name string) map[string]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))

	points := make(map[string]int64)
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			gauge, ok := m.Data.(metricdata.Gauge[int64])
			require.Truef(t, ok, "%s: expected Gauge[int64], got %T", name, m.Data)
			for _, dp := range gauge.DataPoints {
				accountID := ""
				for _, attr := range dp.Attributes.ToSlice() {
					if attr.Key == AccountIDLabel {
						accountID = attr.Value.AsString()
					}
				}
				points[accountID] = dp.Value
			}
		}
	}
	return points
}

func TestKarstMetrics_BedrockChainDepth(t *testing.T) {
	m, reader := newTestKarstMetrics(t)

	m.SetBedrockChainDepth("account-A", 42)
	m.SetBedrockChainDepth("account-B", 7)

	points := gaugePoints(t, reader, "management.karst.bedrock.chain.depth")
	assert.Equal(t, map[string]int64{"account-A": 42, "account-B": 7}, points)

	// A later write for the same account replaces, rather than accumulates.
	m.SetBedrockChainDepth("account-A", 43)
	points = gaugePoints(t, reader, "management.karst.bedrock.chain.depth")
	assert.Equal(t, int64(43), points["account-A"])
}

func TestKarstMetrics_BedrockAnchorAge(t *testing.T) {
	m, reader := newTestKarstMetrics(t)

	// Nothing recorded yet: no data point at all, not a zero or fabricated one.
	points := gaugePoints(t, reader, "management.karst.bedrock.anchor.age.seconds")
	assert.Empty(t, points)

	anchoredAt := time.Now().Add(-30 * time.Second)
	m.SetBedrockLastAnchoredAt("account-A", anchoredAt)

	points = gaugePoints(t, reader, "management.karst.bedrock.anchor.age.seconds")
	require.Contains(t, points, "account-A")
	assert.GreaterOrEqual(t, points["account-A"], int64(30))
	assert.Less(t, points["account-A"], int64(60), "age should reflect the 30s-old anchor, not a stale or fabricated value")
}

func TestKarstMetrics_RelayRegistrySize(t *testing.T) {
	m, reader := newTestKarstMetrics(t)

	m.SetRelayRegistrySize("account-A", 3)
	points := gaugePoints(t, reader, "management.karst.relay.registry.size")
	assert.Equal(t, int64(3), points["account-A"])

	// A registry that shrinks to zero still reports zero explicitly — the
	// Set* call caches whatever value it is given, it does not delete on 0.
	m.SetRelayRegistrySize("account-A", 0)
	points = gaugePoints(t, reader, "management.karst.relay.registry.size")
	assert.Equal(t, int64(0), points["account-A"])
}

func TestKarstMetrics_PSKEpochAge(t *testing.T) {
	m, reader := newTestKarstMetrics(t)

	// Before any rotation is observed, the gauge reports nothing — a fresh
	// process has no "since" to report yet (see observe's own comment).
	points := gaugePoints(t, reader, "management.karst.psk.epoch.age.seconds")
	assert.Empty(t, points)

	bumpedAt := time.Now().Add(-10 * time.Second)
	m.SetPSKEpochLastBumpAt(bumpedAt)

	points = gaugePoints(t, reader, "management.karst.psk.epoch.age.seconds")
	require.Contains(t, points, "", "psk epoch age carries no account_id label — it is one process-wide value")
	assert.GreaterOrEqual(t, points[""], int64(10))
	assert.Less(t, points[""], int64(30))
}

func TestKarstMetrics_NilReceiverIsNoOp(t *testing.T) {
	// Metrics is optional plumbing throughout Karst (bedrock.Log, relayreg.Store,
	// control.EpochScheduler); every Set* method must tolerate a nil receiver
	// so a caller that never wired metrics does not need its own nil checks.
	var m *KarstMetrics
	assert.NotPanics(t, func() {
		m.SetBedrockChainDepth("account-A", 1)
		m.SetBedrockLastAnchoredAt("account-A", time.Now())
		m.SetRelayRegistrySize("account-A", 1)
		m.SetPSKEpochLastBumpAt(time.Now())
	})
}
