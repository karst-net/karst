package telemetry

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// KarstMetrics are the server-side metrics for Karst's own subsystems —
// Bedrock anchoring, the relay registry, and PSK epoch rotation — tracked
// separately from the eleven metrics types above because none of those
// packages (bedrock, relayreg, karst/control) exist outside Karst.
//
// Every gauge here is an ObservableGauge read by callback rather than
// recorded on a timer: the underlying value is cheap to keep current in an
// in-memory field at the point it actually changes (a write to the Bedrock
// log, a relay registry mutation, an epoch rotation), so a callback that
// only reads that field — rather than re-deriving the value from a database
// read on every scrape — is the pattern GRPCMetrics.activeStreamsGauge
// already established for exactly this reason.
type KarstMetrics struct {
	ctx context.Context

	bedrockChainDepthGauge metric.Int64ObservableGauge
	bedrockAnchorAgeGauge  metric.Int64ObservableGauge
	pskEpochAgeGauge       metric.Int64ObservableGauge
	relayRegistrySizeGauge metric.Int64ObservableGauge

	mu sync.Mutex
	// Keyed by account ID. Karst's server-side account model is single-tenant
	// per deployment in the intended use (PLAN.md §0, bedrock.Scheduler's own
	// doc comment), so these maps hold one entry in practice — but the write
	// sites (bedrock.Log.Import, bedrock.Scheduler.Tick, relayreg.Store's
	// Create/Delete) already carry an accountID, and every other per-account
	// metric in this package (GRPCMetrics, AccountManagerMetrics) labels by
	// it, so dropping the label here would be the inconsistent choice.
	bedrockChainDepth     map[string]int64
	bedrockLastAnchoredAt map[string]time.Time
	relayRegistrySize     map[string]int64

	// pskEpochLastBumpAt has no account_id label: control.NetmapHandler.Epoch
	// is one value for the whole process (control/epoch.go), not a
	// per-account roster field, so there is nothing to key it by.
	pskEpochLastBumpAt time.Time
}

// NewKarstMetrics creates KarstMetrics and registers its four gauges'
// callback.
func NewKarstMetrics(ctx context.Context, meter metric.Meter) (*KarstMetrics, error) {
	bedrockChainDepthGauge, err := meter.Int64ObservableGauge("management.karst.bedrock.chain.depth",
		metric.WithUnit("1"),
		metric.WithDescription("Head sequence number of an account's Bedrock audit chain"),
	)
	if err != nil {
		return nil, err
	}

	bedrockAnchorAgeGauge, err := meter.Int64ObservableGauge("management.karst.bedrock.anchor.age.seconds",
		metric.WithUnit("seconds"),
		metric.WithDescription("Time since an account's Bedrock audit chain was last anchored"),
	)
	if err != nil {
		return nil, err
	}

	pskEpochAgeGauge, err := meter.Int64ObservableGauge("management.karst.psk.epoch.age.seconds",
		metric.WithUnit("seconds"),
		metric.WithDescription("Time since the PSK rotation epoch last advanced"),
	)
	if err != nil {
		return nil, err
	}

	relayRegistrySizeGauge, err := meter.Int64ObservableGauge("management.karst.relay.registry.size",
		metric.WithUnit("1"),
		metric.WithDescription("Number of relays registered to an account"),
	)
	if err != nil {
		return nil, err
	}

	m := &KarstMetrics{
		ctx:                    ctx,
		bedrockChainDepthGauge: bedrockChainDepthGauge,
		bedrockAnchorAgeGauge:  bedrockAnchorAgeGauge,
		pskEpochAgeGauge:       pskEpochAgeGauge,
		relayRegistrySizeGauge: relayRegistrySizeGauge,
		bedrockChainDepth:      make(map[string]int64),
		bedrockLastAnchoredAt:  make(map[string]time.Time),
		relayRegistrySize:      make(map[string]int64),
	}

	if _, err := meter.RegisterCallback(m.observe,
		bedrockChainDepthGauge, bedrockAnchorAgeGauge, pskEpochAgeGauge, relayRegistrySizeGauge,
	); err != nil {
		return nil, err
	}

	return m, nil
}

// observe is the callback the exporter invokes on every scrape. It only
// reads state already cached by the Set* methods below — no database access
// happens here, which is the point of caching in the first place.
func (m *KarstMetrics) observe(_ context.Context, o metric.Observer) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for accountID, depth := range m.bedrockChainDepth {
		o.ObserveInt64(m.bedrockChainDepthGauge, depth,
			metric.WithAttributes(attribute.String(AccountIDLabel, accountID)))
	}
	for accountID, at := range m.bedrockLastAnchoredAt {
		o.ObserveInt64(m.bedrockAnchorAgeGauge, int64(now.Sub(at).Seconds()),
			metric.WithAttributes(attribute.String(AccountIDLabel, accountID)))
	}
	for accountID, size := range m.relayRegistrySize {
		o.ObserveInt64(m.relayRegistrySizeGauge, size,
			metric.WithAttributes(attribute.String(AccountIDLabel, accountID)))
	}
	// Zero-value pskEpochLastBumpAt means the epoch has never been observed
	// to rotate yet (a freshly started process) — reporting age against it
	// would be a fabricated value, not a real "since", so it is omitted from
	// the scrape entirely rather than emitted as a huge or negative number.
	if !m.pskEpochLastBumpAt.IsZero() {
		o.ObserveInt64(m.pskEpochAgeGauge, int64(now.Sub(m.pskEpochLastBumpAt).Seconds()))
	}
	return nil
}

// SetBedrockChainDepth records accountID's current Bedrock chain head
// sequence number. m may be nil (metrics are optional plumbing throughout
// Karst — see control.EpochScheduler.Updates for the same convention), in
// which case every Set* method here is a no-op.
func (m *KarstMetrics) SetBedrockChainDepth(accountID string, depth uint64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bedrockChainDepth[accountID] = int64(depth)
}

// SetBedrockLastAnchoredAt records when accountID's Bedrock chain was last
// anchored, so the age gauge can compute time.Since(at) at scrape time.
func (m *KarstMetrics) SetBedrockLastAnchoredAt(accountID string, at time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bedrockLastAnchoredAt[accountID] = at
}

// SetRelayRegistrySize records the current number of relays registered to
// accountID.
func (m *KarstMetrics) SetRelayRegistrySize(accountID string, size int) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.relayRegistrySize[accountID] = int64(size)
}

// SetPSKEpochLastBumpAt records when the PSK rotation epoch last advanced,
// called by control.EpochScheduler only on an actual rotation (not on every
// tick), so the age gauge reflects time since the last real change.
func (m *KarstMetrics) SetPSKEpochLastBumpAt(at time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pskEpochLastBumpAt = at
}
