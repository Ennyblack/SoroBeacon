package store

// Tracing tests for the store's write path. These are integration tests:
// they run against TEST_DATABASE_URL and skip when it is unset, exactly
// like the rest of the store suite. A green run without the variable does
// not prove the store spans work — run make test-db.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/sorotrail/sorobeacon/internal/reqid"
	"github.com/sorotrail/sorobeacon/internal/telemetry"
)

// tracedStore connects to the test database with tracing wired to an
// in-memory exporter, returning the store plus the recorder.
func tracedStore(t *testing.T) (*Postgres, *tracetest.SpanRecorder) {
	t.Helper()
	st := testStore(t)

	exp := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(exp))
	t.Cleanup(func() { require.NoError(t, tp.Shutdown(context.Background())) })
	st.WithTelemetry(telemetry.New(tp.Tracer("test")))
	return st, exp
}

// alertSpanAttrs flattens the attributes of the most recent finished
// store.create_alert span; CreateAlert is the only store method that opens a
// span. The dedup and cooldown tests call CreateAlert twice on purpose, so
// the recorder holds several spans under one name — the caller wants the one
// for the call it just made, which is the last to end, not the first.
func alertSpanAttrs(t *testing.T, exp *tracetest.SpanRecorder) map[string]string {
	t.Helper()
	var found map[string]string
	for _, s := range exp.Ended() {
		if s.Name() != "store.create_alert" {
			continue
		}
		attrs := map[string]string{}
		for _, kv := range s.Attributes() {
			attrs[string(kv.Key)] = kv.Value.Emit()
		}
		found = attrs
	}
	if found == nil {
		t.Fatal("CreateAlert must open a store.create_alert span")
	}
	return found
}

func TestCreateAlertSpanOutcomeAttributes(t *testing.T) {
	st, exp := tracedStore(t)
	ctx := context.Background()

	m := &Monitor{Name: "traced", ContractIDs: []string{"C"}, Enabled: true}
	require.NoError(t, st.CreateMonitor(ctx, m))
	r := &Rule{MonitorID: m.ID, Type: "event_emitted", Params: []byte(`{}`), Enabled: true}
	require.NoError(t, st.CreateRule(ctx, r))

	outcome, err := st.CreateAlert(ctx, &Alert{MonitorID: m.ID, RuleID: r.ID, EventID: "ev-1"})
	require.NoError(t, err)
	require.Equal(t, AlertCreated, outcome)

	attrs := alertSpanAttrs(t, exp)
	assert.Equal(t, "created", attrs[telemetry.AttrOutcome])
	assert.Equal(t, "ev-1", attrs[telemetry.AttrEventID])
	// Only ids and outcome land in attributes; the payload can embed
	// operator data and stays out entirely.
	assert.NotContains(t, attrs, "payload")
}

func TestCreateAlertSpanDedupOutcome(t *testing.T) {
	st, exp := tracedStore(t)
	ctx := context.Background()

	m := &Monitor{Name: "traced2", ContractIDs: []string{"C"}, Enabled: true}
	require.NoError(t, st.CreateMonitor(ctx, m))
	r := &Rule{MonitorID: m.ID, Type: "event_emitted", Params: []byte(`{}`), Enabled: true}
	require.NoError(t, st.CreateRule(ctx, r))

	outcome, err := st.CreateAlert(ctx, &Alert{MonitorID: m.ID, RuleID: r.ID, EventID: "ev-1"})
	require.NoError(t, err)
	require.Equal(t, AlertCreated, outcome)
	outcome, err = st.CreateAlert(ctx, &Alert{MonitorID: m.ID, RuleID: r.ID, EventID: "ev-1"})
	require.NoError(t, err)
	require.Equal(t, AlertDuplicate, outcome)

	assert.Equal(t, "duplicate", alertSpanAttrs(t, exp)[telemetry.AttrOutcome],
		"the dedup gate must be visible on the span")
}

func TestCreateAlertSpanSuppressedOutcome(t *testing.T) {
	st, exp := tracedStore(t)
	ctx := context.Background()

	m := &Monitor{Name: "traced3", ContractIDs: []string{"C"}, Enabled: true}
	require.NoError(t, st.CreateMonitor(ctx, m))
	r := &Rule{MonitorID: m.ID, Type: "event_emitted",
		Params: json.RawMessage(`{"event_name": "x", "cooldown": "5m"}`), Enabled: true}
	require.NoError(t, st.CreateRule(ctx, r))

	// The store enforces the window from Alert.Cooldown, not from the rule's
	// params — the poller is what reads the rule and fills this in (see
	// ruleCooldown in internal/poller). Set it on both writes or the second
	// one is a plain insert and the span records "created".
	her := func(eventID string) *Alert {
		return &Alert{MonitorID: m.ID, RuleID: r.ID, EventID: eventID, Cooldown: 5 * time.Minute}
	}

	outcome, err := st.CreateAlert(ctx, her("ev-1"))
	require.NoError(t, err)
	require.Equal(t, AlertCreated, outcome)
	outcome, err = st.CreateAlert(ctx, her("ev-2"))
	require.NoError(t, err)
	require.Equal(t, AlertSuppressed, outcome)

	assert.Equal(t, "suppressed", alertSpanAttrs(t, exp)[telemetry.AttrOutcome],
		"the cooldown gate must be visible on the span")
}

func TestCreateAlertSpanCarriesRequestID(t *testing.T) {
	st, exp := tracedStore(t)
	ctx := context.Background()

	m := &Monitor{Name: "traced4", ContractIDs: []string{"C"}, Enabled: true}
	require.NoError(t, st.CreateMonitor(ctx, m))
	r := &Rule{MonitorID: m.ID, Type: "event_emitted", Params: []byte(`{}`), Enabled: true}
	require.NoError(t, st.CreateRule(ctx, r))

	// A request id in the context rides onto the span, so a store write can
	// be joined with the log lines that reported it.
	tracedCtx := reqid.WithContext(ctx, "req-store-1")
	_, err := st.CreateAlert(tracedCtx, &Alert{MonitorID: m.ID, RuleID: r.ID, EventID: "ev-1"})
	require.NoError(t, err)

	assert.Equal(t, "req-store-1", alertSpanAttrs(t, exp)[telemetry.AttrRequestID])
}

func TestCreateAlertWithoutTelemetryNilSafe(t *testing.T) {
	// The store's default wiring has no telemetry; nothing may panic.
	st := testStore(t)
	ctx := context.Background()

	m := &Monitor{Name: "untraced", ContractIDs: []string{"C"}, Enabled: true}
	require.NoError(t, st.CreateMonitor(ctx, m))
	r := &Rule{MonitorID: m.ID, Type: "event_emitted", Params: []byte(`{}`), Enabled: true}
	require.NoError(t, st.CreateRule(ctx, r))
	st.telemetry = nil

	outcome, err := st.CreateAlert(ctx, &Alert{MonitorID: m.ID, RuleID: r.ID, EventID: "ev-1"})
	require.NoError(t, err)
	assert.Equal(t, AlertCreated, outcome)
}
