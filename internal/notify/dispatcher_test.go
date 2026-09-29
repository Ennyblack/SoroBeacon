package notify

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sorotrail/sorobeacon/internal/store"
)

// mockNotifier fails a scripted number of times, then succeeds.
type mockNotifier struct {
	failures int
	calls    int
	lastSent Alert
}

func (m *mockNotifier) Send(_ context.Context, a Alert) error {
	m.calls++
	m.lastSent = a
	if m.calls <= m.failures {
		return errors.New("boom")
	}
	return nil
}

// fakeDispatchStore implements DispatchStore in memory.
type fakeDispatchStore struct {
	channels []store.Channel
	attempts []store.DeliveryAttempt
	// window, when set, is returned by ActiveMaintenanceWindow.
	window *store.MaintenanceWindow
	// suppressed records the alert ID and reason of each suppression.
	suppressed []string
	// inhibitions feeds the inhibition check; firing answers RuleFiredWithin.
	inhibitions []store.Inhibition
	firing      map[int64]bool
	inhibited   []inhibitedMark
}

type inhibitedMark struct {
	alertID  int64
	sourceID int64
}

func (f *fakeDispatchStore) ListChannelsForMonitor(_ context.Context, _ int64) ([]store.Channel, error) {
	return f.channels, nil
}

func (f *fakeDispatchStore) RecordDeliveryAttempt(_ context.Context, d *store.DeliveryAttempt) error {
	f.attempts = append(f.attempts, *d)
	return nil
}

func (f *fakeDispatchStore) ActiveMaintenanceWindow(_ context.Context, _ int64, _ string, _ time.Time) (*store.MaintenanceWindow, error) {
	return f.window, nil
}

func (f *fakeDispatchStore) SetAlertSuppressed(_ context.Context, _ int64, reason string) error {
	f.suppressed = append(f.suppressed, reason)
	return nil
}

func (f *fakeDispatchStore) ListChannels(_ context.Context, _ bool) ([]store.Channel, error) {
	return f.channels, nil
}

func (f *fakeDispatchStore) ListInhibitionsForTarget(_ context.Context, target int64) ([]store.Inhibition, error) {
	var out []store.Inhibition
	for _, in := range f.inhibitions {
		if in.TargetRuleID == target {
			out = append(out, in)
		}
	}
	return out, nil
}

func (f *fakeDispatchStore) RuleFiredWithin(_ context.Context, ruleID int64, _ time.Duration) (bool, error) {
	return f.firing[ruleID], nil
}

func (f *fakeDispatchStore) MarkAlertInhibited(_ context.Context, alertID, sourceID int64) error {
	f.inhibited = append(f.inhibited, inhibitedMark{alertID: alertID, sourceID: sourceID})
	return nil
}

func (f *fakeDispatchStore) CreateDeadLetter(_ context.Context, _ *store.DeadLetter) error {
	return nil
}

func newTestDispatcher(t *testing.T, st *fakeDispatchStore, n Notifier) *Dispatcher {
	t.Helper()
	f := &Factory{constructors: map[string]Constructor{}}
	f.Register("mock", func(json.RawMessage) (Notifier, error) { return n, nil })
	d := NewDispatcher(st, f, slog.New(slog.DiscardHandler))
	d.BaseBackoff = time.Millisecond
	return d
}

func mockChannel(id int64) store.Channel {
	return store.Channel{ID: id, Name: "mock", Type: "mock", Config: json.RawMessage(`{}`), Enabled: true}
}

func TestDispatchSuccessFirstTry(t *testing.T) {
	st := &fakeDispatchStore{channels: []store.Channel{mockChannel(1)}}
	n := &mockNotifier{}
	d := newTestDispatcher(t, st, n)

	alert := Alert{ID: 10, MonitorID: 2, MonitorName: "m"}
	d.Dispatch(context.Background(), alert)

	assert.Equal(t, 1, n.calls)
	assert.Equal(t, alert, n.lastSent)
	require.Len(t, st.attempts, 1)
	assert.Equal(t, "success", st.attempts[0].Status)
	assert.Equal(t, int64(10), st.attempts[0].AlertID)
	assert.Equal(t, int64(1), st.attempts[0].ChannelID)
}

func TestDispatchRetriesThenSucceeds(t *testing.T) {
	st := &fakeDispatchStore{channels: []store.Channel{mockChannel(1)}}
	n := &mockNotifier{failures: 2}
	d := newTestDispatcher(t, st, n)

	d.Dispatch(context.Background(), Alert{ID: 11, MonitorID: 2})

	assert.Equal(t, 3, n.calls)
	require.Len(t, st.attempts, 3, "every attempt must be recorded")
	assert.Equal(t, "failed", st.attempts[0].Status)
	assert.Equal(t, "failed", st.attempts[1].Status)
	assert.Equal(t, "success", st.attempts[2].Status)
	assert.Contains(t, st.attempts[0].ResponseSnippet, "boom")
}

func TestDispatchGivesUpAfterMaxAttempts(t *testing.T) {
	st := &fakeDispatchStore{channels: []store.Channel{mockChannel(1)}}
	n := &mockNotifier{failures: 99}
	d := newTestDispatcher(t, st, n)

	d.Dispatch(context.Background(), Alert{ID: 12, MonitorID: 2})

	assert.Equal(t, d.MaxAttempts, n.calls)
	require.Len(t, st.attempts, d.MaxAttempts)
	for _, a := range st.attempts {
		assert.Equal(t, "failed", a.Status)
	}
}

func TestDispatchFansOutToAllChannels(t *testing.T) {
	st := &fakeDispatchStore{channels: []store.Channel{mockChannel(1), mockChannel(2)}}
	n := &mockNotifier{}
	d := newTestDispatcher(t, st, n)

	d.Dispatch(context.Background(), Alert{ID: 13, MonitorID: 2})

	assert.Equal(t, 2, n.calls)
	require.Len(t, st.attempts, 2)
	assert.Equal(t, int64(1), st.attempts[0].ChannelID)
	assert.Equal(t, int64(2), st.attempts[1].ChannelID)
}

func TestRetryRecordsNewAttempt(t *testing.T) {
	st := &fakeDispatchStore{}
	n := &mockNotifier{}
	d := newTestDispatcher(t, st, n)

	got := d.Retry(context.Background(), Alert{ID: 20, MonitorID: 2}, mockChannel(3))

	assert.Equal(t, 1, n.calls)
	require.NotNil(t, got)
	assert.Equal(t, "success", got.Status)
	require.Len(t, st.attempts, 1)
	assert.Equal(t, int64(20), st.attempts[0].AlertID)
	assert.Equal(t, int64(3), st.attempts[0].ChannelID)
}

func TestRetryFailedSendStillRecords(t *testing.T) {
	st := &fakeDispatchStore{}
	n := &mockNotifier{failures: 99}
	d := newTestDispatcher(t, st, n)

	got := d.Retry(context.Background(), Alert{ID: 21}, mockChannel(3))

	assert.Equal(t, 1, n.calls, "manual retry is one shot, not the Dispatch backoff loop")
	require.NotNil(t, got)
	assert.Equal(t, "failed", got.Status)
	assert.Contains(t, got.ResponseSnippet, "boom")
}

func TestGateRetry(t *testing.T) {
	ch := mockChannel(3)
	now := time.Date(2026, 9, 22, 2, 0, 0, 0, time.UTC)
	failed := store.DeliveryAttempt{ChannelID: 3, Status: "failed", AttemptedAt: now.Add(-time.Hour)}
	ok := store.DeliveryAttempt{ChannelID: 3, Status: "success", AttemptedAt: now.Add(-time.Hour)}
	recent := store.DeliveryAttempt{ChannelID: 3, Status: "failed", AttemptedAt: now.Add(-time.Second)}
	other := store.DeliveryAttempt{ChannelID: 9, Status: "success", AttemptedAt: now}

	assert.NoError(t, GateRetry([]store.DeliveryAttempt{failed}, 3, ch, now, DefaultRetryCooldown))
	assert.ErrorIs(t, GateRetry([]store.DeliveryAttempt{failed, ok}, 3, ch, now, DefaultRetryCooldown), ErrAlreadySucceeded)
	assert.ErrorIs(t, GateRetry([]store.DeliveryAttempt{failed}, 3, store.Channel{ID: 3, Enabled: false}, now, DefaultRetryCooldown), ErrChannelDisabled)
	assert.ErrorIs(t, GateRetry(nil, 3, ch, now, DefaultRetryCooldown), ErrNoAttempt)
	assert.ErrorIs(t, GateRetry([]store.DeliveryAttempt{other}, 3, ch, now, DefaultRetryCooldown), ErrNoAttempt)
	assert.ErrorIs(t, GateRetry([]store.DeliveryAttempt{recent}, 3, ch, now, DefaultRetryCooldown), ErrRetryCooldown)
	assert.NoError(t, GateRetry([]store.DeliveryAttempt{recent}, 3, ch, now, 0), "zero cooldown disables the bound")
}

func TestDispatchSuppressedByMaintenanceWindow(t *testing.T) {
	st := &fakeDispatchStore{
		channels: []store.Channel{mockChannel(1)},
		window:   &store.MaintenanceWindow{ID: 9, Reason: "upgrade", Scope: store.MaintenanceScopeGlobal},
	}
	n := &mockNotifier{}
	d := newTestDispatcher(t, st, n)

	d.Dispatch(context.Background(), Alert{ID: 15, MonitorID: 2})

	assert.Equal(t, 0, n.calls, "a suppressed alert must not be delivered")
	assert.Empty(t, st.attempts, "no delivery attempt should be recorded")
	require.Equal(t, []string{"upgrade"}, st.suppressed, "the alert is marked with the window reason")
}

func TestDispatchBadConfigRecordsFailure(t *testing.T) {
	st := &fakeDispatchStore{channels: []store.Channel{
		{ID: 5, Type: "nope", Config: json.RawMessage(`{}`), Enabled: true},
	}}
	d := newTestDispatcher(t, st, &mockNotifier{})

	d.Dispatch(context.Background(), Alert{ID: 14, MonitorID: 2})

	require.Len(t, st.attempts, 1, "bad config is recorded once, not retried")
	assert.Equal(t, "failed", st.attempts[0].Status)
	assert.Contains(t, st.attempts[0].ResponseSnippet, "unknown channel type")
}

func TestDispatchInhibitedSkipsDeliveryAndMarks(t *testing.T) {
	st := &fakeDispatchStore{
		channels: []store.Channel{mockChannel(1)},
		inhibitions: []store.Inhibition{
			{SourceRuleID: 7, TargetRuleID: 9, FiringWindowSeconds: 300},
		},
		firing: map[int64]bool{7: true},
	}
	n := &mockNotifier{}
	d := newTestDispatcher(t, st, n)

	d.Dispatch(context.Background(), Alert{ID: 20, MonitorID: 2, RuleID: 9})

	assert.Equal(t, 0, n.calls, "inhibited alert must not reach any notifier")
	assert.Empty(t, st.attempts, "inhibited alert records no delivery attempts")
	require.Len(t, st.inhibited, 1, "the suppression must be recorded on the alert")
	assert.Equal(t, int64(20), st.inhibited[0].alertID)
	assert.Equal(t, int64(7), st.inhibited[0].sourceID)
}

func TestDispatchQuietSourceDelivers(t *testing.T) {
	st := &fakeDispatchStore{
		channels: []store.Channel{mockChannel(1)},
		inhibitions: []store.Inhibition{
			{SourceRuleID: 7, TargetRuleID: 9, FiringWindowSeconds: 300},
		},
		firing: map[int64]bool{7: false},
	}
	n := &mockNotifier{}
	d := newTestDispatcher(t, st, n)

	d.Dispatch(context.Background(), Alert{ID: 21, MonitorID: 2, RuleID: 9})

	assert.Equal(t, 1, n.calls, "a quiet source must not suppress delivery")
	assert.Empty(t, st.inhibited)
}

// timeoutNotifier captures the context deadline it was called with.
type timeoutNotifier struct {
	gotDeadline time.Time
	hasDeadline bool
}

func (n *timeoutNotifier) Send(ctx context.Context, _ Alert) error {
	dl, ok := ctx.Deadline()
	n.hasDeadline = ok
	n.gotDeadline = dl
	return nil
}

func TestDispatchAppliesPerChannelTimeout(t *testing.T) {
	ch := mockChannel(1)
	ch.Timeout = 5 * time.Second
	st := &fakeDispatchStore{channels: []store.Channel{ch}}
	n := &timeoutNotifier{}
	d := newTestDispatcher(t, st, n)

	before := time.Now()
	d.Dispatch(context.Background(), Alert{ID: 15, MonitorID: 2})

	require.True(t, n.hasDeadline, "Send must receive a context with deadline")
	assert.WithinDuration(t, before.Add(5*time.Second), n.gotDeadline, 500*time.Millisecond)
}

func TestDispatchAppliesDefaultTimeoutWhenUnset(t *testing.T) {
	ch := mockChannel(1)
	ch.Timeout = 0 // unset
	st := &fakeDispatchStore{channels: []store.Channel{ch}}
	n := &timeoutNotifier{}
	d := newTestDispatcher(t, st, n)

	before := time.Now()
	d.Dispatch(context.Background(), Alert{ID: 16, MonitorID: 2})

	require.True(t, n.hasDeadline, "Send must receive a context with deadline")
	assert.WithinDuration(t, before.Add(DefaultTimeout), n.gotDeadline, 500*time.Millisecond)
}

func TestRetryAppliesPerChannelTimeout(t *testing.T) {
	ch := mockChannel(1)
	ch.Timeout = 8 * time.Second
	st := &fakeDispatchStore{channels: []store.Channel{ch}}
	n := &timeoutNotifier{}
	d := newTestDispatcher(t, st, n)

	before := time.Now()
	da := d.Retry(context.Background(), Alert{ID: 17, MonitorID: 2}, ch)

	require.NotNil(t, da)
	assert.Equal(t, "success", da.Status)
	require.True(t, n.hasDeadline, "Retry must apply channel timeout to ctx")
	assert.WithinDuration(t, before.Add(8*time.Second), n.gotDeadline, 500*time.Millisecond)
}
