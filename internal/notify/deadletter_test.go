package notify

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/sorotrail/sorobeacon/internal/store"
)

type mockDeadLetterStore struct {
	store.Store
	deadLetters []*store.DeadLetter
}

func (m *mockDeadLetterStore) RecordDeadLetter(ctx context.Context, dl *store.DeadLetter) error {
	dl.ID = int64(len(m.deadLetters) + 1)
	m.deadLetters = append(m.deadLetters, dl)
	return nil
}

func (m *mockDeadLetterStore) RecordDeliveryAttempt(ctx context.Context, d *store.DeliveryAttempt) error {
	return nil
}

func TestDeadLetterRedactionAndRecording(t *testing.T) {
	st := &mockDeadLetterStore{}
	factory := NewFactory()
	d := NewDispatcher(st, factory, nil)
	d.MaxAttempts = 1

	alert := store.Alert{ID: 10, MonitorID: 1, RuleID: 1, EventID: "ev-1"}
	// Use a webhook URL containing credentials
	cfg, err := json.Marshal(map[string]any{"url": "https://secret-token:secret-val@example.com/webhook"})
	require.NoError(t, err)
	ch := store.Channel{ID: 5, Type: "webhook", Config: cfg, Enabled: true}

	err = d.DeliverToChannel(context.Background(), alert, ch)
	require.Error(t, err)

	require.Len(t, st.deadLetters, 1)
	dl := st.deadLetters[0]
	assert.Equal(t, int64(10), dl.AlertID)
	assert.Equal(t, int64(5), dl.ChannelID)
	// Assert no secret credential reaches the stored last_error or snippet
	assert.NotContains(t, dl.LastError, "secret-token")
	assert.NotContains(t, dl.LastError, "secret-val")
}
