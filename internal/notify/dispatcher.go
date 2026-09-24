package notify

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/sorotrail/sorobeacon/internal/metrics"
	"github.com/sorotrail/sorobeacon/internal/store"
	"github.com/sorotrail/sorobeacon/internal/telemetry"
)

// Retry gate errors. The HTTP layer maps these onto status codes; the
// dashboard uses the same checks so a stray click cannot double-notify.
var (
	ErrAlreadySucceeded = errors.New("delivery already succeeded")
	ErrChannelDisabled  = errors.New("channel is disabled")
	ErrNoAttempt        = errors.New("no delivery attempt for this channel")
	ErrRetryCooldown    = errors.New("retried too recently")
)

// DefaultRetryCooldown bounds how often an operator can re-send one
// alert to one channel. Long enough to stop a jammed button, short
// enough that a real "the webhook is fixed, try again" is not blocked.
const DefaultRetryCooldown = 30 * time.Second

// DispatchStore is the slice of the store the dispatcher needs.
type DispatchStore interface {
	ListChannelsForMonitor(ctx context.Context, monitorID int64) ([]store.Channel, error)
	RecordDeliveryAttempt(ctx context.Context, d *store.DeliveryAttempt) error
}

// Dispatcher fans an alert out to its monitor's channels, retrying each
// channel with exponential backoff and recording every attempt.
type Dispatcher struct {
	store   DispatchStore
	factory *Factory
	log     *slog.Logger
	// metrics is optional Prometheus instrumentation; nil-safe.
	metrics *metrics.Metrics
	// telemetry is optional tracing; nil-safe. Delivery spans are started
	// from the alert's context, so they are children of the alert's span —
	// that parent chain, not any attribute, is what joins the delivery to
	// the poll cycle that produced it.
	telemetry *telemetry.Provider

	// MaxAttempts per channel (default 3) and BaseBackoff between attempts
	// (default 1s, doubled each retry: 1s, 2s, 4s...).
	MaxAttempts int
	BaseBackoff time.Duration
}

// NewDispatcher wires a Dispatcher with default retry settings.
func NewDispatcher(s DispatchStore, f *Factory, log *slog.Logger) *Dispatcher {
	return &Dispatcher{
		store:       s,
		factory:     f,
		log:         log,
		MaxAttempts: 3,
		BaseBackoff: time.Second,
	}
}

// WithMetrics attaches delivery instrumentation.
func (d *Dispatcher) WithMetrics(m *metrics.Metrics) *Dispatcher {
	d.metrics = m
	return d
}

// WithTelemetry attaches tracing to every delivery path, including manual
// retries issued from the API and dashboard.
func (d *Dispatcher) WithTelemetry(t *telemetry.Provider) *Dispatcher {
	d.telemetry = t
	return d
}

// Dispatch delivers one alert to every enabled channel attached to its
// monitor. Channel failures are recorded and logged, never fatal: one bad
// channel must not block the others or the poller.
func (d *Dispatcher) Dispatch(ctx context.Context, a Alert) {
	channels, err := d.store.ListChannelsForMonitor(ctx, a.MonitorID)
	if err != nil {
		d.log.Error("list channels for alert", "alert_id", a.ID, "monitor_id", a.MonitorID, "err", err)
		return
	}
	for _, ch := range channels {
		d.deliver(ctx, a, ch)
	}
}

func (d *Dispatcher) deliver(ctx context.Context, a Alert, ch store.Channel) {
	// One span per channel covers the whole delivery: notifier construction
	// plus every retried attempt. The span's parent is whatever ctx carries
	// — the alert's span when called from Dispatch — which is the whole
	// point: a delivery must never be a root span. Channel identity rides
	// only as the row id and static type; the config (webhook URLs, bot
	// tokens, SMTP credentials) never enters a span, an attribute or an
	// event, here or anywhere.
	var span trace.Span
	if d.telemetry != nil {
		ctx, span = d.telemetry.WithRequestID(ctx, "notify.deliver",
			trace.WithAttributes(
				attribute.Int64(telemetry.AttrAlertID, a.ID),
				attribute.Int64(telemetry.AttrChannelID, ch.ID),
				attribute.String(telemetry.AttrChannelType, ch.Type),
			),
		)
		defer span.End()
	}

	notifier, err := d.factory.New(ch.Type, ch.Config)
	if err != nil {
		// Bad config: record one failed attempt, no point retrying.
		d.record(ctx, a.ID, ch.ID, "failed", err.Error())
		d.log.Error("build notifier", "channel_id", ch.ID, "channel_type", ch.Type, "err", err)
		telemetry.RecordError(span, err)
		return
	}

	backoff := d.BaseBackoff
	for attempt := 1; ; attempt++ {
		err := notifier.Send(ctx, a)
		if err == nil {
			d.metrics.RecordDelivery(ch.Type, true)
			d.record(ctx, a.ID, ch.ID, "success", "")
			d.log.Info("alert delivered", "alert_id", a.ID, "channel_id", ch.ID, "attempt", attempt)
			return
		}
		d.metrics.RecordDelivery(ch.Type, false)
		d.record(ctx, a.ID, ch.ID, "failed", err.Error())
		d.log.Warn("alert delivery failed",
			"alert_id", a.ID, "channel_id", ch.ID, "attempt", attempt, "err", err)
		telemetry.RecordError(span, err)

		if attempt >= d.MaxAttempts || ctx.Err() != nil {
			return
		}
		select {
		case <-time.After(backoff):
			backoff *= 2
		case <-ctx.Done():
			return
		}
	}
}

func (d *Dispatcher) record(ctx context.Context, alertID, channelID int64, status, snippet string) *store.DeliveryAttempt {
	if len(snippet) > 500 {
		snippet = snippet[:500]
	}
	da := &store.DeliveryAttempt{
		AlertID:         alertID,
		ChannelID:       channelID,
		Status:          status,
		ResponseSnippet: snippet,
	}
	if err := d.store.RecordDeliveryAttempt(ctx, da); err != nil {
		d.log.Error("record delivery attempt", "alert_id", alertID, "channel_id", channelID, "err", err)
	}
	return da
}

// GateRetry decides whether a manual retry is allowed. attempts is the
// alert's full delivery history; only rows for channelID are considered.
// cooldown is measured from the most recent attempt for that channel.
func GateRetry(attempts []store.DeliveryAttempt, channelID int64, ch store.Channel, now time.Time, cooldown time.Duration) error {
	if !ch.Enabled {
		return ErrChannelDisabled
	}
	var last *store.DeliveryAttempt
	any := false
	for i := range attempts {
		if attempts[i].ChannelID != channelID {
			continue
		}
		any = true
		if attempts[i].Status == "success" {
			return ErrAlreadySucceeded
		}
		if last == nil || attempts[i].AttemptedAt.After(last.AttemptedAt) {
			last = &attempts[i]
		}
	}
	if !any {
		return ErrNoAttempt
	}
	if cooldown > 0 && last != nil && !last.AttemptedAt.IsZero() && now.Sub(last.AttemptedAt) < cooldown {
		return ErrRetryCooldown
	}
	return nil
}

// Retry sends the alert once to ch and records a new delivery attempt.
// Unlike Dispatch it does not loop with backoff: the operator asked for
// one try and the HTTP handler returns that outcome on the same request.
func (d *Dispatcher) Retry(ctx context.Context, a Alert, ch store.Channel) *store.DeliveryAttempt {
	// The retry gets its own span under the API request's trace, so a
	// manual re-send is attributable on the dashboard's request id too.
	var span trace.Span
	if d.telemetry != nil {
		ctx, span = d.telemetry.WithRequestID(ctx, "notify.retry",
			trace.WithAttributes(
				attribute.Int64(telemetry.AttrAlertID, a.ID),
				attribute.Int64(telemetry.AttrChannelID, ch.ID),
				attribute.String(telemetry.AttrChannelType, ch.Type),
			),
		)
		defer span.End()
	}

	notifier, err := d.factory.New(ch.Type, ch.Config)
	if err != nil {
		d.log.Error("build notifier", "channel_id", ch.ID, "channel_type", ch.Type, "err", err)
		return d.record(ctx, a.ID, ch.ID, "failed", err.Error())
	}
	err = notifier.Send(ctx, a)
	if err == nil {
		d.metrics.RecordDelivery(ch.Type, true)
		d.log.Info("alert delivered", "alert_id", a.ID, "channel_id", ch.ID, "attempt", "retry")
		return d.record(ctx, a.ID, ch.ID, "success", "")
	}
	d.metrics.RecordDelivery(ch.Type, false)
	d.log.Warn("alert delivery failed", "alert_id", a.ID, "channel_id", ch.ID, "attempt", "retry", "err", err)
	return d.record(ctx, a.ID, ch.ID, "failed", err.Error())
}
