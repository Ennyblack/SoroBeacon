// Package poller ingests Soroban contract events from a Stellar RPC node
// and feeds them through the rules engine, creating and dispatching alerts.
package poller

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/sorotrail/sorobeacon/internal/metrics"
	"github.com/sorotrail/sorobeacon/internal/notify"
	"github.com/sorotrail/sorobeacon/internal/rules"
	"github.com/sorotrail/sorobeacon/internal/stellar"
	"github.com/sorotrail/sorobeacon/internal/store"
	"github.com/sorotrail/sorobeacon/internal/telemetry"
)

// Position is a race-free snapshot of how far the poller has got relative
// to the chain. A zero LastSuccessfulPoll means no successful poll has
// completed yet — callers must not treat the ledger fields as "in sync".
type Position struct {
	LastProcessedLedger uint32
	LatestChainLedger   uint32
	LastSuccessfulPoll  time.Time
}

// Ready reports whether a successful poll has completed.
func (p Position) Ready() bool { return !p.LastSuccessfulPoll.IsZero() }

// Lag is latest known chain ledger minus last processed ledger.
func (p Position) Lag() int64 {
	return int64(p.LatestChainLedger) - int64(p.LastProcessedLedger)
}

// Store is the slice of the store the poller needs.
type Store interface {
	ListMonitors(ctx context.Context, enabledOnly bool) ([]store.Monitor, error)
	ListRules(ctx context.Context, monitorID int64, enabledOnly bool) ([]store.Rule, error)
	CreateAlert(ctx context.Context, a *store.Alert) (store.AlertOutcome, error)
	GetIngestState(ctx context.Context) (store.IngestState, error)
	SetIngestState(ctx context.Context, s store.IngestState) error
}

// Dispatcher receives every newly created alert. Implemented by
// notify.Dispatcher; mocked in tests.
type Dispatcher interface {
	Dispatch(ctx context.Context, a notify.Alert)
}

// Poller runs the ingest loop: getEvents from the last checkpoint, decode,
// match rules, create + dispatch alerts, advance the checkpoint.
type Poller struct {
	source   EventSource
	store    Store
	registry *rules.Registry
	dispatch Dispatcher
	interval time.Duration
	log      *slog.Logger
	// metrics is optional instrumentation; nil-safe, see internal/metrics.
	metrics *metrics.Metrics
	// telemetry is optional tracing; nil-safe like metrics. When set, every
	// poll cycle becomes one trace: fetch, decode, rule evaluation, the
	// alert write and each channel delivery hang off the same root span.
	telemetry *telemetry.Provider
	// scanned/matched accumulate per-cycle counts for metrics.
	scanned int
	matched int
	// pos is the last successful poll snapshot, stored as Position.
	// atomic.Value so HTTP handlers can read it without a mutex.
	pos atomic.Value
}

// Position returns the last successful poll snapshot. Safe to call from
// another goroutine (the HTTP health handler). Before the first successful
// poll the returned Position is the zero value and Ready is false.
func (p *Poller) Position() Position {
	if v := p.pos.Load(); v != nil {
		return v.(Position)
	}
	return Position{}
}

func (p *Poller) recordPosition(processed, latest uint32, at time.Time) {
	p.pos.Store(Position{
		LastProcessedLedger: processed,
		LatestChainLedger:   latest,
		LastSuccessfulPoll:  at.UTC(),
	})
}

// New wires a Poller. src is where events come from: NewRPCSource for a
// Stellar RPC node, or the SoroTrail source for upstream mode.
func New(src EventSource, st Store, reg *rules.Registry, d Dispatcher, interval time.Duration, log *slog.Logger) *Poller {
	return &Poller{
		source:   src,
		store:    st,
		registry: reg,
		dispatch: d,
		interval: interval,
		log:      log,
	}
}

// WithMetrics attaches Prometheus instrumentation to the poll loop.
func (p *Poller) WithMetrics(m *metrics.Metrics) *Poller {
	p.metrics = m
	return p
}

// WithTelemetry attaches tracing to the ingest pipeline. The provider's
// own disabled state decides whether anything is exported; a nil provider
// means no spans at all.
func (p *Poller) WithTelemetry(t *telemetry.Provider) *Poller {
	p.telemetry = t
	return p
}

// Run polls until ctx is cancelled. RPC errors back off exponentially
// (capped at 10x the poll interval) instead of hammering the node.
func (p *Poller) Run(ctx context.Context) {
	p.log.Info("poller started", "interval", p.interval)
	delay := p.interval
	for {
		select {
		case <-ctx.Done():
			p.log.Info("poller stopped")
			return
		case <-time.After(delay):
		}

		p.scanned, p.matched = 0, 0
		start := time.Now()
		err := p.Poll(ctx)
		p.metrics.RecordPoll(err == nil, time.Since(start))
		p.metrics.RecordEvents(p.scanned, p.matched)
		if err != nil {
			if ctx.Err() != nil {
				continue
			}
			delay = min(delay*2, 10*p.interval)
			p.log.Error("poll failed", "err", err, "retry_in", delay)
			continue
		}
		delay = p.interval
	}
}

// Poll runs one ingest cycle as a single trace. The root span
// (poller.poll) covers the whole cycle; fetch, rule evaluation, the alert
// write and — via the context the alert's span rides in — every channel
// delivery hang underneath it, so one late alert is one timeline answering
// which stage was slow. Exported so tests (and one-shot tools) can drive
// the poller without the timing loop.
func (p *Poller) Poll(ctx context.Context) error {
	if p.telemetry != nil {
		var span trace.Span
		ctx, span = p.telemetry.WithRequestID(ctx, "poller.poll")
		defer func() {
			telemetry.SetAttrs(span,
				telemetry.AttrEventsScanned, p.scanned,
				telemetry.AttrEventsMatched, p.matched,
			)
			span.End()
		}()
	}

	monitors, err := p.store.ListMonitors(ctx, true)
	if err != nil {
		return err
	}

	// Map each contract to the monitors watching it; dedupe contracts. Along
	// the way, collect the event names its enabled rules require so the source
	// can push a topic filter into getEvents instead of streaming events we
	// would immediately discard. A contract is only narrowed when every rule
	// watching it names a concrete event; otherwise it stays unfiltered.
	byContract := map[string][]store.Monitor{}
	var contracts []string
	namesByContract := map[string]map[string]bool{}
	unfilterable := map[string]bool{}
	for _, m := range monitors {
		ruleList, err := p.store.ListRules(ctx, m.ID, true)
		if err != nil {
			return err
		}
		names, ok := ruleEventNames(p.registry, ruleList)
		for _, c := range m.ContractIDs {
			// A single malformed ID makes the RPC reject the whole request,
			// stalling ingestion for every monitor — skip, don't send.
			if !stellar.IsValidContractID(c) {
				p.log.Warn("skipping invalid contract id", "monitor_id", m.ID, "contract_id", c)
				continue
			}
			if _, seen := byContract[c]; !seen {
				contracts = append(contracts, c)
			}
			byContract[c] = append(byContract[c], m)
			if unfilterable[c] {
				continue
			}
			if !ok {
				unfilterable[c] = true
				continue
			}
			if namesByContract[c] == nil {
				namesByContract[c] = map[string]bool{}
			}
			for _, n := range names {
				namesByContract[c][n] = true
			}
		}
	}
	if len(contracts) == 0 {
		return nil
	}

	// Compile the derived filters into the watch list the source sees. A nil
	// Topics is the safe default: no server-side narrowing.
	watch := make([]Watch, 0, len(contracts))
	for _, c := range contracts {
		w := Watch{ContractID: c}
		if !unfilterable[c] {
			w.Topics = topicFiltersFor(sortedKeys(namesByContract[c]))
		}
		watch = append(watch, w)
	}

	state, err := p.store.GetIngestState(ctx)
	if err != nil {
		return err
	}
	startLedger := state.LastLedger + 1
	if state.LastLedger == 0 {
		// Cold start against an RPC source: the node only retains ~1-7
		// days of events, so begin at the current tip. Upstream sources
		// (SoroTrail) hold durable history and answer the same query.
		latest, err := p.source.LatestLedger(ctx)
		if err != nil {
			return err
		}
		startLedger = latest
		p.log.Info("cold start", "start_ledger", startLedger)
	}

	// Page the source until it reports no more events for the cycle. The
	// cursor is opaque; batching (the RPC caps filters per request) is the
	// source's concern, encoded in its cursors.
	checkpoint := uint32(0) // min latestLedger across pages
	tip := uint32(0)        // max latestLedger across pages
	cursor := ""
	for {
		// One span per page covers both halves of the fetch: the RPC call
		// (or indexer request) and the local decode of what came back. That
		// is the "RPC fetch" stage of the slow-alert question; decode time
		// is inside it by design, since the source owns decoding. The span
		// ends before handleEvent so pages stay siblings under the cycle
		// span — otherwise page two would parent to page one.
		fetchCtx := ctx
		// NoopSpan keeps the error/End calls below uniform when tracing is
		// off — a nil interface would panic on End.
		fetchSpan := telemetry.NoopSpan()
		if p.telemetry != nil {
			fetchCtx, fetchSpan = p.telemetry.WithRequestID(ctx, "poller.fetch_events",
				trace.WithAttributes(
					attribute.Int(telemetry.AttrStartLedger, int(startLedger)),
					attribute.Int(telemetry.AttrContractsWatched, len(contracts)),
				),
			)
		}
		page, err := p.source.FetchEvents(fetchCtx, startLedger, watch, cursor, stellar.DefaultEventsLimit)
		if err != nil {
			telemetry.RecordError(fetchSpan, err)
			fetchSpan.End()
			return err
		}
		fetchSpan.End()

		if page.LatestLedger > 0 && (checkpoint == 0 || page.LatestLedger < checkpoint) {
			checkpoint = page.LatestLedger
		}
		if page.LatestLedger > tip {
			tip = page.LatestLedger
		}
		p.scanned += len(page.Events)
		for _, ev := range page.Events {
			p.handleEvent(ctx, ev, byContract)
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}

	// Lag: how far the checkpoint we reached trails the node's own tip.
	// Grows when a batch's page-through takes longer than ledger cadence.
	p.metrics.SetPollLag(int64(tip) - int64(checkpoint))
	if checkpoint > state.LastLedger {
		state.LastLedger = checkpoint
		state.LastCursor = ""
		if err := p.store.SetIngestState(ctx, state); err != nil {
			return err
		}
	}
	processed := checkpoint
	if processed == 0 {
		processed = state.LastLedger
	}
	p.recordPosition(processed, tip, time.Now())
	return nil
}

// handleEvent runs every enabled rule of every monitor watching the
// event's contract. Events arrive already decoded from the source;
// per-event failures are logged, not fatal: one bad event must not stall
// ingestion. Rule evaluation spans come from the registry, one per rule,
// each a child of the cycle span, on the same trace as the fetch page that
// produced the event.
func (p *Poller) handleEvent(ctx context.Context, decoded *stellar.DecodedEvent, byContract map[string][]store.Monitor) {
	monitors, watched := byContract[decoded.ContractID]
	if !watched {
		return
	}

	for _, m := range monitors {
		ruleList, err := p.store.ListRules(ctx, m.ID, true)
		if err != nil {
			p.log.Error("list rules", "monitor_id", m.ID, "err", err)
			continue
		}
		for _, rule := range ruleList {
			// The rule id rides in the context so a stateful evaluator (the
			// frequency rule) can key its per-rule state.
			ruleCtx := rules.WithRuleID(ctx, rule.ID)
			matched, err := p.registry.Evaluate(ruleCtx, rule.Type, decoded, rule.Params)
			if err != nil {
				p.log.Warn("rule evaluation failed", "rule_id", rule.ID, "event_id", decoded.ID, "err", err)
				continue
			}
			if matched {
				p.matched++
				p.metrics.RecordAlert()
				// An evaluator may override the dedup key (the frequency rule
				// stores every crossing in one episode under the window start).
				eventID := decoded.ID
				if id := p.registry.AlertEventID(ruleCtx, rule.Type, decoded, rule.Params); id != "" {
					eventID = id
				}
				p.fireAlert(ctx, m, rule, decoded, eventID)
			}
		}
	}
}

// fireAlert persists a deduped, cooldown-gated alert and hands it to the
// dispatcher. The store owns both gates so they hold across poller instances
// and restarts; this function only reports the outcome.
//
// The alert runs in its own span (poller.create_alert) under the poll
// cycle; Dispatch is called with that span's context, so every delivery
// span becomes a child of this alert's span — never a root. That parent
// chain is what ties one alert's full path into one timeline, and the
// poller test pins it.
func (p *Poller) fireAlert(ctx context.Context, m store.Monitor, rule store.Rule, ev *stellar.DecodedEvent, eventID string) {
	if p.telemetry != nil {
		var span trace.Span
		ctx, span = p.telemetry.WithRequestID(ctx, "poller.create_alert",
			trace.WithAttributes(
				attribute.Int64(telemetry.AttrMonitorID, m.ID),
				attribute.Int64(telemetry.AttrRuleID, rule.ID),
				attribute.String(telemetry.AttrEventID, eventID),
			),
		)
		defer span.End()
	}

	body := map[string]any{
		"contract_id":      ev.ContractID,
		"event_name":       ev.EventName(),
		"ledger":           ev.Ledger,
		"ledger_closed_at": ev.LedgerClosedAt,
		"tx_hash":          ev.TxHash,
		"topics":           ev.Topics,
		"value":            ev.Value,
	}
	// Named fields are only present when the contract's spec was available;
	// without one the payload is byte-for-byte what it has always been.
	if ev.Fields != nil {
		body["fields"] = ev.Fields
	}
	payload, err := json.Marshal(body)
	if err != nil {
		p.log.Error("marshal alert payload", "event_id", ev.ID, "err", err)
		return
	}

	alert := &store.Alert{
		MonitorID:      m.ID,
		RuleID:         rule.ID,
		EventID:        eventID,
		Payload:        payload,
		LedgerClosedAt: ev.LedgerClosedAt,
		Cooldown:       ruleCooldown(rule),
	}
	outcome, err := p.store.CreateAlert(ctx, alert)
	if err != nil {
		p.log.Error("create alert", "rule_id", rule.ID, "event_id", ev.ID, "err", err)
		return
	}
	switch outcome {
	case store.AlertDuplicate:
		return // dedup: this rule already fired for this event
	case store.AlertSuppressed:
		// Counted by the store; logged so an operator can see the rule is
		// firing far more often than it is alerting.
		p.log.Info("alert suppressed by cooldown",
			"rule_id", rule.ID, "event_id", ev.ID, "cooldown", alert.Cooldown)
		return
	}
	logAttrs := []any{"alert_id", alert.ID, "monitor", m.Name, "rule_id", rule.ID, "event_id", ev.ID}
	if alert.SuppressedSinceLast > 0 {
		logAttrs = append(logAttrs, "suppressed_since_last", alert.SuppressedSinceLast)
	}
	p.log.Info("alert created", logAttrs...)

	p.dispatch.Dispatch(ctx, notify.Alert{
		ID:          alert.ID,
		MonitorID:   m.ID,
		MonitorName: m.Name,
		RuleID:      rule.ID,
		RuleType:    rule.Type,
		EventID:     eventID,
		ContractID:  ev.ContractID,
		EventName:   ev.EventName(),
		Ledger:      ev.Ledger,
		TxHash:      ev.TxHash,
		// The store folds the suppressed count into the payload, so the
		// notification reports it too.
		Payload:   alert.Payload,
		CreatedAt: alert.CreatedAt,
	})
}

// ruleCooldown reads a rule's optional cooldown. It is validated when the rule
// is created, so a value that no longer parses is treated as "no cooldown"
// rather than dropping matches.
func ruleCooldown(rule store.Rule) time.Duration {
	d, err := rules.ParseCooldown(rule.Params)
	if err != nil {
		return 0
	}
	return d
}
