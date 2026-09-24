// Package poller ingests Soroban contract events from a Stellar RPC node
// and feeds them through the rules engine, creating and dispatching alerts.
package poller

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/sorotrail/sorobeacon/internal/alerts"
	"github.com/sorotrail/sorobeacon/internal/metrics"
	"github.com/sorotrail/sorobeacon/internal/notify"
	"github.com/sorotrail/sorobeacon/internal/rules"
	"github.com/sorotrail/sorobeacon/internal/stellar"
	"github.com/sorotrail/sorobeacon/internal/store"
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
	GroupAlerts(ctx context.Context, key string, windowStart time.Time) (shouldDeliver bool, currentCount int64, err error)
	CreateAlertGroup(ctx context.Context, key string, windowStart time.Time) (int64, error)
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
	// scanned/matched accumulate per-cycle counts for metrics.
	scanned int
	matched int
	// pos is the last successful poll snapshot, stored as Position.
	// atomic.Value so HTTP handlers can read it without a mutex.
	pos atomic.Value
	// GroupWindow is the duration of the fixed tumbling window for
	// alert grouping. Zero means grouping is disabled and all alerts
	// are dispatched normally, preserving the pre-existing behaviour
	// for existing deployments.
	GroupWindow time.Duration
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

// WithGroupWindow sets the grouping window duration. A zero value
// disables grouping so all alerts dispatch immediately, matching
// the default behaviour for existing deployments.
func (p *Poller) WithGroupWindow(d time.Duration) *Poller {
	p.GroupWindow = d
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

// Poll runs one ingest cycle. Exported so tests (and one-shot tools) can
// drive the poller without the timing loop.
func (p *Poller) Poll(ctx context.Context) error {
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
		page, err := p.source.FetchEvents(ctx, startLedger, watch, cursor, stellar.DefaultEventsLimit)
		if err != nil {
			return err
		}
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

// pollBatch pages through getEvents for one set of filters, following the
// cursor until the stream is drained. Returns the node's latestLedger.
// handleEvent runs every enabled rule of every monitor watching the
// event's contract. Events arrive already decoded from the source;
// per-event failures are logged, not fatal: one bad event must not stall
// ingestion.
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
func (p *Poller) fireAlert(ctx context.Context, m store.Monitor, rule store.Rule, ev *stellar.DecodedEvent, eventID string) {
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

	// Grouping decision: if a window is configured, check the group
	// state before dispatching. The first alert in the window is
	// delivered immediately; subsequent alerts are suppressed until
	// the window closes and a summary is delivered.
	groupCount := int64(0)
	windowStart := time.Time{}
	windowEnd := time.Time{}
	if p.GroupWindow > 0 {
		windowStart = ev.LedgerClosedAt.Truncate(p.GroupWindow)
		windowEnd = windowStart.Add(p.GroupWindow)
		key := alerts.MakeGroupKey(m.ID, rule.ID, ev.ContractID).String()
		count, err := p.store.CreateAlertGroup(ctx, key, windowStart)
		if err != nil {
			p.log.Error("create alert group", "key", key, "window_start", windowStart, "err", err)
		} else {
			groupCount = count
			if count > 1 {
				// This alert is part of an existing window: it is
				// not delivered individually; the summary covers it.
				p.log.Info("alert grouped, suppressed",
					"key", key, "window_start", windowStart, "group_count", count)
				return
			}
		}
	}

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
		// GroupCount is 1 for the first alert in a window (the one
		// we are delivering now) and 0 when grouping is disabled.
		GroupCount: groupCount,
		WindowStart: windowStart,
		WindowEnd:   windowEnd,
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
