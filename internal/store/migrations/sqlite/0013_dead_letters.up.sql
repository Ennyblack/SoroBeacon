CREATE TABLE dead_letters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    channel_id INTEGER NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    last_error TEXT NOT NULL DEFAULT '',
    attempt_count INTEGER NOT NULL DEFAULT 1,
    last_status INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE INDEX idx_dead_letters_monitor ON dead_letters(alert_id);
CREATE INDEX idx_dead_letters_channel ON dead_letters(channel_id);
