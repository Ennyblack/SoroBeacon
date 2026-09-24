-- SQLite equivalent of the Postgres 0008_monitor_templates. JSONB becomes
-- TEXT, BIGINT[] becomes TEXT holding a JSON array (decoded by the Go
-- layer, mirroring how monitors.contract_ids is stored), TIMESTAMPTZ
-- becomes TEXT in the fixed format.
CREATE TABLE monitor_templates (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    description TEXT    NOT NULL DEFAULT '',
    rules       TEXT    NOT NULL DEFAULT '[]',
    channel_ids TEXT    NOT NULL DEFAULT '[]',
    parameters  TEXT    NOT NULL DEFAULT '[]',
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
