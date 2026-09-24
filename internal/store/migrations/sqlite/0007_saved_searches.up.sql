-- SQLite equivalent of the Postgres 0007_saved_searches. JSONB becomes TEXT,
-- TIMESTAMPTZ becomes TEXT in the fixed 'YYYY-MM-DDTHH:MM:SS.mmmZ' format,
-- BOOLEAN becomes INTEGER 0/1. The partial unique index on is_default has
-- no SQLite equivalent with identical semantics, so the single-default
-- invariant is enforced by the Go layer (as on Postgres, which also clears
-- other defaults in the same statement).
CREATE TABLE saved_searches (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL,
    filter     TEXT    NOT NULL DEFAULT '{}',
    is_default INTEGER NOT NULL DEFAULT 0,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
