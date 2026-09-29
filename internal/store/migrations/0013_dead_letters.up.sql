CREATE TABLE dead_letters (
    id BIGSERIAL PRIMARY KEY,
    alert_id BIGINT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    channel_id BIGINT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    last_error TEXT NOT NULL DEFAULT '',
    attempt_count INT NOT NULL DEFAULT 1,
    last_status INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_dead_letters_monitor ON dead_letters(alert_id);
CREATE INDEX idx_dead_letters_channel ON dead_letters(channel_id);
