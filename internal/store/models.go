package store

import (
	"time"
)

// DeadLetter represents a permanently failed alert delivery attempt.
type DeadLetter struct {
	ID              int64     `json:"id"`
	AlertID         int64     `json:"alert_id"`
	ChannelID       int64     `json:"channel_id"`
	LastError       string    `json:"last_error"`
	AttemptCount    int       `json:"attempt_count"`
	LastStatus      int       `json:"last_status"`
	CreatedAt       time.Time `json:"created_at"`
}

// DeadLetterFilter controls pagination and filtering for dead-letter lists.
type DeadLetterFilter struct {
	MonitorID *int64
	ChannelID *int64
	Limit     int
	Cursor    string
}
