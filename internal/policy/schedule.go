package policy

import (
	"fmt"
	"time"
)

// ScheduleRule restricts signing to specific time windows.
//
// This limits the blast radius of a compromise: an attacker who gains
// signing access at 3am on a Sunday still can't sign transactions.
type ScheduleRule struct {
	// allowedDays specifies which days of the week are allowed.
	// Default: Monday through Friday.
	allowedDays map[time.Weekday]bool

	// startHour is the earliest hour (0-23) when signing is allowed.
	startHour int

	// endHour is the latest hour (0-23) when signing is allowed (exclusive).
	// If endHour < startHour, window wraps past midnight.
	endHour int

	// timezone for evaluating the schedule.
	timezone *time.Location
}

// ScheduleConfig configures a schedule rule.
type ScheduleConfig struct {
	AllowedDays []time.Weekday // empty = weekdays only
	StartHour   int            // 0-23, default 9
	EndHour     int            // 0-23, default 18
	Timezone    string         // IANA timezone, default "UTC"
}

// NewScheduleRule creates a schedule restriction rule.
func NewScheduleRule(cfg ScheduleConfig) (*ScheduleRule, error) {
	// Default timezone
	tz := time.UTC
	if cfg.Timezone != "" {
		var err error
		tz, err = time.LoadLocation(cfg.Timezone)
		if err != nil {
			return nil, fmt.Errorf("invalid timezone %q: %w", cfg.Timezone, err)
		}
	}

	// Default to weekdays
	allowedDays := make(map[time.Weekday]bool)
	if len(cfg.AllowedDays) == 0 {
		for _, d := range []time.Weekday{
			time.Monday, time.Tuesday, time.Wednesday,
			time.Thursday, time.Friday,
		} {
			allowedDays[d] = true
		}
	} else {
		for _, d := range cfg.AllowedDays {
			allowedDays[d] = true
		}
	}

	// Default hours: 9am to 6pm
	startHour := cfg.StartHour
	endHour := cfg.EndHour
	if startHour == 0 && endHour == 0 {
		startHour = 9
		endHour = 18
	}

	return &ScheduleRule{
		allowedDays: allowedDays,
		startHour:   startHour,
		endHour:     endHour,
		timezone:    tz,
	}, nil
}

// ID implements Rule.
func (r *ScheduleRule) ID() string {
	return "schedule"
}

// Evaluate implements Rule.
func (r *ScheduleRule) Evaluate(req *TransactionRequest) Decision {
	// Use request time, converted to the configured timezone
	t := req.RequestedAt.In(r.timezone)

	// Check day of week
	if !r.allowedDays[t.Weekday()] {
		return Deny(r.ID(), fmt.Sprintf(
			"%s is not an allowed day for signing",
			t.Weekday().String(),
		))
	}

	// Check time of day
	hour := t.Hour()
	if !r.isWithinHours(hour) {
		return Deny(r.ID(), fmt.Sprintf(
			"hour %d is outside allowed window (%d:00 - %d:00 %s)",
			hour, r.startHour, r.endHour, r.timezone.String(),
		))
	}

	return Allow(r.ID())
}

// isWithinHours checks if the given hour is within the allowed window.
func (r *ScheduleRule) isWithinHours(hour int) bool {
	if r.startHour <= r.endHour {
		// Normal window: e.g., 9-18
		return hour >= r.startHour && hour < r.endHour
	}
	// Wrapped window: e.g., 22-6 (night shift)
	return hour >= r.startHour || hour < r.endHour
}

// IsAllowedAt checks if a specific time is within the schedule.
// Useful for displaying schedule status in a UI.
func (r *ScheduleRule) IsAllowedAt(t time.Time) bool {
	t = t.In(r.timezone)
	return r.allowedDays[t.Weekday()] && r.isWithinHours(t.Hour())
}

// NextAllowedTime returns when signing will next be allowed.
// Returns zero time if signing is currently allowed.
func (r *ScheduleRule) NextAllowedTime(from time.Time) time.Time {
	from = from.In(r.timezone)

	if r.IsAllowedAt(from) {
		return time.Time{}
	}

	// Try each hour up to 7 days out
	t := from.Truncate(time.Hour).Add(time.Hour)
	for i := 0; i < 24*7; i++ {
		if r.IsAllowedAt(t) {
			return t
		}
		t = t.Add(time.Hour)
	}

	// No allowed time found (shouldn't happen with valid config)
	return time.Time{}
}
