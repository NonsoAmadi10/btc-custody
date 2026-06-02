package policy

import (
	"fmt"
	"sync"
	"time"
)

// VelocityRule limits the total amount that can be sent within a time window.
//
// This prevents rapid draining of funds even if attackers gain signing access.
// Example: max 1 BTC per 24 hours.
type VelocityRule struct {
	maxAmount int64         // maximum satoshis allowed in window
	window    time.Duration // sliding window duration

	mu     sync.Mutex
	ledger []velocityEntry // recent transactions within window
}

type velocityEntry struct {
	amount    int64
	timestamp time.Time
}

// NewVelocityRule creates a velocity limit rule.
//
// Parameters:
//   - maxAmount: maximum satoshis allowed in the window
//   - window: duration of the sliding window (e.g., 24*time.Hour)
func NewVelocityRule(maxAmount int64, window time.Duration) *VelocityRule {
	return &VelocityRule{
		maxAmount: maxAmount,
		window:    window,
		ledger:    make([]velocityEntry, 0),
	}
}

// ID implements Rule.
func (r *VelocityRule) ID() string {
	return "velocity"
}

// Evaluate implements Rule.
func (r *VelocityRule) Evaluate(req *TransactionRequest) Decision {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Prune old entries outside the window
	r.prune()

	// Calculate current spending in window
	var currentSpend int64
	for _, entry := range r.ledger {
		currentSpend += entry.amount
	}

	// Check if this request would exceed the limit
	proposedTotal := currentSpend + req.TotalAmount
	if proposedTotal > r.maxAmount {
		return Deny(r.ID(), fmt.Sprintf(
			"velocity limit exceeded: %d + %d = %d sats, limit is %d sats per %v",
			currentSpend, req.TotalAmount, proposedTotal, r.maxAmount, r.window,
		))
	}

	return Allow(r.ID())
}

// RecordTransaction adds a transaction to the ledger after it's been signed.
// Call this after successful signing, not during Evaluate.
func (r *VelocityRule) RecordTransaction(amount int64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.ledger = append(r.ledger, velocityEntry{
		amount:    amount,
		timestamp: time.Now(),
	})
}

// prune removes entries older than the window. Must hold mu.
func (r *VelocityRule) prune() {
	cutoff := time.Now().Add(-r.window)

	// Find first entry that's within the window
	i := 0
	for ; i < len(r.ledger); i++ {
		if r.ledger[i].timestamp.After(cutoff) {
			break
		}
	}

	// Remove old entries
	if i > 0 {
		r.ledger = r.ledger[i:]
	}
}

// CurrentSpend returns the total amount spent in the current window.
func (r *VelocityRule) CurrentSpend() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.prune()

	var total int64
	for _, entry := range r.ledger {
		total += entry.amount
	}
	return total
}

// RemainingAllowance returns how much more can be spent in the current window.
func (r *VelocityRule) RemainingAllowance() int64 {
	return r.maxAmount - r.CurrentSpend()
}

// Reset clears the ledger. Use for testing or after a policy change.
func (r *VelocityRule) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ledger = r.ledger[:0]
}
