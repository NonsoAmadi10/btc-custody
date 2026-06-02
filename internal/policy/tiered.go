package policy

import (
	"fmt"
	"sort"
)

// TieredRule requires different approval counts based on transaction amount.
//
// This implements the principle that larger transactions need more scrutiny.
// Example tiers:
//   - < 100,000 sats (0.001 BTC): auto-approve (0 approvals)
//   - < 10,000,000 sats (0.1 BTC): 1 approval
//   - >= 10,000,000 sats: 2 approvals
type TieredRule struct {
	tiers []Tier
}

// Tier defines an amount threshold and required approval count.
type Tier struct {
	// MaxAmount is the upper bound (exclusive) for this tier, in satoshis.
	// Use -1 for unlimited (the "catch-all" tier for largest amounts).
	MaxAmount int64

	// RequiredApprovals is how many human approvals are needed.
	RequiredApprovals int

	// Label is a human-readable name for this tier (e.g., "small", "medium", "large").
	Label string
}

// NewTieredRule creates a tiered approval rule.
// Tiers are automatically sorted by MaxAmount.
func NewTieredRule(tiers []Tier) *TieredRule {
	// Sort tiers by MaxAmount ascending (-1 goes last)
	sorted := make([]Tier, len(tiers))
	copy(sorted, tiers)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].MaxAmount == -1 {
			return false
		}
		if sorted[j].MaxAmount == -1 {
			return true
		}
		return sorted[i].MaxAmount < sorted[j].MaxAmount
	})

	return &TieredRule{tiers: sorted}
}

// ID implements Rule.
func (r *TieredRule) ID() string {
	return "tiered"
}

// Evaluate implements Rule.
func (r *TieredRule) Evaluate(req *TransactionRequest) Decision {
	if len(r.tiers) == 0 {
		return Deny(r.ID(), "no tiers configured")
	}

	// Find the applicable tier
	tier := r.tierFor(req.TotalAmount)
	if tier == nil {
		return Deny(r.ID(), fmt.Sprintf("no tier covers amount %d sats", req.TotalAmount))
	}

	// Count valid approvals
	approvalCount := len(req.Approvals)

	if approvalCount < tier.RequiredApprovals {
		return Deny(r.ID(), fmt.Sprintf(
			"amount %d sats requires %d approvals (tier: %s), but only %d provided",
			req.TotalAmount, tier.RequiredApprovals, tier.Label, approvalCount,
		))
	}

	return Allow(r.ID())
}

// tierFor returns the tier applicable to the given amount.
func (r *TieredRule) tierFor(amount int64) *Tier {
	for i := range r.tiers {
		tier := &r.tiers[i]
		if tier.MaxAmount == -1 || amount < tier.MaxAmount {
			return tier
		}
	}
	return nil
}

// TierFor returns the tier that applies to the given amount (for inspection).
func (r *TieredRule) TierFor(amount int64) *Tier {
	return r.tierFor(amount)
}

// Tiers returns a copy of the tier configuration.
func (r *TieredRule) Tiers() []Tier {
	result := make([]Tier, len(r.tiers))
	copy(result, r.tiers)
	return result
}
