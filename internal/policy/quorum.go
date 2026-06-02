package policy

import (
	"fmt"
	"time"
)

// QuorumRule requires a minimum number of human approvals.
//
// This ensures that signing cannot proceed without explicit human authorization.
// Approvals are verified against a list of valid approvers.
type QuorumRule struct {
	// requiredCount is the minimum number of approvals needed.
	requiredCount int

	// validApprovers maps approver IDs to their names/roles.
	// Only approvals from these IDs are counted.
	validApprovers map[string]string

	// maxApprovalAge is how long an approval remains valid.
	// Default: 1 hour. Set to 0 for no expiry.
	maxApprovalAge time.Duration
}

// NewQuorumRule creates a quorum rule requiring N approvals.
func NewQuorumRule(requiredCount int, validApprovers map[string]string) *QuorumRule {
	if validApprovers == nil {
		validApprovers = make(map[string]string)
	}
	return &QuorumRule{
		requiredCount:  requiredCount,
		validApprovers: validApprovers,
		maxApprovalAge: time.Hour,
	}
}

// SetMaxApprovalAge configures how long approvals remain valid.
func (r *QuorumRule) SetMaxApprovalAge(d time.Duration) {
	r.maxApprovalAge = d
}

// ID implements Rule.
func (r *QuorumRule) ID() string {
	return "quorum"
}

// Evaluate implements Rule.
func (r *QuorumRule) Evaluate(req *TransactionRequest) Decision {
	if r.requiredCount == 0 {
		return Allow(r.ID())
	}

	if len(r.validApprovers) == 0 {
		return Deny(r.ID(), "no valid approvers configured")
	}

	// Count valid, non-expired approvals
	validCount := 0
	now := time.Now()

	for _, approval := range req.Approvals {
		// Check if approver is in the valid list
		if _, ok := r.validApprovers[approval.ApproverID]; !ok {
			continue
		}

		// Check if approval has expired
		if r.maxApprovalAge > 0 {
			age := now.Sub(approval.ApprovedAt)
			if age > r.maxApprovalAge {
				continue
			}
		}

		validCount++
	}

	if validCount < r.requiredCount {
		return Deny(r.ID(), fmt.Sprintf(
			"requires %d approvals but only %d valid approvals present",
			r.requiredCount, validCount,
		))
	}

	return Allow(r.ID())
}

// AddApprover adds a valid approver.
func (r *QuorumRule) AddApprover(id, name string) {
	r.validApprovers[id] = name
}

// RemoveApprover removes a valid approver.
func (r *QuorumRule) RemoveApprover(id string) {
	delete(r.validApprovers, id)
}

// RequiredCount returns the number of approvals needed.
func (r *QuorumRule) RequiredCount() int {
	return r.requiredCount
}

// ValidApprovers returns a copy of the valid approvers map.
func (r *QuorumRule) ValidApprovers() map[string]string {
	result := make(map[string]string, len(r.validApprovers))
	for k, v := range r.validApprovers {
		result[k] = v
	}
	return result
}
