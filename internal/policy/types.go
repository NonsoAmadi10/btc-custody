// Package policy implements transaction authorization rules.
//
// The policy engine evaluates transaction requests against configurable rules
// before allowing FROST signing to proceed. This provides defense-in-depth:
// even if t signers are compromised, policy rules can block malicious txs.
//
// # Design Principles
//
//   - Deny by default: any rule failure blocks the transaction
//   - Auditable: every decision is logged with reasons
//   - Configurable: rules loaded from config, not hardcoded
//   - Testable: each rule is isolated and unit-tested
//
// # Available Rules
//
//   - WhitelistRule: only send to pre-approved addresses
//   - VelocityRule: cap withdrawals per time window
//   - TieredRule: require more approvals for larger amounts
//   - ScheduleRule: restrict signing to business hours
//   - QuorumRule: require N human approvals before signing
package policy

import "time"

// TransactionRequest represents a pending transaction to be evaluated.
type TransactionRequest struct {
	// ID is a unique identifier for this request (for audit logs).
	ID string

	// Destinations lists where funds will be sent.
	Destinations []Destination

	// TotalAmount is the sum of all destination amounts in satoshis.
	TotalAmount int64

	// RequestedBy identifies who initiated the request (email, user ID, etc.).
	RequestedBy string

	// RequestedAt is when the request was created.
	RequestedAt time.Time

	// Approvals contains human approvals collected for this request.
	Approvals []Approval

	// Metadata holds additional context (e.g., ticket number, reason).
	Metadata map[string]string
}

// Destination is a single output in a transaction.
type Destination struct {
	// Address is the Bitcoin address receiving funds.
	Address string

	// Amount is the value in satoshis being sent to this address.
	Amount int64
}

// Approval records a human approver's sign-off on a request.
type Approval struct {
	// ApproverID identifies who approved (email, employee ID, etc.).
	ApproverID string

	// ApprovedAt is when the approval was recorded.
	ApprovedAt time.Time

	// Method describes how approval was authenticated.
	// Examples: "yubikey", "totp", "manual", "biometric"
	Method string
}

// Decision is the result of evaluating a request against policy rules.
type Decision struct {
	// Allowed is true if the request passed all rules.
	Allowed bool

	// Reason explains why the request was allowed or denied.
	// For denials, this should be actionable (e.g., "address X not on whitelist").
	Reason string

	// RuleID identifies which rule made this decision.
	// Empty for aggregate decisions from the engine.
	RuleID string

	// Timestamp is when the decision was made.
	Timestamp time.Time
}

// Deny creates a denial decision with the given reason.
func Deny(ruleID, reason string) Decision {
	return Decision{
		Allowed:   false,
		Reason:    reason,
		RuleID:    ruleID,
		Timestamp: time.Now(),
	}
}

// Allow creates an approval decision.
func Allow(ruleID string) Decision {
	return Decision{
		Allowed:   true,
		Reason:    "passed",
		RuleID:    ruleID,
		Timestamp: time.Now(),
	}
}
