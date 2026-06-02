package policy

// Rule is the interface that all policy rules must implement.
//
// Each rule evaluates a transaction request and returns a decision.
// Rules should be stateless where possible; any state (e.g., velocity
// tracking) should be injected via the rule's constructor.
type Rule interface {
	// ID returns a unique identifier for this rule (e.g., "whitelist", "velocity").
	// Used in decision logs and error messages.
	ID() string

	// Evaluate checks the request against this rule's criteria.
	// Returns Allow if the request passes, Deny with a reason if it fails.
	Evaluate(req *TransactionRequest) Decision
}

// RuleFunc is an adapter to allow ordinary functions to be used as Rules.
// Useful for simple inline rules or testing.
type RuleFunc struct {
	id string
	fn func(*TransactionRequest) Decision
}

// NewRuleFunc creates a Rule from a function.
func NewRuleFunc(id string, fn func(*TransactionRequest) Decision) Rule {
	return &RuleFunc{id: id, fn: fn}
}

func (r *RuleFunc) ID() string {
	return r.id
}

func (r *RuleFunc) Evaluate(req *TransactionRequest) Decision {
	return r.fn(req)
}
