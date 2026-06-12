package policy

import (
	"fmt"
	"strings"
	"time"
)

// Engine evaluates transaction requests against a set of policy rules.
//
// The engine runs all rules and returns a decision. If any rule denies
// the request, the engine short-circuits and returns that denial.
// All rules must pass for the request to be allowed.
type Engine struct {
	rules []Rule
}

// NewEngine creates a policy engine with the given rules.
// Rules are evaluated in the order provided.
func NewEngine(rules ...Rule) *Engine {
	return &Engine{rules: rules}
}

// AddRule appends a rule to the engine.
func (e *Engine) AddRule(r Rule) {
	e.rules = append(e.rules, r)
}

// Evaluate runs all rules against the request.
//
// Returns:
//   - Allow if all rules pass
//   - Deny with reason from first failing rule
//
// The engine short-circuits on first denial for efficiency.
func (e *Engine) Evaluate(req *TransactionRequest) Decision {
	if len(e.rules) == 0 {
		return Deny("engine", "no rules configured (deny by default)")
	}

	var passed []string

	for _, rule := range e.rules {
		decision := rule.Evaluate(req)
		if !decision.Allowed {
			// Short-circuit: return first denial
			return decision
		}
		passed = append(passed, rule.ID())
	}

	return Decision{
		Allowed:   true,
		Reason:    fmt.Sprintf("passed %d rules: %s", len(passed), strings.Join(passed, ", ")),
		RuleID:    "engine",
		Timestamp: time.Now(),
	}
}

// EvaluateAll runs all rules and returns all decisions (no short-circuit).
// Useful for debugging or showing all failing rules at once.
func (e *Engine) EvaluateAll(req *TransactionRequest) []Decision {
	decisions := make([]Decision, 0, len(e.rules))
	for _, rule := range e.rules {
		decisions = append(decisions, rule.Evaluate(req))
	}
	return decisions
}

// Rules returns the list of rules in evaluation order.
func (e *Engine) Rules() []Rule {
	return e.rules
}

// RecordTransaction updates stateful rules (like velocity) after a transaction
// is successfully signed. Call this after signing completes.
func (e *Engine) RecordTransaction(amount int64) {
	for _, rule := range e.rules {
		if vr, ok := rule.(*VelocityRule); ok {
			vr.RecordTransaction(amount)
		}
	}
}
