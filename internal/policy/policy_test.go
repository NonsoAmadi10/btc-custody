package policy

import (
	"testing"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════
// Engine Tests
// ═══════════════════════════════════════════════════════════════════════════

func TestEngine_NoRules(t *testing.T) {
	engine := NewEngine()
	req := &TransactionRequest{ID: "test"}

	decision := engine.Evaluate(req)

	if decision.Allowed {
		t.Error("expected deny when no rules configured")
	}
	if decision.RuleID != "engine" {
		t.Errorf("expected ruleID 'engine', got %q", decision.RuleID)
	}
}

func TestEngine_AllPass(t *testing.T) {
	engine := NewEngine(
		NewRuleFunc("rule1", func(*TransactionRequest) Decision { return Allow("rule1") }),
		NewRuleFunc("rule2", func(*TransactionRequest) Decision { return Allow("rule2") }),
	)
	req := &TransactionRequest{ID: "test"}

	decision := engine.Evaluate(req)

	if !decision.Allowed {
		t.Errorf("expected allow, got deny: %s", decision.Reason)
	}
}

func TestEngine_ShortCircuitOnDeny(t *testing.T) {
	callCount := 0
	engine := NewEngine(
		NewRuleFunc("rule1", func(*TransactionRequest) Decision { return Allow("rule1") }),
		NewRuleFunc("rule2", func(*TransactionRequest) Decision { return Deny("rule2", "blocked") }),
		NewRuleFunc("rule3", func(*TransactionRequest) Decision {
			callCount++
			return Allow("rule3")
		}),
	)
	req := &TransactionRequest{ID: "test"}

	decision := engine.Evaluate(req)

	if decision.Allowed {
		t.Error("expected deny")
	}
	if decision.RuleID != "rule2" {
		t.Errorf("expected ruleID 'rule2', got %q", decision.RuleID)
	}
	if callCount != 0 {
		t.Error("rule3 should not have been called (short-circuit)")
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Whitelist Tests
// ═══════════════════════════════════════════════════════════════════════════

func TestWhitelist_AllowedAddress(t *testing.T) {
	rule := NewWhitelistRule(map[string]string{
		"bc1qtest": "Test Address",
	})
	req := &TransactionRequest{
		Destinations: []Destination{{Address: "bc1qtest", Amount: 1000}},
	}

	decision := rule.Evaluate(req)

	if !decision.Allowed {
		t.Errorf("expected allow, got: %s", decision.Reason)
	}
}

func TestWhitelist_BlockedAddress(t *testing.T) {
	rule := NewWhitelistRule(map[string]string{
		"bc1qtest": "Test Address",
	})
	req := &TransactionRequest{
		Destinations: []Destination{{Address: "bc1qevil", Amount: 1000}},
	}

	decision := rule.Evaluate(req)

	if decision.Allowed {
		t.Error("expected deny for non-whitelisted address")
	}
}

func TestWhitelist_PrefixMatch(t *testing.T) {
	rule := NewWhitelistRule(nil)
	rule.AddPrefix("tb1p") // all testnet Taproot

	req := &TransactionRequest{
		Destinations: []Destination{
			{Address: "tb1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqp3mvzv", Amount: 1000},
		},
	}

	decision := rule.Evaluate(req)

	if !decision.Allowed {
		t.Errorf("expected allow for prefix match, got: %s", decision.Reason)
	}
}

func TestWhitelist_EmptyList(t *testing.T) {
	rule := NewWhitelistRule(nil)
	req := &TransactionRequest{
		Destinations: []Destination{{Address: "bc1qtest", Amount: 1000}},
	}

	decision := rule.Evaluate(req)

	if decision.Allowed {
		t.Error("expected deny when whitelist is empty")
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Velocity Tests
// ═══════════════════════════════════════════════════════════════════════════

func TestVelocity_UnderLimit(t *testing.T) {
	rule := NewVelocityRule(100_000_000, 24*time.Hour) // 1 BTC per day
	req := &TransactionRequest{
		TotalAmount: 50_000_000, // 0.5 BTC
	}

	decision := rule.Evaluate(req)

	if !decision.Allowed {
		t.Errorf("expected allow, got: %s", decision.Reason)
	}
}

func TestVelocity_OverLimit(t *testing.T) {
	rule := NewVelocityRule(100_000_000, 24*time.Hour)
	req := &TransactionRequest{
		TotalAmount: 150_000_000, // 1.5 BTC
	}

	decision := rule.Evaluate(req)

	if decision.Allowed {
		t.Error("expected deny when over velocity limit")
	}
}

func TestVelocity_CumulativeLimit(t *testing.T) {
	rule := NewVelocityRule(100_000_000, 24*time.Hour)

	// First transaction: 0.6 BTC
	rule.RecordTransaction(60_000_000)

	// Second transaction: 0.5 BTC (would exceed 1 BTC total)
	req := &TransactionRequest{
		TotalAmount: 50_000_000,
	}

	decision := rule.Evaluate(req)

	if decision.Allowed {
		t.Error("expected deny when cumulative spend exceeds limit")
	}
}

func TestVelocity_RemainingAllowance(t *testing.T) {
	rule := NewVelocityRule(100_000_000, 24*time.Hour)
	rule.RecordTransaction(30_000_000)

	remaining := rule.RemainingAllowance()
	expected := int64(70_000_000)

	if remaining != expected {
		t.Errorf("expected remaining %d, got %d", expected, remaining)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Tiered Tests
// ═══════════════════════════════════════════════════════════════════════════

func TestTiered_AutoApproveSmall(t *testing.T) {
	rule := NewTieredRule([]Tier{
		{MaxAmount: 100_000, RequiredApprovals: 0, Label: "small"},
		{MaxAmount: -1, RequiredApprovals: 2, Label: "large"},
	})
	req := &TransactionRequest{
		TotalAmount: 50_000, // under 100k, no approval needed
	}

	decision := rule.Evaluate(req)

	if !decision.Allowed {
		t.Errorf("expected auto-approve for small amount, got: %s", decision.Reason)
	}
}

func TestTiered_RequireApprovalLarge(t *testing.T) {
	rule := NewTieredRule([]Tier{
		{MaxAmount: 100_000, RequiredApprovals: 0, Label: "small"},
		{MaxAmount: -1, RequiredApprovals: 2, Label: "large"},
	})
	req := &TransactionRequest{
		TotalAmount: 500_000,      // over 100k, needs 2 approvals
		Approvals:   []Approval{}, // no approvals
	}

	decision := rule.Evaluate(req)

	if decision.Allowed {
		t.Error("expected deny for large amount without approvals")
	}
}

func TestTiered_SufficientApprovals(t *testing.T) {
	rule := NewTieredRule([]Tier{
		{MaxAmount: 100_000, RequiredApprovals: 0, Label: "small"},
		{MaxAmount: -1, RequiredApprovals: 2, Label: "large"},
	})
	req := &TransactionRequest{
		TotalAmount: 500_000,
		Approvals: []Approval{
			{ApproverID: "alice", ApprovedAt: time.Now()},
			{ApproverID: "bob", ApprovedAt: time.Now()},
		},
	}

	decision := rule.Evaluate(req)

	if !decision.Allowed {
		t.Errorf("expected allow with sufficient approvals, got: %s", decision.Reason)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Schedule Tests
// ═══════════════════════════════════════════════════════════════════════════

func TestSchedule_DuringBusinessHours(t *testing.T) {
	rule, err := NewScheduleRule(ScheduleConfig{
		StartHour: 9,
		EndHour:   18,
		Timezone:  "UTC",
	})
	if err != nil {
		t.Fatalf("NewScheduleRule: %v", err)
	}

	// Tuesday at 2pm UTC
	requestTime := time.Date(2024, 6, 4, 14, 0, 0, 0, time.UTC)
	req := &TransactionRequest{
		RequestedAt: requestTime,
	}

	decision := rule.Evaluate(req)

	if !decision.Allowed {
		t.Errorf("expected allow during business hours, got: %s", decision.Reason)
	}
}

func TestSchedule_OutsideBusinessHours(t *testing.T) {
	rule, err := NewScheduleRule(ScheduleConfig{
		StartHour: 9,
		EndHour:   18,
		Timezone:  "UTC",
	})
	if err != nil {
		t.Fatalf("NewScheduleRule: %v", err)
	}

	// Tuesday at 3am UTC
	requestTime := time.Date(2024, 6, 4, 3, 0, 0, 0, time.UTC)
	req := &TransactionRequest{
		RequestedAt: requestTime,
	}

	decision := rule.Evaluate(req)

	if decision.Allowed {
		t.Error("expected deny outside business hours")
	}
}

func TestSchedule_Weekend(t *testing.T) {
	rule, err := NewScheduleRule(ScheduleConfig{
		StartHour: 9,
		EndHour:   18,
		Timezone:  "UTC",
	})
	if err != nil {
		t.Fatalf("NewScheduleRule: %v", err)
	}

	// Saturday at noon UTC
	requestTime := time.Date(2024, 6, 8, 12, 0, 0, 0, time.UTC)
	req := &TransactionRequest{
		RequestedAt: requestTime,
	}

	decision := rule.Evaluate(req)

	if decision.Allowed {
		t.Error("expected deny on weekend")
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Quorum Tests
// ═══════════════════════════════════════════════════════════════════════════

func TestQuorum_SufficientApprovals(t *testing.T) {
	rule := NewQuorumRule(2, map[string]string{
		"alice": "Alice",
		"bob":   "Bob",
		"carol": "Carol",
	})
	req := &TransactionRequest{
		Approvals: []Approval{
			{ApproverID: "alice", ApprovedAt: time.Now()},
			{ApproverID: "bob", ApprovedAt: time.Now()},
		},
	}

	decision := rule.Evaluate(req)

	if !decision.Allowed {
		t.Errorf("expected allow with 2 approvals, got: %s", decision.Reason)
	}
}

func TestQuorum_InsufficientApprovals(t *testing.T) {
	rule := NewQuorumRule(2, map[string]string{
		"alice": "Alice",
		"bob":   "Bob",
	})
	req := &TransactionRequest{
		Approvals: []Approval{
			{ApproverID: "alice", ApprovedAt: time.Now()},
		},
	}

	decision := rule.Evaluate(req)

	if decision.Allowed {
		t.Error("expected deny with only 1 approval when 2 required")
	}
}

func TestQuorum_InvalidApprover(t *testing.T) {
	rule := NewQuorumRule(1, map[string]string{
		"alice": "Alice",
	})
	req := &TransactionRequest{
		Approvals: []Approval{
			{ApproverID: "mallory", ApprovedAt: time.Now()}, // not a valid approver
		},
	}

	decision := rule.Evaluate(req)

	if decision.Allowed {
		t.Error("expected deny when approver is not in valid list")
	}
}

func TestQuorum_ExpiredApproval(t *testing.T) {
	rule := NewQuorumRule(1, map[string]string{
		"alice": "Alice",
	})
	rule.SetMaxApprovalAge(time.Hour)

	req := &TransactionRequest{
		Approvals: []Approval{
			{ApproverID: "alice", ApprovedAt: time.Now().Add(-2 * time.Hour)}, // expired
		},
	}

	decision := rule.Evaluate(req)

	if decision.Allowed {
		t.Error("expected deny when approval has expired")
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Integration Tests
// ═══════════════════════════════════════════════════════════════════════════

func TestFullPolicyEvaluation(t *testing.T) {
	// Build a policy with all rules
	whitelist := NewWhitelistRule(map[string]string{
		"bc1qsafe": "Safe Address",
	})

	velocity := NewVelocityRule(100_000_000, 24*time.Hour)

	tiered := NewTieredRule([]Tier{
		{MaxAmount: 1_000_000, RequiredApprovals: 0, Label: "small"},
		{MaxAmount: -1, RequiredApprovals: 1, Label: "large"},
	})

	schedule, _ := NewScheduleRule(ScheduleConfig{
		StartHour: 0, // allow all hours for test
		EndHour:   24,
		AllowedDays: []time.Weekday{
			time.Sunday, time.Monday, time.Tuesday,
			time.Wednesday, time.Thursday, time.Friday, time.Saturday,
		},
	})

	quorum := NewQuorumRule(1, map[string]string{
		"alice": "Alice",
	})

	engine := NewEngine(whitelist, velocity, tiered, schedule, quorum)

	// Request that passes all rules
	req := &TransactionRequest{
		ID: "tx-001",
		Destinations: []Destination{
			{Address: "bc1qsafe", Amount: 500_000},
		},
		TotalAmount: 500_000,
		RequestedBy: "system",
		RequestedAt: time.Now(),
		Approvals: []Approval{
			{ApproverID: "alice", ApprovedAt: time.Now()},
		},
	}

	decision := engine.Evaluate(req)

	if !decision.Allowed {
		t.Errorf("expected allow, got: %s (rule: %s)", decision.Reason, decision.RuleID)
	}
}

func TestFullPolicyDenial(t *testing.T) {
	whitelist := NewWhitelistRule(map[string]string{
		"bc1qsafe": "Safe Address",
	})

	engine := NewEngine(whitelist)

	// Request with non-whitelisted address
	req := &TransactionRequest{
		Destinations: []Destination{
			{Address: "bc1qevil", Amount: 1000},
		},
	}

	decision := engine.Evaluate(req)

	if decision.Allowed {
		t.Error("expected deny for non-whitelisted address")
	}
	if decision.RuleID != "whitelist" {
		t.Errorf("expected whitelist rule to deny, got: %s", decision.RuleID)
	}
}
