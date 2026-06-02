package policy

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the complete policy configuration.
type Config struct {
	Whitelist WhitelistConfig `yaml:"whitelist"`
	Velocity  VelocityConfig  `yaml:"velocity"`
	Tiered    TieredConfig    `yaml:"tiered"`
	Schedule  ScheduleConfig  `yaml:"schedule"`
	Quorum    QuorumConfig    `yaml:"quorum"`
}

// WhitelistConfig configures the whitelist rule.
type WhitelistConfig struct {
	Addresses map[string]string `yaml:"addresses"` // address -> label
	Prefixes  []string          `yaml:"prefixes"`  // allowed address prefixes
}

// VelocityConfig configures the velocity rule.
type VelocityConfig struct {
	MaxAmount int64  `yaml:"max_amount"` // satoshis
	Window    string `yaml:"window"`     // duration string, e.g., "24h"
}

// TieredConfig configures the tiered approval rule.
type TieredConfig struct {
	Tiers []TierConfig `yaml:"tiers"`
}

// TierConfig is a single tier in the tiered rule.
type TierConfig struct {
	MaxAmount         int64  `yaml:"max_amount"`         // -1 for unlimited
	RequiredApprovals int    `yaml:"required_approvals"`
	Label             string `yaml:"label"`
}

// QuorumConfig configures the quorum rule.
type QuorumConfig struct {
	RequiredCount  int               `yaml:"required_count"`
	ValidApprovers map[string]string `yaml:"valid_approvers"` // id -> name
	MaxApprovalAge string            `yaml:"max_approval_age"` // duration string
}

// LoadConfig reads a policy configuration from a YAML file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config YAML: %w", err)
	}

	return &cfg, nil
}

// BuildEngine creates an Engine from the configuration.
func (c *Config) BuildEngine() (*Engine, error) {
	var rules []Rule

	// Whitelist rule
	if len(c.Whitelist.Addresses) > 0 || len(c.Whitelist.Prefixes) > 0 {
		wl := NewWhitelistRule(c.Whitelist.Addresses)
		for _, p := range c.Whitelist.Prefixes {
			wl.AddPrefix(p)
		}
		rules = append(rules, wl)
	}

	// Velocity rule
	if c.Velocity.MaxAmount > 0 && c.Velocity.Window != "" {
		window, err := time.ParseDuration(c.Velocity.Window)
		if err != nil {
			return nil, fmt.Errorf("invalid velocity window %q: %w", c.Velocity.Window, err)
		}
		rules = append(rules, NewVelocityRule(c.Velocity.MaxAmount, window))
	}

	// Tiered rule
	if len(c.Tiered.Tiers) > 0 {
		tiers := make([]Tier, len(c.Tiered.Tiers))
		for i, t := range c.Tiered.Tiers {
			tiers[i] = Tier{
				MaxAmount:         t.MaxAmount,
				RequiredApprovals: t.RequiredApprovals,
				Label:             t.Label,
			}
		}
		rules = append(rules, NewTieredRule(tiers))
	}

	// Schedule rule
	if c.Schedule.StartHour != 0 || c.Schedule.EndHour != 0 || len(c.Schedule.AllowedDays) > 0 {
		sched, err := NewScheduleRule(c.Schedule)
		if err != nil {
			return nil, fmt.Errorf("invalid schedule config: %w", err)
		}
		rules = append(rules, sched)
	}

	// Quorum rule
	if c.Quorum.RequiredCount > 0 {
		q := NewQuorumRule(c.Quorum.RequiredCount, c.Quorum.ValidApprovers)
		if c.Quorum.MaxApprovalAge != "" {
			age, err := time.ParseDuration(c.Quorum.MaxApprovalAge)
			if err != nil {
				return nil, fmt.Errorf("invalid max_approval_age %q: %w", c.Quorum.MaxApprovalAge, err)
			}
			q.SetMaxApprovalAge(age)
		}
		rules = append(rules, q)
	}

	return NewEngine(rules...), nil
}

// ExampleConfig returns a sample configuration for documentation.
func ExampleConfig() Config {
	return Config{
		Whitelist: WhitelistConfig{
			Addresses: map[string]string{
				"bc1qexchangecoldwallet": "Exchange Cold Wallet",
				"bc1qpayroll":            "Payroll Account",
			},
			Prefixes: []string{"tb1p"}, // all testnet Taproot
		},
		Velocity: VelocityConfig{
			MaxAmount: 100_000_000, // 1 BTC
			Window:    "24h",
		},
		Tiered: TieredConfig{
			Tiers: []TierConfig{
				{MaxAmount: 100_000, RequiredApprovals: 0, Label: "small"},
				{MaxAmount: 10_000_000, RequiredApprovals: 1, Label: "medium"},
				{MaxAmount: -1, RequiredApprovals: 2, Label: "large"},
			},
		},
		Schedule: ScheduleConfig{
			StartHour: 9,
			EndHour:   18,
			Timezone:  "America/New_York",
		},
		Quorum: QuorumConfig{
			RequiredCount: 2,
			ValidApprovers: map[string]string{
				"alice@company.com": "Alice (CFO)",
				"bob@company.com":   "Bob (CTO)",
				"carol@company.com": "Carol (CEO)",
			},
			MaxApprovalAge: "1h",
		},
	}
}
