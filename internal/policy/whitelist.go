package policy

import (
	"fmt"
	"strings"
)

// WhitelistRule ensures all destinations are on an approved list.
//
// This is the most fundamental security control: funds can only be sent
// to pre-approved addresses (e.g., exchange cold wallets, payroll accounts).
type WhitelistRule struct {
	// addresses maps allowed addresses to optional labels.
	// Key: Bitcoin address, Value: human-readable label (e.g., "Coinbase cold wallet")
	addresses map[string]string

	// prefixes allows address patterns (e.g., "bc1q" for all native segwit).
	// Use sparingly as this is less restrictive.
	prefixes []string
}

// NewWhitelistRule creates a whitelist rule with the given addresses.
func NewWhitelistRule(addresses map[string]string) *WhitelistRule {
	if addresses == nil {
		addresses = make(map[string]string)
	}
	return &WhitelistRule{
		addresses: addresses,
	}
}

// AddAddress adds an address to the whitelist.
func (r *WhitelistRule) AddAddress(address, label string) {
	r.addresses[address] = label
}

// RemoveAddress removes an address from the whitelist.
func (r *WhitelistRule) RemoveAddress(address string) {
	delete(r.addresses, address)
}

// AddPrefix adds an address prefix pattern to allow.
func (r *WhitelistRule) AddPrefix(prefix string) {
	r.prefixes = append(r.prefixes, prefix)
}

// ID implements Rule.
func (r *WhitelistRule) ID() string {
	return "whitelist"
}

// Evaluate implements Rule.
func (r *WhitelistRule) Evaluate(req *TransactionRequest) Decision {
	if len(r.addresses) == 0 && len(r.prefixes) == 0 {
		return Deny(r.ID(), "whitelist is empty; no addresses allowed")
	}

	for _, dest := range req.Destinations {
		if !r.isAllowed(dest.Address) {
			return Deny(r.ID(), fmt.Sprintf("address %s is not on whitelist", dest.Address))
		}
	}

	return Allow(r.ID())
}

// isAllowed checks if an address is whitelisted.
func (r *WhitelistRule) isAllowed(address string) bool {
	// Check exact match
	if _, ok := r.addresses[address]; ok {
		return true
	}

	// Check prefix patterns
	for _, prefix := range r.prefixes {
		if strings.HasPrefix(address, prefix) {
			return true
		}
	}

	return false
}

// Addresses returns a copy of the whitelist.
func (r *WhitelistRule) Addresses() map[string]string {
	result := make(map[string]string, len(r.addresses))
	for k, v := range r.addresses {
		result[k] = v
	}
	return result
}
