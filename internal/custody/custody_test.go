package custody

import (
	"context"
	"testing"
	"time"

	"github.com/NonsoAmadi10/btc-custody/internal/policy"
	"github.com/NonsoAmadi10/btc-custody/internal/psbt"
	"github.com/NonsoAmadi10/btc-custody/internal/wallet"
	"github.com/btcsuite/btcd/chaincfg"
)

// TestFullCustodyFlow exercises the complete custody system:
// 1. Create system
// 2. Run DKG ceremony
// 3. Initialize wallet
// 4. Simulate deposit
// 5. Check policy and sign transaction
func TestFullCustodyFlow(t *testing.T) {
	ctx := context.Background()

	// ══════════════════════════════════════════════════════════════════════
	// Phase 1: Create custody system with policy
	// ══════════════════════════════════════════════════════════════════════

	mockClient := wallet.NewMockClient()

	// Create policy that allows our test destination
	policyConfig := &policy.Config{
		Whitelist: policy.WhitelistConfig{
			Addresses: map[string]string{
				"tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx": "Test Recipient",
			},
			Prefixes: []string{"tb1p"}, // all testnet Taproot
		},
		Velocity: policy.VelocityConfig{
			MaxAmount: 1_000_000_000, // 10 BTC
			Window:    "24h",
		},
		Tiered: policy.TieredConfig{
			Tiers: []policy.TierConfig{
				{MaxAmount: 100_000, RequiredApprovals: 0, Label: "small"},
				{MaxAmount: -1, RequiredApprovals: 0, Label: "any"}, // no approval for test
			},
		},
	}

	system, err := New(Config{
		Network:          &chaincfg.TestNet3Params,
		Threshold:        2,
		Total:            3,
		BlockchainClient: mockClient,
		PolicyConfig:     policyConfig,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	t.Log("✓ Custody system created (2-of-3)")

	// ══════════════════════════════════════════════════════════════════════
	// Phase 2: Run DKG ceremony
	// ══════════════════════════════════════════════════════════════════════

	if err := system.InitializeDKG(); err != nil {
		t.Fatalf("InitializeDKG: %v", err)
	}

	groupPubKey, err := system.RunDKGCeremony()
	if err != nil {
		t.Fatalf("RunDKGCeremony: %v", err)
	}

	t.Logf("✓ DKG complete: group key = %x", groupPubKey.SerializeCompressed()[:8])

	// ══════════════════════════════════════════════════════════════════════
	// Phase 3: Initialize wallet
	// ══════════════════════════════════════════════════════════════════════

	if err := system.InitializeWallet(ctx); err != nil {
		t.Fatalf("InitializeWallet: %v", err)
	}

	status := system.GetStatus()
	if !status.DKGComplete {
		t.Error("expected DKG complete")
	}
	if !status.WalletReady {
		t.Error("expected wallet ready")
	}

	t.Log("✓ Wallet initialized")

	// Get deposit address
	depositAddr, err := system.GetDepositAddress()
	if err != nil {
		t.Fatalf("GetDepositAddress: %v", err)
	}

	if depositAddr[:4] != "tb1p" {
		t.Errorf("expected tb1p prefix, got %s", depositAddr[:4])
	}

	t.Logf("✓ Deposit address: %s", depositAddr)

	// ══════════════════════════════════════════════════════════════════════
	// Phase 4: Simulate deposit (add UTXO to mock client)
	// ══════════════════════════════════════════════════════════════════════

	// Derive the pkScript for the deposit address
	deriver := wallet.NewAddressDeriver(groupPubKey, &chaincfg.TestNet3Params)
	hotAddr, _ := deriver.DeriveHot(20) // Index 20 is our new address

	mockClient.UTXOs[hotAddr.Address] = []*wallet.UTXO{
		{
			TxID:          "0000000000000000000000000000000000000000000000000000000000000001",
			Vout:          0,
			Amount:        500_000, // 0.005 BTC
			Address:       hotAddr.Address,
			PkScript:      hotAddr.PkScript,
			Confirmations: 6,
			Timestamp:     time.Now(),
		},
	}

	// Sync wallet to pick up deposit
	if err := system.SyncWallet(ctx); err != nil {
		t.Fatalf("SyncWallet: %v", err)
	}

	balance := system.GetBalance()
	if balance != 500_000 {
		t.Errorf("expected balance 500000, got %d", balance)
	}

	t.Logf("✓ Deposit received: %s", wallet.FormatBTC(balance))

	// ══════════════════════════════════════════════════════════════════════
	// Phase 5: Spend (policy check + FROST signing)
	// ══════════════════════════════════════════════════════════════════════

	spendReq := SpendRequest{
		Destinations: []psbt.Recipient{
			{
				Address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
				Amount:  100_000,
			},
		},
		FeeRate:       2,
		RequestedBy:   "test@example.com",
		SignerIndices: []uint32{1, 2}, // 2-of-3
	}

	result, err := system.Spend(ctx, spendReq, false) // don't broadcast
	if err != nil {
		t.Fatalf("Spend: %v", err)
	}

	if !result.PolicyDecision.Allowed {
		t.Errorf("expected policy to allow, got: %s", result.PolicyDecision.Reason)
	}

	if result.RawTx == "" {
		t.Error("expected signed transaction")
	}

	if result.Fee <= 0 {
		t.Error("expected positive fee")
	}

	t.Logf("✓ Transaction signed: fee=%d sats, tx=%s...", result.Fee, result.RawTx[:32])
	t.Logf("✓ Policy decision: %s", result.PolicyDecision.Reason)

	// ══════════════════════════════════════════════════════════════════════
	// Final Status
	// ══════════════════════════════════════════════════════════════════════

	finalStatus := system.GetStatus()
	t.Logf("\n═══ Final Status ═══")
	t.Logf("Ceremony ID: %s", finalStatus.CeremonyID)
	t.Logf("Threshold: %d-of-%d", finalStatus.Threshold, finalStatus.Total)
	t.Logf("DKG Complete: %v", finalStatus.DKGComplete)
	t.Logf("Wallet Ready: %v", finalStatus.WalletReady)
	t.Logf("Network: %s", finalStatus.Network)
}

// TestPolicyDenial verifies that policy rules are enforced.
func TestPolicyDenial(t *testing.T) {
	ctx := context.Background()

	mockClient := wallet.NewMockClient()

	// Strict policy: only allow specific address
	policyConfig := &policy.Config{
		Whitelist: policy.WhitelistConfig{
			Addresses: map[string]string{
				"tb1qapproved": "Approved Address",
			},
		},
	}

	system, _ := New(Config{
		Network:          &chaincfg.TestNet3Params,
		Threshold:        2,
		Total:            3,
		BlockchainClient: mockClient,
		PolicyConfig:     policyConfig,
	})

	system.InitializeDKG()
	system.RunDKGCeremony()
	system.InitializeWallet(ctx)

	// Add UTXO
	deriver := wallet.NewAddressDeriver(system.GroupPublicKey(), &chaincfg.TestNet3Params)
	addr, _ := deriver.DeriveHot(0)
	mockClient.UTXOs[addr.Address] = []*wallet.UTXO{
		{
			TxID:          "abc123",
			Vout:          0,
			Amount:        100_000,
			Address:       addr.Address,
			PkScript:      addr.PkScript,
			Confirmations: 6,
		},
	}
	system.SyncWallet(ctx)

	// Try to spend to non-whitelisted address
	spendReq := SpendRequest{
		Destinations: []psbt.Recipient{
			{
				Address: "tb1qnotapproved", // NOT on whitelist
				Amount:  50_000,
			},
		},
		FeeRate:       1,
		RequestedBy:   "test@example.com",
		SignerIndices: []uint32{1, 2},
	}

	_, err := system.Spend(ctx, spendReq, false)
	if err == nil {
		t.Error("expected policy denial")
	}

	t.Logf("✓ Policy correctly denied: %v", err)
}

// TestInsufficientSigners verifies threshold enforcement.
func TestInsufficientSigners(t *testing.T) {
	ctx := context.Background()

	system, _ := New(Config{
		Network:          &chaincfg.TestNet3Params,
		Threshold:        2, // Need 2 signers
		Total:            3,
		BlockchainClient: wallet.NewMockClient(),
		PolicyConfig: &policy.Config{
			Whitelist: policy.WhitelistConfig{
				Prefixes: []string{"tb1"},
			},
		},
	})

	system.InitializeDKG()
	system.RunDKGCeremony()
	system.InitializeWallet(ctx)

	// Try with only 1 signer
	spendReq := SpendRequest{
		Destinations: []psbt.Recipient{
			{Address: "tb1qtest", Amount: 1000},
		},
		SignerIndices: []uint32{1}, // Only 1 signer, need 2
	}

	_, err := system.Spend(ctx, spendReq, false)
	if err == nil {
		t.Error("expected insufficient signers error")
	}

	t.Logf("✓ Correctly rejected: %v", err)
}

// TestStatusBeforeDKG verifies status before DKG is run.
func TestStatusBeforeDKG(t *testing.T) {
	system, _ := New(Config{
		Network:          &chaincfg.TestNet3Params,
		Threshold:        2,
		Total:            3,
		BlockchainClient: wallet.NewMockClient(),
	})

	status := system.GetStatus()

	if status.DKGComplete {
		t.Error("DKG should not be complete before ceremony")
	}

	if status.WalletReady {
		t.Error("wallet should not be ready before DKG")
	}

	if status.Threshold != 2 || status.Total != 3 {
		t.Errorf("unexpected threshold/total: %d/%d", status.Threshold, status.Total)
	}
}

// TestMultipleSignerCombinations tests that any 2-of-3 combination works.
func TestMultipleSignerCombinations(t *testing.T) {
	ctx := context.Background()

	mockClient := wallet.NewMockClient()

	system, _ := New(Config{
		Network:          &chaincfg.TestNet3Params,
		Threshold:        2,
		Total:            3,
		BlockchainClient: mockClient,
		PolicyConfig: &policy.Config{
			Whitelist: policy.WhitelistConfig{
				Prefixes: []string{"tb1p", "tb1q"},
			},
		},
	})

	system.InitializeDKG()
	system.RunDKGCeremony()
	system.InitializeWallet(ctx)

	// Add UTXO
	deriver := wallet.NewAddressDeriver(system.GroupPublicKey(), &chaincfg.TestNet3Params)
	addr, _ := deriver.DeriveHot(0)

	// Test all 3 combinations of 2-of-3
	combinations := [][]uint32{
		{1, 2},
		{1, 3},
		{2, 3},
	}

	for _, signers := range combinations {
		// Reset UTXO for each test
		mockClient.UTXOs[addr.Address] = []*wallet.UTXO{
			{TxID: "aaa", Vout: 0, Amount: 100_000, Address: addr.Address, PkScript: addr.PkScript, Confirmations: 6},
		}
		system.SyncWallet(ctx)

		// Use a real testnet address
		spendReq := SpendRequest{
			Destinations:  []psbt.Recipient{{Address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", Amount: 10_000}},
			FeeRate:       1,
			SignerIndices: signers,
		}

		result, err := system.Spend(ctx, spendReq, false)
		if err != nil {
			t.Errorf("signers %v failed: %v", signers, err)
			continue
		}

		if result.RawTx == "" {
			t.Errorf("signers %v produced empty tx", signers)
		}

		t.Logf("✓ Signers %v: success", signers)
	}
}
