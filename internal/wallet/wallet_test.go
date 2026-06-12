package wallet

import (
	"context"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
)

// ═══════════════════════════════════════════════════════════════════════════
// Address Derivation Tests
// ═══════════════════════════════════════════════════════════════════════════

func TestAddressDeriver_DeriveHot(t *testing.T) {
	// Generate a test key
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	groupPubKey := privKey.PubKey()

	deriver := NewAddressDeriver(groupPubKey, &chaincfg.TestNet3Params)

	// Derive first hot address
	addr, err := deriver.DeriveHot(0)
	if err != nil {
		t.Fatalf("DeriveHot(0): %v", err)
	}

	// Check address format (testnet Taproot)
	if addr.Address[:4] != "tb1p" {
		t.Errorf("expected tb1p prefix, got %s", addr.Address[:4])
	}

	if addr.Type != AddressTypeHot {
		t.Errorf("expected hot type, got %s", addr.Type)
	}

	if addr.Index != 0 {
		t.Errorf("expected index 0, got %d", addr.Index)
	}

	t.Logf("Hot address 0: %s", addr.Address)
}

func TestAddressDeriver_Deterministic(t *testing.T) {
	privKey, _ := btcec.NewPrivateKey()
	groupPubKey := privKey.PubKey()

	deriver1 := NewAddressDeriver(groupPubKey, &chaincfg.TestNet3Params)
	deriver2 := NewAddressDeriver(groupPubKey, &chaincfg.TestNet3Params)

	addr1, _ := deriver1.DeriveHot(5)
	addr2, _ := deriver2.DeriveHot(5)

	if addr1.Address != addr2.Address {
		t.Error("derivation should be deterministic")
	}
}

func TestAddressDeriver_HotColdDifferent(t *testing.T) {
	privKey, _ := btcec.NewPrivateKey()
	groupPubKey := privKey.PubKey()

	deriver := NewAddressDeriver(groupPubKey, &chaincfg.TestNet3Params)

	hot, _ := deriver.DeriveHot(0)
	cold, _ := deriver.DeriveCold(0)

	if hot.Address == cold.Address {
		t.Error("hot and cold addresses at same index should differ")
	}
}

func TestAddressDeriver_DeriveRange(t *testing.T) {
	privKey, _ := btcec.NewPrivateKey()
	groupPubKey := privKey.PubKey()

	deriver := NewAddressDeriver(groupPubKey, &chaincfg.TestNet3Params)

	addrs, err := deriver.DeriveRange(0, 5, AddressTypeHot)
	if err != nil {
		t.Fatalf("DeriveRange: %v", err)
	}

	if len(addrs) != 5 {
		t.Errorf("expected 5 addresses, got %d", len(addrs))
	}

	// Check uniqueness
	seen := make(map[string]bool)
	for _, addr := range addrs {
		if seen[addr.Address] {
			t.Errorf("duplicate address: %s", addr.Address)
		}
		seen[addr.Address] = true
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// UTXO Set Tests
// ═══════════════════════════════════════════════════════════════════════════

func TestUTXOSet_AddAndGet(t *testing.T) {
	set := NewUTXOSet()

	utxo := &UTXO{
		TxID:          "abc123",
		Vout:          0,
		Amount:        100_000,
		Address:       "tb1ptest",
		Confirmations: 6,
	}

	set.Add(utxo)

	got, ok := set.Get("abc123", 0)
	if !ok {
		t.Fatal("expected to find UTXO")
	}

	if got.Amount != 100_000 {
		t.Errorf("expected amount 100000, got %d", got.Amount)
	}
}

func TestUTXOSet_Balance(t *testing.T) {
	set := NewUTXOSet()

	set.Add(&UTXO{TxID: "a", Vout: 0, Amount: 50_000, Confirmations: 1})
	set.Add(&UTXO{TxID: "b", Vout: 0, Amount: 30_000, Confirmations: 1})
	set.Add(&UTXO{TxID: "c", Vout: 0, Amount: 20_000, Confirmations: 0}) // unconfirmed

	balance := set.Balance()
	if balance != 80_000 { // only confirmed
		t.Errorf("expected balance 80000, got %d", balance)
	}

	unconfirmed := set.UnconfirmedBalance()
	if unconfirmed != 20_000 {
		t.Errorf("expected unconfirmed 20000, got %d", unconfirmed)
	}
}

func TestUTXOSet_MarkSpent(t *testing.T) {
	set := NewUTXOSet()

	set.Add(&UTXO{TxID: "a", Vout: 0, Amount: 100_000, Confirmations: 1})

	before := set.Balance()
	if before != 100_000 {
		t.Fatalf("expected balance 100000, got %d", before)
	}

	set.MarkSpent("a", 0, "spending-tx")

	after := set.Balance()
	if after != 0 {
		t.Errorf("expected balance 0 after spending, got %d", after)
	}

	utxo, _ := set.Get("a", 0)
	if !utxo.Spent {
		t.Error("expected UTXO to be marked spent")
	}
	if utxo.SpentInTxID != "spending-tx" {
		t.Errorf("expected spentInTxID 'spending-tx', got %s", utxo.SpentInTxID)
	}
}

func TestUTXOSet_SelectCoins(t *testing.T) {
	set := NewUTXOSet()

	set.Add(&UTXO{TxID: "a", Vout: 0, Amount: 50_000, Confirmations: 1})
	set.Add(&UTXO{TxID: "b", Vout: 0, Amount: 100_000, Confirmations: 1})
	set.Add(&UTXO{TxID: "c", Vout: 0, Amount: 30_000, Confirmations: 1})

	// Select for 60k target at 2 sat/vbyte
	selected, total, err := set.SelectCoins(60_000, 2, 68)
	if err != nil {
		t.Fatalf("SelectCoins: %v", err)
	}

	// Should select largest first (100k covers 60k + fees)
	if len(selected) != 1 {
		t.Errorf("expected 1 UTXO selected, got %d", len(selected))
	}

	if total != 100_000 {
		t.Errorf("expected total 100000, got %d", total)
	}
}

func TestUTXOSet_SelectCoins_InsufficientFunds(t *testing.T) {
	set := NewUTXOSet()

	set.Add(&UTXO{TxID: "a", Vout: 0, Amount: 10_000, Confirmations: 1})

	_, _, err := set.SelectCoins(100_000, 2, 68)
	if err == nil {
		t.Error("expected insufficient funds error")
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Wallet Tests
// ═══════════════════════════════════════════════════════════════════════════

func TestWallet_Initialize(t *testing.T) {
	privKey, _ := btcec.NewPrivateKey()
	groupPubKey := privKey.PubKey()

	mockClient := NewMockClient()

	wallet, err := NewWallet(WalletConfig{
		GroupPubKey: groupPubKey,
		Network:     &chaincfg.TestNet3Params,
		Client:      mockClient,
		GapLimit:    5,
	})
	if err != nil {
		t.Fatalf("NewWallet: %v", err)
	}

	ctx := context.Background()
	if err := wallet.Initialize(ctx); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	// Should have derived gap limit addresses
	if len(wallet.HotAddresses()) != 5 {
		t.Errorf("expected 5 hot addresses, got %d", len(wallet.HotAddresses()))
	}

	if len(wallet.ColdAddresses()) != 5 {
		t.Errorf("expected 5 cold addresses, got %d", len(wallet.ColdAddresses()))
	}
}

func TestWallet_NewAddress(t *testing.T) {
	privKey, _ := btcec.NewPrivateKey()
	groupPubKey := privKey.PubKey()

	wallet, _ := NewWallet(WalletConfig{
		GroupPubKey: groupPubKey,
		Network:     &chaincfg.TestNet3Params,
		Client:      NewMockClient(),
		GapLimit:    2,
	})

	ctx := context.Background()
	wallet.Initialize(ctx)

	// Get a new hot address
	addr, err := wallet.NewHotAddress()
	if err != nil {
		t.Fatalf("NewHotAddress: %v", err)
	}

	if addr.Index != 2 { // gap limit was 2, so next is 2
		t.Errorf("expected index 2, got %d", addr.Index)
	}

	// Should now have 3 hot addresses
	if len(wallet.HotAddresses()) != 3 {
		t.Errorf("expected 3 hot addresses, got %d", len(wallet.HotAddresses()))
	}
}

func TestWallet_BalanceWithMockUTXOs(t *testing.T) {
	privKey, _ := btcec.NewPrivateKey()
	groupPubKey := privKey.PubKey()

	deriver := NewAddressDeriver(groupPubKey, &chaincfg.TestNet3Params)
	hotAddr, _ := deriver.DeriveHot(0)

	mockClient := NewMockClient()
	mockClient.UTXOs[hotAddr.Address] = []*UTXO{
		{TxID: "a", Vout: 0, Amount: 100_000, Address: hotAddr.Address, Confirmations: 6},
		{TxID: "b", Vout: 1, Amount: 50_000, Address: hotAddr.Address, Confirmations: 3},
	}

	wallet, _ := NewWallet(WalletConfig{
		GroupPubKey: groupPubKey,
		Network:     &chaincfg.TestNet3Params,
		Client:      mockClient,
		GapLimit:    1,
	})

	ctx := context.Background()
	wallet.Initialize(ctx)

	balance := wallet.Balance()
	if balance != 150_000 {
		t.Errorf("expected balance 150000, got %d", balance)
	}

	t.Logf("Balance: %s", FormatBTC(balance))
}

func TestWallet_Summary(t *testing.T) {
	privKey, _ := btcec.NewPrivateKey()
	groupPubKey := privKey.PubKey()

	wallet, _ := NewWallet(WalletConfig{
		GroupPubKey: groupPubKey,
		Network:     &chaincfg.TestNet3Params,
		Client:      NewMockClient(),
		GapLimit:    5,
	})

	wallet.Initialize(context.Background())

	summary := wallet.Summary()

	if summary.HotAddressCount != 5 {
		t.Errorf("expected 5 hot addresses, got %d", summary.HotAddressCount)
	}

	if summary.Network != "testnet3" {
		t.Errorf("expected network 'testnet3', got %s", summary.Network)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// UTXO Helpers Tests
// ═══════════════════════════════════════════════════════════════════════════

func TestUTXO_OutPoint(t *testing.T) {
	utxo := &UTXO{TxID: "abc123", Vout: 2}

	if utxo.OutPoint() != "abc123:2" {
		t.Errorf("expected 'abc123:2', got %s", utxo.OutPoint())
	}
}

func TestUTXO_IsConfirmed(t *testing.T) {
	unconfirmed := &UTXO{Confirmations: 0}
	confirmed := &UTXO{Confirmations: 1}

	if unconfirmed.IsConfirmed() {
		t.Error("0 confirmations should not be confirmed")
	}

	if !confirmed.IsConfirmed() {
		t.Error("1+ confirmations should be confirmed")
	}
}

func TestFormatBTC(t *testing.T) {
	tests := []struct {
		sats     int64
		expected string
	}{
		{100_000_000, "1.00000000 BTC"},
		{50_000_000, "0.50000000 BTC"},
		{1, "0.00000001 BTC"},
		{0, "0.00000000 BTC"},
	}

	for _, tc := range tests {
		got := FormatBTC(tc.sats)
		if got != tc.expected {
			t.Errorf("FormatBTC(%d): expected %s, got %s", tc.sats, tc.expected, got)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Integration-style Tests
// ═══════════════════════════════════════════════════════════════════════════

func TestWalletFlow_DepositAndSpend(t *testing.T) {
	// Setup
	privKey, _ := btcec.NewPrivateKey()
	groupPubKey := privKey.PubKey()

	mockClient := NewMockClient()

	wallet, _ := NewWallet(WalletConfig{
		GroupPubKey: groupPubKey,
		Network:     &chaincfg.TestNet3Params,
		Client:      mockClient,
		GapLimit:    3,
	})

	ctx := context.Background()
	wallet.Initialize(ctx)

	// Simulate receiving a deposit
	hotAddrs := wallet.HotAddresses()
	depositAddr := hotAddrs[0].Address

	// Add UTXO to mock client
	mockClient.UTXOs[depositAddr] = []*UTXO{
		{
			TxID:          "deposit-tx",
			Vout:          0,
			Amount:        500_000,
			Address:       depositAddr,
			Confirmations: 6,
			Timestamp:     time.Now(),
		},
	}

	// Sync to pick up the deposit
	if err := wallet.Sync(ctx); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	// Check balance
	balance := wallet.Balance()
	if balance != 500_000 {
		t.Errorf("expected balance 500000 after deposit, got %d", balance)
	}

	// Select coins for a spend
	selected, total, err := wallet.SelectCoins(200_000, 2)
	if err != nil {
		t.Fatalf("SelectCoins: %v", err)
	}

	if len(selected) != 1 {
		t.Errorf("expected 1 UTXO selected, got %d", len(selected))
	}

	if total != 500_000 {
		t.Errorf("expected total 500000, got %d", total)
	}

	t.Logf("Selected %d UTXOs totaling %s for spend", len(selected), FormatBTC(total))
}
