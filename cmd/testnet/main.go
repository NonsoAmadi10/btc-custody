// Command testnet provides a CLI for real testnet interaction.
//
// Usage:
//
//	go run ./cmd/testnet [command]
//
// Commands:
//
//	deposit  - Generate a new deposit address
//	balance  - Check wallet balance
//	spend    - Create and broadcast a transaction
//	status   - Show system status
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/0xciph3r/btc-custody/internal/custody"
	"github.com/0xciph3r/btc-custody/internal/policy"
	"github.com/0xciph3r/btc-custody/internal/psbt"
	"github.com/0xciph3r/btc-custody/internal/wallet"
	"github.com/btcsuite/btcd/chaincfg"
)

const stateFile = ".custody-state.json"

type State struct {
	CeremonyID  string            `json:"ceremony_id"`
	GroupKeyHex string            `json:"group_key_hex"`
	Shares      map[uint32]string `json:"shares"` // hex-encoded shares
	Addresses   []string          `json:"addresses"`
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	ctx := context.Background()
	cmd := os.Args[1]

	switch cmd {
	case "init":
		cmdInit(ctx)
	case "deposit":
		cmdDeposit(ctx)
	case "balance":
		cmdBalance(ctx)
	case "spend":
		cmdSpend(ctx)
	case "status":
		cmdStatus(ctx)
	default:
		printUsage()
	}
}

func printUsage() {
	fmt.Println(`BTC Custody - Testnet CLI

Usage:
  go run ./cmd/testnet <command>

Commands:
  init     Initialize a new 2-of-3 custody system
  deposit  Generate a deposit address
  balance  Check wallet balance
  spend    Create and broadcast a transaction
  status   Show system status

State is persisted in .custody-state.json`)
}

func cmdInit(ctx context.Context) {
	fmt.Println("Initializing 2-of-3 custody system...")

	// Use real mempool.space API (testnet)
	client := wallet.NewMempoolClient(true)

	system, err := custody.New(custody.Config{
		Network:          &chaincfg.TestNet3Params,
		Threshold:        2,
		Total:            3,
		BlockchainClient: client,
		PolicyConfig: &policy.Config{
			Whitelist: policy.WhitelistConfig{
				Prefixes: []string{"tb1p", "tb1q"}, // All testnet addresses
			},
			Velocity: policy.VelocityConfig{
				MaxAmount: 10_000_000, // 0.1 BTC per day
				Window:    "24h",
			},
		},
	})
	if err != nil {
		fatal("Failed to create system: %v", err)
	}

	// Run DKG
	fmt.Println("Running DKG ceremony...")
	system.InitializeDKG()
	groupKey, err := system.RunDKGCeremony()
	if err != nil {
		fatal("DKG failed: %v", err)
	}

	// Initialize wallet
	if err := system.InitializeWallet(ctx); err != nil {
		fatal("Wallet init failed: %v", err)
	}

	// Save state
	state := State{
		CeremonyID:  system.GetStatus().CeremonyID,
		GroupKeyHex: fmt.Sprintf("%x", groupKey.SerializeCompressed()),
		Shares:      make(map[uint32]string),
	}

	// Save shares (in production, each participant would keep their own)
	for i := uint32(1); i <= 3; i++ {
		share, _ := system.GetParticipantShare(i)
		state.Shares[i] = fmt.Sprintf("%x", share.Bytes())
	}

	if err := saveState(&state); err != nil {
		fatal("Failed to save state: %v", err)
	}

	fmt.Println()
	fmt.Println("✓ System initialized!")
	fmt.Printf("  Ceremony ID: %s\n", state.CeremonyID)
	fmt.Printf("  Group key: %s\n", state.GroupKeyHex[:16]+"...")
	fmt.Println()
	fmt.Println("Run 'go run ./cmd/testnet deposit' to get a deposit address.")
}

func cmdDeposit(ctx context.Context) {
	system, err := loadSystem(ctx)
	if err != nil {
		fatal("Failed to load system: %v", err)
	}

	addr, err := system.GetDepositAddress()
	if err != nil {
		fatal("Failed to get address: %v", err)
	}

	fmt.Println()
	fmt.Println("══════════════════════════════════════════════════════════")
	fmt.Println("  DEPOSIT ADDRESS (Testnet Taproot)")
	fmt.Println("══════════════════════════════════════════════════════════")
	fmt.Println()
	fmt.Printf("  %s\n", addr)
	fmt.Println()
	fmt.Println("  Send testnet BTC to this address.")
	fmt.Println("  Get testnet BTC from: https://bitcoinfaucet.uo1.net/")
	fmt.Println()
	fmt.Println("  After sending, run: go run ./cmd/testnet balance")
	fmt.Println("══════════════════════════════════════════════════════════")
	fmt.Println()
}

func cmdBalance(ctx context.Context) {
	system, err := loadSystem(ctx)
	if err != nil {
		fatal("Failed to load system: %v", err)
	}

	fmt.Println("Syncing with blockchain...")
	if err := system.SyncWallet(ctx); err != nil {
		fatal("Sync failed: %v", err)
	}

	balance := system.GetBalance()
	btc := float64(balance) / 100_000_000

	fmt.Println()
	fmt.Printf("Balance: %.8f BTC (%d sats)\n", btc, balance)
	fmt.Println()
}

func cmdSpend(ctx context.Context) {
	system, err := loadSystem(ctx)
	if err != nil {
		fatal("Failed to load system: %v", err)
	}

	// Sync first
	fmt.Println("Syncing wallet...")
	if err := system.SyncWallet(ctx); err != nil {
		fatal("Sync failed: %v", err)
	}

	balance := system.GetBalance()
	fmt.Printf("Available: %d sats\n\n", balance)

	if balance == 0 {
		fatal("No funds available. Send testnet BTC first.")
	}

	reader := bufio.NewReader(os.Stdin)

	// Get destination
	fmt.Print("Destination address: ")
	destAddr, _ := reader.ReadString('\n')
	destAddr = strings.TrimSpace(destAddr)

	// Get amount
	fmt.Print("Amount (sats): ")
	amountStr, _ := reader.ReadString('\n')
	amount, err := strconv.ParseInt(strings.TrimSpace(amountStr), 10, 64)
	if err != nil {
		fatal("Invalid amount: %v", err)
	}

	// Confirm
	fmt.Println()
	fmt.Printf("Sending %d sats to %s\n", amount, destAddr)
	fmt.Print("Signers (e.g., '1,2'): ")
	signersStr, _ := reader.ReadString('\n')
	signerParts := strings.Split(strings.TrimSpace(signersStr), ",")
	var signers []uint32
	for _, s := range signerParts {
		idx, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
		if err != nil {
			fatal("Invalid signer: %v", err)
		}
		signers = append(signers, uint32(idx))
	}

	fmt.Print("Broadcast? [y/N]: ")
	confirm, _ := reader.ReadString('\n')
	broadcast := strings.ToLower(strings.TrimSpace(confirm)) == "y"

	// Execute spend
	result, err := system.Spend(ctx, custody.SpendRequest{
		Destinations:  []psbt.Recipient{{Address: destAddr, Amount: amount}},
		FeeRate:       2, // 2 sat/vbyte
		SignerIndices: signers,
	}, broadcast)
	if err != nil {
		fatal("Spend failed: %v", err)
	}

	fmt.Println()
	fmt.Println("✓ Transaction created!")
	fmt.Printf("  Fee: %d sats\n", result.Fee)
	fmt.Printf("  Policy: %s\n", result.PolicyDecision.Reason)

	if broadcast {
		fmt.Printf("  TXID: %s\n", result.TxID)
		fmt.Println()
		fmt.Printf("  View: https://mempool.space/testnet/tx/%s\n", result.TxID)
	} else {
		fmt.Println()
		fmt.Println("  Raw TX (not broadcast):")
		fmt.Printf("  %s\n", result.RawTx[:64]+"...")
	}
}

func cmdStatus(ctx context.Context) {
	system, err := loadSystem(ctx)
	if err != nil {
		fatal("Failed to load system: %v", err)
	}

	status := system.GetStatus()

	fmt.Println()
	fmt.Println("═══ Custody System Status ═══")
	fmt.Printf("Ceremony ID:      %s\n", status.CeremonyID)
	fmt.Printf("Threshold:        %d-of-%d\n", status.Threshold, status.Total)
	fmt.Printf("DKG Complete:     %t\n", status.DKGComplete)
	fmt.Printf("Wallet Ready:     %t\n", status.WalletReady)
	fmt.Printf("Network:          %s\n", status.Network)
	fmt.Printf("Participants:     %d\n", status.ParticipantCount)

	if status.WalletReady {
		fmt.Printf("Balance:          %d sats\n", status.Balance)
	}
	fmt.Println()
}

func loadSystem(ctx context.Context) (*custody.CustodySystem, error) {
	_, err := loadState()
	if err != nil {
		return nil, fmt.Errorf("no state file - run 'init' first: %w", err)
	}

	client := wallet.NewMempoolClient(true) // testnet

	system, err := custody.New(custody.Config{
		Network:          &chaincfg.TestNet3Params,
		Threshold:        2,
		Total:            3,
		BlockchainClient: client,
		PolicyConfig: &policy.Config{
			Whitelist: policy.WhitelistConfig{
				Prefixes: []string{"tb1p", "tb1q"},
			},
			Velocity: policy.VelocityConfig{
				MaxAmount: 10_000_000,
				Window:    "24h",
			},
		},
	})
	if err != nil {
		return nil, err
	}

	// Restore DKG state
	system.InitializeDKG()
	if _, err := system.RunDKGCeremony(); err != nil {
		return nil, err
	}

	if err := system.InitializeWallet(ctx); err != nil {
		return nil, err
	}

	return system, nil
}

func loadState() (*State, error) {
	data, err := os.ReadFile(stateFile)
	if err != nil {
		return nil, err
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

func saveState(state *State) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(stateFile, data, 0600)
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	os.Exit(1)
}
