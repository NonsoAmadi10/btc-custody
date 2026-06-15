// Command custody demonstrates the full BTC custody system.
//
// Usage:
//
//	go run ./cmd/custody
//
// This interactive demo walks through:
//  1. FROST DKG ceremony (2-of-3 threshold)
//  2. Deposit address generation
//  3. Simulated deposit
//  4. Policy-checked withdrawal
//  5. Threshold signing
package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/0xciph3r/btc-custody/internal/custody"
	"github.com/0xciph3r/btc-custody/internal/policy"
	"github.com/0xciph3r/btc-custody/internal/psbt"
	"github.com/0xciph3r/btc-custody/internal/wallet"
	"github.com/btcsuite/btcd/chaincfg"
)

const (
	colorReset  = "\033[0m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

func main() {
	ctx := context.Background()
	reader := bufio.NewReader(os.Stdin)

	printBanner()

	// Step 1: Create custody system
	printStep(1, "Initialize Custody System")
	fmt.Println("Creating a 2-of-3 threshold custody system...")
	fmt.Println("This means any 2 of 3 key holders can authorize transactions.")
	waitForEnter(reader)

	mockClient := wallet.NewMockClient()
	system, err := custody.New(custody.Config{
		Network:          &chaincfg.TestNet3Params,
		Threshold:        2,
		Total:            3,
		BlockchainClient: mockClient,
		PolicyConfig: &policy.Config{
			Whitelist: policy.WhitelistConfig{
				Addresses: map[string]string{},
				Prefixes:  []string{"tb1p", "tb1q"}, // Allow all testnet addresses
			},
			Velocity: policy.VelocityConfig{
				MaxAmount: 10_000_000, // 0.1 BTC
				Window:    "24h",
			},
			Tiered: policy.TieredConfig{
				Tiers: []policy.TierConfig{
					{MaxAmount: 100_000, RequiredApprovals: 0},   // < 0.001 BTC: auto
					{MaxAmount: 1_000_000, RequiredApprovals: 1}, // < 0.01 BTC: 1 approval
					{MaxAmount: -1, RequiredApprovals: 2},        // unlimited: 2 approvals
				},
			},
		},
	})
	if err != nil {
		fatal("Failed to create custody system: %v", err)
	}

	printSuccess("Custody system created: %s", system.GetStatus().CeremonyID)
	fmt.Println()

	// Step 2: Run DKG
	printStep(2, "Distributed Key Generation (DKG)")
	fmt.Println("Running FROST DKG ceremony...")
	fmt.Println()
	fmt.Println("  " + colorCyan + "FROST DKG creates a shared public key where:" + colorReset)
	fmt.Println("  • No single party ever sees the full private key")
	fmt.Println("  • Each participant holds a share of the key")
	fmt.Println("  • t-of-n threshold signing is possible")
	fmt.Println()
	waitForEnter(reader)

	system.InitializeDKG()
	groupKey, err := system.RunDKGCeremony()
	if err != nil {
		fatal("DKG failed: %v", err)
	}

	printSuccess("DKG complete!")
	fmt.Printf("  Group public key: %s%x%s\n", colorYellow, groupKey.SerializeCompressed()[:8], colorReset)
	fmt.Println()

	// Step 3: Initialize wallet
	printStep(3, "Initialize Wallet")
	fmt.Println("Deriving deposit addresses from the group key...")
	waitForEnter(reader)

	if err := system.InitializeWallet(ctx); err != nil {
		fatal("Failed to initialize wallet: %v", err)
	}

	addrStr, err := system.GetDepositAddress()
	if err != nil {
		fatal("Failed to get deposit address: %v", err)
	}

	// Get PkScript from the deriver
	deriver := wallet.NewAddressDeriver(groupKey, &chaincfg.TestNet3Params)
	addr, err := deriver.DeriveHot(0)
	if err != nil {
		fatal("Failed to derive address: %v", err)
	}

	printSuccess("Wallet initialized!")
	fmt.Printf("  Deposit address: %s%s%s\n", colorYellow, addrStr, colorReset)
	fmt.Println()

	// Step 4: Simulate deposit
	printStep(4, "Receive Deposit")
	fmt.Println("Simulating a deposit of 0.005 BTC (500,000 sats)...")
	waitForEnter(reader)

	mockClient.UTXOs[addr.Address] = []*wallet.UTXO{
		{
			TxID:          "abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
			Vout:          0,
			Amount:        500_000,
			Address:       addr.Address,
			PkScript:      addr.PkScript,
			Confirmations: 6,
		},
	}
	if err := system.SyncWallet(ctx); err != nil {
		fatal("Failed to sync wallet: %v", err)
	}

	balance := system.GetBalance()
	printSuccess("Deposit received!")
	fmt.Printf("  Balance: %s%s BTC%s (%d sats)\n", colorGreen, formatBTC(balance), colorReset, balance)
	fmt.Println()

	// Step 5: Policy check explanation
	printStep(5, "Policy Engine")
	fmt.Println("Before any withdrawal, the policy engine checks:")
	fmt.Println()
	fmt.Println("  " + colorPurple + "╔══════════════════════════════════════════╗" + colorReset)
	fmt.Println("  " + colorPurple + "║" + colorReset + "  1. Whitelist    - Is destination allowed? " + colorPurple + "║" + colorReset)
	fmt.Println("  " + colorPurple + "║" + colorReset + "  2. Velocity     - Within daily limits?     " + colorPurple + "║" + colorReset)
	fmt.Println("  " + colorPurple + "║" + colorReset + "  3. Tiered       - Enough approvals?        " + colorPurple + "║" + colorReset)
	fmt.Println("  " + colorPurple + "║" + colorReset + "  4. Schedule     - During business hours?   " + colorPurple + "║" + colorReset)
	fmt.Println("  " + colorPurple + "║" + colorReset + "  5. Quorum       - Required signatures?     " + colorPurple + "║" + colorReset)
	fmt.Println("  " + colorPurple + "╚══════════════════════════════════════════╝" + colorReset)
	fmt.Println()
	waitForEnter(reader)

	// Step 6: Create and sign withdrawal
	printStep(6, "Threshold Signing")
	fmt.Println("Creating a withdrawal of 0.001 BTC...")
	fmt.Println()
	fmt.Println("  Signers: Participant 1 + Participant 2 (2-of-3)")
	fmt.Println("  Destination: tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx")
	fmt.Println()
	waitForEnter(reader)

	result, err := system.Spend(ctx, custody.SpendRequest{
		Destinations: []psbt.Recipient{
			{Address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", Amount: 100_000},
		},
		FeeRate:       1,
		SignerIndices: []uint32{1, 2},
	}, false)
	if err != nil {
		fatal("Failed to spend: %v", err)
	}

	printSuccess("Transaction signed!")
	fmt.Printf("  Fee: %s%d sats%s\n", colorYellow, result.Fee, colorReset)
	fmt.Printf("  Policy: %s%s%s\n", colorGreen, result.PolicyDecision.Reason, colorReset)
	fmt.Printf("  Raw TX: %s...%s\n", result.RawTx[:32], result.RawTx[len(result.RawTx)-8:])
	fmt.Println()

	// Step 7: Try different signer combinations
	printStep(7, "Any 2-of-3 Works")
	fmt.Println("Let's verify other signer combinations work too...")
	waitForEnter(reader)

	combinations := [][]uint32{
		{1, 3},
		{2, 3},
	}

	for _, signers := range combinations {
		// Reset UTXO for demo
		mockClient.UTXOs[addr.Address] = []*wallet.UTXO{
			{
				TxID:          "bbb123def456abc123def456abc123def456abc123def456abc123def456bbb1",
				Vout:          0,
				Amount:        500_000,
				Address:       addr.Address,
				PkScript:      addr.PkScript,
				Confirmations: 6,
			},
		}
		system.SyncWallet(ctx)

		_, err := system.Spend(ctx, custody.SpendRequest{
			Destinations: []psbt.Recipient{
				{Address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", Amount: 100_000},
			},
			FeeRate:       1,
			SignerIndices: signers,
		}, false)
		if err != nil {
			fmt.Printf("  %s✗ Signers %v: %v%s\n", "\033[31m", signers, err, colorReset)
		} else {
			printSuccess("Signers %v: transaction signed!", signers)
		}
	}
	fmt.Println()

	// Step 8: Policy denial demo
	printStep(8, "Policy Denial Demo")
	fmt.Println("What happens if policy denies a transaction?")
	fmt.Println("Attempting to send to non-whitelisted address...")
	waitForEnter(reader)

	// Reset balance
	mockClient.UTXOs[addr.Address] = []*wallet.UTXO{
		{
			TxID:          "ccc123def456abc123def456abc123def456abc123def456abc123def456ccc1",
			Vout:          0,
			Amount:        500_000,
			Address:       addr.Address,
			PkScript:      addr.PkScript,
			Confirmations: 6,
		},
	}
	system.SyncWallet(ctx)

	_, err = system.Spend(ctx, custody.SpendRequest{
		Destinations: []psbt.Recipient{
			{Address: "bc1qnotwhitelisted", Amount: 100_000}, // mainnet address not in whitelist
		},
		FeeRate:       1,
		SignerIndices: []uint32{1, 2},
	}, false)
	if err != nil {
		printSuccess("Policy correctly denied: %v", err)
	}
	fmt.Println()

	// Summary
	printSummary()
}

func printBanner() {
	fmt.Println()
	fmt.Println(colorBold + colorCyan + "  ╔═══════════════════════════════════════════════════════════╗" + colorReset)
	fmt.Println(colorBold + colorCyan + "  ║" + colorReset + "                                                           " + colorBold + colorCyan + "║" + colorReset)
	fmt.Println(colorBold + colorCyan + "  ║" + colorReset + "   " + colorBold + "BTC CUSTODY SYSTEM" + colorReset + " - FROST Threshold Signing Demo    " + colorBold + colorCyan + "║" + colorReset)
	fmt.Println(colorBold + colorCyan + "  ║" + colorReset + "                                                           " + colorBold + colorCyan + "║" + colorReset)
	fmt.Println(colorBold + colorCyan + "  ║" + colorReset + "   2-of-3 Taproot Multisig with Policy Controls            " + colorBold + colorCyan + "║" + colorReset)
	fmt.Println(colorBold + colorCyan + "  ║" + colorReset + "                                                           " + colorBold + colorCyan + "║" + colorReset)
	fmt.Println(colorBold + colorCyan + "  ╚═══════════════════════════════════════════════════════════╝" + colorReset)
	fmt.Println()
}

func printStep(n int, title string) {
	fmt.Println(colorBold + colorBlue + fmt.Sprintf("━━━ Step %d: %s ━━━", n, title) + colorReset)
	fmt.Println()
}

func printSuccess(format string, args ...interface{}) {
	fmt.Printf(colorGreen+"  ✓ "+format+colorReset+"\n", args...)
}

func printSummary() {
	fmt.Println(colorBold + colorPurple + "━━━ Summary ━━━" + colorReset)
	fmt.Println()
	fmt.Println("This demo showed:")
	fmt.Println()
	fmt.Println("  1. " + colorCyan + "FROST DKG" + colorReset + " - Created shared key without trusted dealer")
	fmt.Println("  2. " + colorCyan + "Taproot" + colorReset + " - Native P2TR addresses (BIP-341)")
	fmt.Println("  3. " + colorCyan + "Threshold Signing" + colorReset + " - Any 2-of-3 can sign")
	fmt.Println("  4. " + colorCyan + "Policy Engine" + colorReset + " - Programmatic transaction controls")
	fmt.Println("  5. " + colorCyan + "No Single Point of Failure" + colorReset + " - No party sees full key")
	fmt.Println()
	fmt.Println(colorYellow + "Ready for production? Add:" + colorReset)
	fmt.Println("  • HSM integration for key share storage")
	fmt.Println("  • Real mempool.space API calls")
	fmt.Println("  • Network transport for distributed DKG")
	fmt.Println("  • Audit logging and monitoring")
	fmt.Println()
}

func waitForEnter(reader *bufio.Reader) {
	fmt.Print(colorYellow + "  Press Enter to continue..." + colorReset)
	reader.ReadString('\n')
	fmt.Println()
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "\033[31m✗ "+format+"\033[0m\n", args...)
	os.Exit(1)
}

func formatBTC(sats int64) string {
	btc := float64(sats) / 100_000_000
	s := fmt.Sprintf("%.8f", btc)
	s = strings.TrimRight(s, "0")
	if strings.HasSuffix(s, ".") {
		s += "0"
	}
	return s
}
