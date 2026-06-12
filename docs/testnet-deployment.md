# Testnet Deployment Guide

This guide walks through deploying and testing the BTC custody system on Bitcoin testnet.

## Prerequisites

1. **Testnet coins**: Get testnet BTC from a faucet:
   - https://testnet-faucet.com/btc-testnet/
   - https://bitcoinfaucet.uo1.net/

2. **Environment**: The system is built and tested:
   ```bash
   go test ./...  # All 63 tests should pass
   ```

## Step 1: Run the Interactive Demo

The demo walks through the full custody flow with a mock blockchain:

```bash
go run ./cmd/custody
```

This demonstrates:
- DKG ceremony (2-of-3 threshold)
- Address derivation
- Deposit simulation
- Policy evaluation
- Threshold signing
- Any 2-of-3 signer combinations

## Step 2: Real Testnet Integration

### Generate a Real Deposit Address

Create a small Go program or extend the CLI to:

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/NonsoAmadi10/btc-custody/internal/custody"
    "github.com/NonsoAmadi10/btc-custody/internal/policy"
    "github.com/NonsoAmadi10/btc-custody/internal/wallet"
    "github.com/btcsuite/btcd/chaincfg"
)

func main() {
    ctx := context.Background()
    
    // Use real mempool.space client
    client := wallet.NewMempoolClient("https://mempool.space/testnet/api")
    
    system, err := custody.New(custody.Config{
        Network:          &chaincfg.TestNet3Params,
        Threshold:        2,
        Total:            3,
        BlockchainClient: client,
        PolicyConfig: &policy.Config{
            Whitelist: policy.WhitelistConfig{
                Prefixes: []string{"tb1p", "tb1q"},
            },
        },
    })
    if err != nil {
        log.Fatal(err)
    }
    
    // Run DKG
    system.InitializeDKG()
    groupKey, err := system.RunDKGCeremony()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Group public key: %x\n", groupKey.SerializeCompressed())
    
    // Initialize wallet
    if err := system.InitializeWallet(ctx); err != nil {
        log.Fatal(err)
    }
    
    // Get deposit address
    addr, err := system.GetDepositAddress()
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("\n=== DEPOSIT ADDRESS ===\n")
    fmt.Printf("%s\n", addr)
    fmt.Printf("\nSend testnet BTC to this address, then sync and spend.\n")
}
```

### Sync and Check Balance

After sending testnet BTC:

```go
// Sync wallet with blockchain
if err := system.SyncWallet(ctx); err != nil {
    log.Fatal(err)
}

// Check balance
balance := system.GetBalance()
fmt.Printf("Balance: %d sats (%.8f BTC)\n", balance, float64(balance)/100_000_000)
```

### Create a Real Transaction

```go
// Spend to another testnet address
result, err := system.Spend(ctx, custody.SpendRequest{
    Destinations: []psbt.Recipient{
        {
            Address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", // Change this!
            Amount:  10_000, // 10k sats
        },
    },
    FeeRate:       1, // 1 sat/vbyte
    SignerIndices: []uint32{1, 2}, // Participants 1 and 2
}, true) // true = broadcast

if err != nil {
    log.Fatal(err)
}

fmt.Printf("Transaction broadcast!\n")
fmt.Printf("TXID: %s\n", result.TxID)
fmt.Printf("Fee: %d sats\n", result.Fee)
```

## Step 3: Verify on Block Explorer

After broadcasting, verify on:
- https://mempool.space/testnet/tx/{TXID}
- https://blockstream.info/testnet/tx/{TXID}

## Security Notes for Production

This prototype demonstrates the concepts. For production:

1. **Key share storage**: Use real HSMs (AWS CloudHSM, Azure HSM, YubiHSM)
2. **Network transport**: Add secure channels for DKG rounds between participants
3. **Audit logging**: Log all policy decisions and signing events
4. **Monitoring**: Alert on unusual transaction patterns
5. **Geographic distribution**: Run participants in different regions
6. **Cold storage**: Implement air-gapped signing for cold funds

## API Reference

### CustodySystem

| Method | Description |
|--------|-------------|
| `New(Config)` | Create custody system |
| `InitializeDKG()` | Start DKG ceremony |
| `RunDKGCeremony()` | Execute DKG, returns group key |
| `InitializeWallet(ctx)` | Initialize wallet with group key |
| `GetDepositAddress()` | Get next deposit address |
| `SyncWallet(ctx)` | Sync UTXOs from blockchain |
| `GetBalance()` | Return total balance in sats |
| `Spend(ctx, req, broadcast)` | Create and optionally broadcast transaction |
| `GetStatus()` | Return system status |
| `GroupPublicKey()` | Return the group public key |
| `GetParticipantShare(index)` | Return participant's key share |

### SpendRequest

```go
type SpendRequest struct {
    Destinations  []psbt.Recipient // Where to send
    FeeRate       int64            // Sats per vbyte
    SignerIndices []uint32         // Which participants sign
}
```

### SpendResult

```go
type SpendResult struct {
    RawTx          string            // Hex-encoded signed tx
    TxID           string            // Transaction ID (if broadcast)
    Fee            int64             // Fee in sats
    PolicyDecision policy.Decision   // Policy evaluation result
}
```

## Test Scenarios

### Happy Path
1. Create 2-of-3 system
2. Run DKG
3. Generate deposit address
4. Receive funds
5. Spend with signers {1,2}, {1,3}, or {2,3}
6. Verify on block explorer

### Policy Denial
1. Configure strict whitelist
2. Attempt to send to non-whitelisted address
3. Verify policy denies

### Threshold Enforcement
1. Attempt to spend with only 1 signer
2. Verify system rejects (needs 2)

### Velocity Limit
1. Configure 0.001 BTC/day limit
2. Make several small transactions
3. Verify limit enforced

## Troubleshooting

### "no UTXOs available"
- Check that the deposit address received funds
- Wait for 1 confirmation
- Call `SyncWallet()` to refresh

### "policy denied"
- Check whitelist configuration
- Check velocity limits
- Check approval requirements

### "insufficient signers"
- Provide at least `threshold` signer indices
- Indices must be valid (1 to N)

### "invalid signature"
- This indicates a bug in Taproot key handling
- File an issue with transaction details
