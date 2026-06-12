# BTC Custody

[![Go](https://github.com/NonsoAmadi10/btc-custody/actions/workflows/ci.yml/badge.svg)](https://github.com/NonsoAmadi10/btc-custody/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/NonsoAmadi10/btc-custody)](https://goreportcard.com/report/github.com/NonsoAmadi10/btc-custody)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A **production-grade Bitcoin custody system** implementing FROST threshold signatures for Taproot. No single party ever sees the full private key—not at generation, not at signing.

<p align="center">
  <img src="https://img.shields.io/badge/Bitcoin-Taproot-orange" alt="Bitcoin Taproot"/>
  <img src="https://img.shields.io/badge/Signatures-FROST%20Threshold-blue" alt="FROST"/>
  <img src="https://img.shields.io/badge/Tests-63%20passing-brightgreen" alt="Tests"/>
</p>

## What This Does

```
┌─────────────────────────────────────────────────────────────────┐
│                    2-of-3 Threshold Custody                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Participant 1        Participant 2        Participant 3        │
│   ┌──────────┐         ┌──────────┐         ┌──────────┐        │
│   │  Share 1 │         │  Share 2 │         │  Share 3 │        │
│   └────┬─────┘         └────┬─────┘         └────┬─────┘        │
│        │                    │                    │               │
│        └────────────────────┼────────────────────┘               │
│                             │                                    │
│                    ┌────────▼────────┐                          │
│                    │  Group Public   │                          │
│                    │      Key        │                          │
│                    └────────┬────────┘                          │
│                             │                                    │
│                    ┌────────▼────────┐                          │
│                    │ Taproot Address │  ← tb1p...               │
│                    │    (P2TR)       │                          │
│                    └─────────────────┘                          │
│                                                                  │
│   Any 2 participants can sign. No party sees the full key.      │
└─────────────────────────────────────────────────────────────────┘
```

### Key Features

- **🔐 FROST DKG** — Distributed key generation with no trusted dealer
- **⚡ Taproot Native** — BIP-341 key-spend paths, indistinguishable from single-sig
- **🛡️ Policy Engine** — Whitelist, velocity limits, tiered approvals, business hours
- **💾 HSM Ready** — PKCS#11 interface for hardware security modules
- **🧪 Battle-tested** — 63 tests including 9 STRIDE threat validations

## Quick Start

```bash
# Clone
git clone https://github.com/NonsoAmadi10/btc-custody.git
cd btc-custody

# Run tests
go test ./...

# Interactive demo
go run ./cmd/custody

# Real testnet
go run ./cmd/testnet init
go run ./cmd/testnet deposit
go run ./cmd/testnet balance
go run ./cmd/testnet spend
```

## Architecture

```
btc-custody/
├── cmd/
│   ├── custody/          # Interactive demo CLI
│   └── testnet/          # Real testnet CLI
├── internal/
│   ├── frost/            # FROST DKG + threshold signing
│   ├── hsm/              # PKCS#11 key storage (SoftHSM2)
│   ├── psbt/             # PSBT construction + Taproot signing
│   ├── policy/           # Transaction authorization rules
│   ├── wallet/           # Address derivation, UTXO tracking
│   └── custody/          # Main orchestrator
└── docs/
    ├── architecture.md           # System design + STRIDE threat model
    ├── frost-mathematics.md      # Shamir, Feldman VSS, FROST math
    ├── frost-signing-deep-dive.md # Interview prep guide
    └── testnet-deployment.md     # Testnet deployment guide
```

## How It Works

### 1. Distributed Key Generation (DKG)

```go
// Each participant generates a secret polynomial
// Shares are distributed so that t-of-n can reconstruct
system.InitializeDKG()
groupKey, _ := system.RunDKGCeremony()
// groupKey is public; no party has the private key
```

### 2. Policy Evaluation

```go
// Every transaction passes through policy rules
PolicyConfig{
    Whitelist: { Addresses: [...], Prefixes: ["tb1p", "tb1q"] },
    Velocity:  { MaxAmount: 10_000_000, Window: "24h" },
    Tiered:    { Tiers: [...] },
}
// Deny by default. All rules must pass.
```

### 3. Threshold Signing

```go
// Any t-of-n participants can produce a valid signature
result, _ := system.Spend(ctx, SpendRequest{
    Destinations:  []Recipient{{Address: "tb1q...", Amount: 10000}},
    SignerIndices: []uint32{1, 2},  // Participants 1 and 2
}, true)
// result.TxID contains the broadcast transaction
```

## Policy Rules

| Rule | Description |
|------|-------------|
| **Whitelist** | Only approved addresses/prefixes allowed |
| **Velocity** | Cumulative spending limits per time window |
| **Tiered** | Approval requirements based on amount |
| **Schedule** | Business hours restrictions |
| **Quorum** | Multi-party human approval |

## Security Model

Based on STRIDE threat analysis. See [docs/architecture.md](docs/architecture.md).

| Threat | Mitigation |
|--------|------------|
| Single point of compromise | t-of-n threshold; no party has full key |
| Unauthorized destination | Whitelist rule in policy engine |
| Rapid fund drainage | Velocity limits with sliding window |
| Insider attack | Quorum approvals for large amounts |
| Key extraction | Shares stored in HSM; no reconstruction API |

### Threat Model Tests

```bash
go test ./internal/custody/... -run Threat -v
```

All 9 threat scenarios validated:
- ✅ Insufficient signers rejected
- ✅ Invalid signer index rejected  
- ✅ Whitelist bypass blocked
- ✅ Velocity limit enforced
- ✅ Duplicate signer rejected
- ✅ Zero signers rejected
- ✅ Insufficient funds handled
- ✅ Key shares never assembled
- ✅ Taproot output key correctly used

## Requirements

- Go 1.21+
- SoftHSM2 (optional, for HSM tests)

```bash
# macOS
brew install go softhsm

# Linux
apt install golang softhsm2
```

## Test Coverage

```
Package          Tests   Coverage
───────────────────────────────────
internal/frost      6    Core DKG + signing
internal/hsm        3    PKCS#11 (skipped without HSM)
internal/psbt       3    PSBT + Taproot
internal/policy    23    All 5 rules
internal/wallet    17    Address + UTXO + client
internal/custody   14    Integration + threat tests
───────────────────────────────────
Total              63    passing
```

## Documentation

| Document | Description |
|----------|-------------|
| [architecture.md](docs/architecture.md) | System design, data flows, STRIDE threat model |
| [frost-mathematics.md](docs/frost-mathematics.md) | Shamir, Feldman VSS, FROST from first principles |
| [frost-signing-deep-dive.md](docs/frost-signing-deep-dive.md) | Interview-ready crypto explainer |
| [testnet-deployment.md](docs/testnet-deployment.md) | Deploy to Bitcoin testnet |
| [SETUP.md](SETUP.md) | Quick development setup |

## Production Considerations

This is a **learning prototype**. For production:

- [ ] Replace SoftHSM with hardware HSMs (AWS CloudHSM, YubiHSM)
- [ ] Add network transport for distributed DKG (gRPC, libp2p)
- [ ] Implement audit logging and monitoring
- [ ] Add geographic distribution of signers
- [ ] Implement cold storage with air-gapped signing

## Concepts Demonstrated

- Bitcoin Taproot (BIP-341)
- Schnorr signatures (BIP-340)
- FROST threshold signatures
- Shamir's Secret Sharing
- Feldman VSS
- PSBT (BIP-174)
- PKCS#11 HSM interface
- Policy engine design
- STRIDE threat modeling

## License

MIT License. See [LICENSE](LICENSE).

## Author

**Chinonso Amadi** — Platform Engineer → Security Engineer

Building in public. Learning Bitcoin internals, cryptography, and custody systems.

---

<p align="center">
  <i>The private key is never assembled. Not at generation. Not at signing. Ever.</i>
</p>
