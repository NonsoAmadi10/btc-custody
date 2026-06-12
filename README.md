# BTC Custody

[![CI](https://github.com/NonsoAmadi10/btc-custody/actions/workflows/ci.yml/badge.svg)](https://github.com/NonsoAmadi10/btc-custody/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/NonsoAmadi10/btc-custody)](https://goreportcard.com/report/github.com/NonsoAmadi10/btc-custody)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Bitcoin custody system implementing FROST threshold signatures for Taproot. The private key is never assembled—not at generation, not at signing.

## Overview

This system enables t-of-n threshold signing for Bitcoin transactions. Any subset of t participants can collaboratively sign a transaction without any party ever possessing the complete private key.

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
│                    │ Taproot Address │  tb1p...                 │
│                    │    (P2TR)       │                          │
│                    └─────────────────┘                          │
│                                                                  │
│   Any 2 participants can sign. No party sees the full key.      │
└─────────────────────────────────────────────────────────────────┘
```

### Features

- **FROST DKG** — Distributed key generation with no trusted dealer
- **Taproot Native** — BIP-341 key-spend paths, indistinguishable from single-sig on-chain
- **Policy Engine** — Whitelist, velocity limits, tiered approvals, business hours
- **HSM Integration** — PKCS#11 interface for hardware security modules
- **Tested** — 63 tests including 9 STRIDE threat model validations

## Quick Start

```bash
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
    ├── frost-signing-deep-dive.md # Cryptography deep dive
    └── testnet-deployment.md     # Testnet deployment guide
```

## Usage

### Distributed Key Generation

```go
system, _ := custody.New(custody.Config{
    Network:   &chaincfg.TestNet3Params,
    Threshold: 2,
    Total:     3,
})

system.InitializeDKG()
groupKey, _ := system.RunDKGCeremony()
// groupKey is public; no party has the private key
```

### Policy Configuration

```go
PolicyConfig{
    Whitelist: { Prefixes: []string{"tb1p", "tb1q"} },
    Velocity:  { MaxAmount: 10_000_000, Window: "24h" },
    Tiered:    { Tiers: [...] },
}
// Deny by default. All rules must pass.
```

### Threshold Signing

```go
result, _ := system.Spend(ctx, SpendRequest{
    Destinations:  []Recipient{{Address: "tb1q...", Amount: 10000}},
    SignerIndices: []uint32{1, 2},  // Any 2 of 3
}, true)
```

## Policy Rules

| Rule | Description |
|------|-------------|
| Whitelist | Only approved addresses or prefixes allowed |
| Velocity | Cumulative spending limits per time window |
| Tiered | Approval requirements based on transaction amount |
| Schedule | Business hours restrictions |
| Quorum | Multi-party human approval for large transactions |

## Security Model

The system implements STRIDE threat modeling. See [docs/architecture.md](docs/architecture.md) for the complete analysis.

| Threat | Mitigation |
|--------|------------|
| Single point of compromise | t-of-n threshold; no party has full key |
| Unauthorized destination | Whitelist rule in policy engine |
| Rapid fund drainage | Velocity limits with sliding window |
| Insider attack | Quorum approvals for large amounts |
| Key extraction | Shares stored in HSM; no reconstruction API |

### Threat Model Validation

```bash
go test ./internal/custody/... -run Threat -v
```

9 attack scenarios validated:
- Insufficient signers rejected
- Invalid signer index rejected
- Whitelist bypass blocked
- Velocity limit enforced
- Duplicate signer rejected
- Zero signers rejected
- Insufficient funds handled
- Key shares never assembled
- Taproot output key correctly used

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

| Package | Tests | Description |
|---------|-------|-------------|
| internal/frost | 6 | DKG + signing |
| internal/hsm | 3 | PKCS#11 (requires HSM) |
| internal/psbt | 3 | PSBT + Taproot |
| internal/policy | 23 | All 5 rules |
| internal/wallet | 17 | Address + UTXO |
| internal/custody | 14 | Integration + threat |
| **Total** | **63** | |

## Documentation

| Document | Description |
|----------|-------------|
| [architecture.md](docs/architecture.md) | System design, data flows, STRIDE threat model |
| [frost-mathematics.md](docs/frost-mathematics.md) | Shamir, Feldman VSS, FROST from first principles |
| [frost-signing-deep-dive.md](docs/frost-signing-deep-dive.md) | Cryptography deep dive |
| [testnet-deployment.md](docs/testnet-deployment.md) | Deploy to Bitcoin testnet |
| [SETUP.md](SETUP.md) | Development setup |

## Production Considerations

This is a prototype. For production deployment:

- Replace SoftHSM with hardware HSMs (AWS CloudHSM, YubiHSM)
- Add network transport for distributed DKG (gRPC, libp2p)
- Implement audit logging and monitoring
- Geographic distribution of signers
- Air-gapped signing for cold storage

## Concepts

- Bitcoin Taproot (BIP-341)
- Schnorr signatures (BIP-340)
- FROST threshold signatures
- Shamir's Secret Sharing
- Feldman Verifiable Secret Sharing
- PSBT (BIP-174)
- PKCS#11 HSM interface
- STRIDE threat modeling

## License

MIT License. See [LICENSE](LICENSE).

## Author

Chinonso Amadi
