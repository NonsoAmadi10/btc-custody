# Dev Environment Setup

Get the project running on a new machine in under 10 minutes.

## Prerequisites

```bash
brew install go softhsm opensc
```

Go 1.25+ is required (the btcec v2 dependency uses range-over-int).

## Clone and install dependencies

```bash
git clone https://github.com/NonsoAmadi10/btc-custody.git
cd btc-custody
go mod download
```

## Initialise SoftHSM2

SoftHSM2 simulates a hardware HSM. Run this once per machine:

```bash
mkdir -p ~/.softhsm2/tokens

cat > ~/.softhsm2/softhsm2.conf <<'EOF'
directories.tokendir = /Users/$USER/.softhsm2/tokens
objectstore.backend = file
log.level = INFO
EOF

export SOFTHSM2_CONF=~/.softhsm2/softhsm2.conf

softhsm2-util --init-token --slot 0 --label "btc-custody" --pin 1234 --so-pin 0000
```

Note the slot number printed (e.g. `943771573`) -- you need it for tests.

## Run the tests

```bash
export SOFTHSM2_CONF=~/.softhsm2/softhsm2.conf

SLOT=$(softhsm2-util --show-slots 2>&1 | grep "^Slot " | head -1 | awk '{print $2}')

SOFTHSM2_CONF=~/.softhsm2/softhsm2.conf \
SOFTHSM2_LIB=$(find /opt/homebrew /usr/local -name "libsofthsm2.so" 2>/dev/null | head -1) \
SOFTHSM2_SLOT=$SLOT \
go test ./... -v
```

Expected: **63 tests pass** (6 FROST DKG + 3 HSM skipped + 3 PSBT + 23 Policy + 17 Wallet + 14 Custody).

## What has been built

| Package | Description |
|---------|-------------|
| `internal/frost` | Full FROST DKG: polynomial secret sharing, Feldman VSS, Round1/ShareFor/Finalise |
| `internal/hsm` | PKCS#11 key-share storage via SoftHSM2: StoreShare, SignHMAC (CKM_SHA256_HMAC in-HSM), DeleteShare |
| `internal/psbt` | PSBT construction and FROST threshold signing for Taproot: Builder, NonceCommitment, Sign, Aggregate |
| `internal/policy` | Transaction authorization rules: Whitelist, Velocity, Tiered, Schedule, Quorum |
| `internal/wallet` | Address derivation, UTXO tracking, blockchain queries via mempool.space API |
| `internal/custody` | Main orchestrator: DKG ceremony, wallet init, policy-checked spending, full integration |
| `cmd/custody` | Interactive demo CLI for walkthrough |
| `cmd/testnet` | Real testnet CLI for Bitcoin testnet deployment |

### Key files

- `docs/architecture.md` -- system design, four components, STRIDE threat model
- `docs/frost-mathematics.md` -- Shamir, Feldman VSS, FROST DKG from first principles with code references
- `docs/frost-signing-deep-dive.md` -- comprehensive crypto explainer for interviews
- `docs/testnet-deployment.md` -- guide for deploying to Bitcoin testnet

## What is next

1. ~~**PSBT construction**~~ ✅ -- `internal/psbt/` -- PSBT building, Taproot address derivation, FROST signing
2. ~~**Policy engine**~~ ✅ -- `internal/policy/` -- whitelist, velocity limits, business-hours, approver quorum, tiered approvals
3. ~~**Wallet infrastructure**~~ ✅ -- `internal/wallet/` -- hot/cold address derivation, UTXO tracking, mempool.space client
4. ~~**Integration**~~ ✅ -- `internal/custody/` -- full orchestration: DKG → deposit → policy check → threshold sign → broadcast
5. ~~**CLI Demo**~~ ✅ -- `cmd/custody/` -- interactive demo of full custody flow
6. ~~**Threat model validation**~~ ✅ -- 9 security tests validating STRIDE controls
7. ~~**Testnet deployment**~~ ✅ -- `cmd/testnet/` + `docs/testnet-deployment.md`

## Quick Start

```bash
# Run all tests
go test ./...

# Interactive demo (mock blockchain)
go run ./cmd/custody

# Real testnet
go run ./cmd/testnet init
go run ./cmd/testnet deposit
go run ./cmd/testnet balance
go run ./cmd/testnet spend
```

## Environment variables reference

| Variable | Example | Purpose |
|----------|---------|---------|
| `SOFTHSM2_CONF` | `~/.softhsm2/softhsm2.conf` | Points to token directory config |
| `SOFTHSM2_LIB` | `/opt/homebrew/.../libsofthsm2.so` | Override library path auto-detection |
| `SOFTHSM2_SLOT` | `943771573` | Token slot number (from `--show-slots`) |
| `SOFTHSM2_PIN` | `1234` | User PIN set during `--init-token` |
