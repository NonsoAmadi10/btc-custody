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

Expected: **13 tests pass** (6 FROST DKG + 4 HSM + 3 PSBT).

## What has been built

| Package | Description |
|---------|-------------|
| `internal/frost` | Full FROST DKG: polynomial secret sharing, Feldman VSS, Round1/ShareFor/Finalise |
| `internal/hsm` | PKCS#11 key-share storage via SoftHSM2: StoreShare, SignHMAC (CKM_SHA256_HMAC in-HSM), DeleteShare |
| `internal/psbt` | PSBT construction and FROST threshold signing for Taproot: Builder, NonceCommitment, Sign, Aggregate |

### Key files

- `docs/architecture.md` -- system design, four components, STRIDE threat model
- `docs/frost-mathematics.md` -- Shamir, Feldman VSS, FROST DKG from first principles with code references

## What is next

1. ~~**PSBT construction**~~ ✅ -- `internal/psbt/` -- PSBT building, Taproot address derivation, FROST signing (nonce generation, partial signatures, aggregation)
2. **Policy engine** -- `internal/policy/` -- whitelist, velocity limits, business-hours check, approver quorum, tier routing, duress protocol
3. **Wallet infrastructure** -- `internal/wallet/` -- hot/cold address management, UTXO tracking on Bitcoin testnet
4. **Integration** -- wire all four components into a single ceremony + sweep flow
5. **Threat model validation** -- attempt to violate each control

## Environment variables reference

| Variable | Example | Purpose |
|----------|---------|---------|
| `SOFTHSM2_CONF` | `~/.softhsm2/softhsm2.conf` | Points to token directory config |
| `SOFTHSM2_LIB` | `/opt/homebrew/.../libsofthsm2.so` | Override library path auto-detection |
| `SOFTHSM2_SLOT` | `943771573` | Token slot number (from `--show-slots`) |
| `SOFTHSM2_PIN` | `1234` | User PIN set during `--init-token` |
