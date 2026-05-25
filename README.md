# btc-custody

A production-grade Bitcoin custody system prototype built to understand what
Fireblocks does from the inside.

## What this is

A research prototype implementing the full custody stack:

- **Key Ceremony** -- FROST distributed key generation (DKG), key shares
  distributed across N participants, hot and cold wallet addresses derived,
  cold address immutable after ceremony
- **Policy Engine** -- runtime compliance layer: address whitelist, velocity
  limits, business hours, multi-approver quorum, tiered authorisation,
  emergency sweep protocol, duress detection
- **FROST Signing** -- 2-round threshold signing (t-of-n), partial signature
  aggregation, final Schnorr signature indistinguishable from single-key spend
- **Wallet Infrastructure** -- hot wallet (online, automated, 2-of-3) and
  cold wallet (air-gapped, human quorum, 3-of-5), PSBT-based transport

## Why

A single HSM holding a complete private key is a single point of failure.
This system ensures the private key is never assembled anywhere -- not at
generation, not at signing. Threshold signing means no single compromise
is sufficient to steal funds.

## Status

Design phase. See [docs/architecture.md](docs/architecture.md) for the full
system design, data flows, and threat model before any code is written.

## Build order

1. FROST implementation (DKG + 2-round signing)
2. PKCS#11 / SoftHSM2 integration
3. PSBT construction and air-gap transport simulation
4. Policy engine (rules, tiers, approval workflow)
5. Wallet infrastructure (hot/cold, sweep logic, testnet)
6. Integration and threat model validation

## Concepts covered

Bitcoin protocol, Schnorr linearity, FROST threshold signing, MuSig2 vs FROST,
PSBT (BIP 174), PKCS#11 HSM interface, policy engine system design, hot/cold
wallet architecture, air-gapped signing workflows, STRIDE threat modeling,
duress protocols, tiered authorisation, velocity controls.
