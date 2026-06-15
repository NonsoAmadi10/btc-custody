# BTC Custody System -- Architecture

**Author:** cipher  
**Status:** Design (pre-implementation)  
**Last updated:** 2026-05-22

---

## Purpose

This document defines the architecture of a production-grade Bitcoin custody
system. It exists to answer three questions before a single line of code is
written:

1. What are the components, what does each one own, and what are the
   boundaries between them?
2. What is the data flow for every transaction type?
3. What is the threat model -- what does the system protect against, and what
   does it explicitly not protect against?

Every implementation decision made during the build must be traceable back to
this document. If a decision cannot be justified here, the design needs to be
updated first.

---

## Background: Why This Architecture Exists

Traditional key storage (encrypt a private key, store it in a database or
HSM) solves the problem of keys being stolen from a database. It does not
solve three harder problems:

**1. The single point of assembly problem**
An HSM holds a complete private key. At the moment of signing, the full key
material is present in one place. A compromised HSM firmware, a rogue
operator with physical access, or a vendor backdoor exposes the complete key.
One breach, all funds gone.

**2. The policy enforcement problem**
An HSM signs whatever it is instructed to sign, given valid authentication.
It has no concept of business rules -- velocity limits, destination whitelists,
approval quorums, time windows. Those rules must be enforced externally, which
means they can be bypassed externally.

**3. The availability problem**
A single HSM is a single point of failure. Geographic replication means the
key exists in multiple places, which increases the attack surface.

This system solves all three by ensuring the private key is never assembled
anywhere -- not at generation, not at signing. Instead, key material exists
only as mathematical shares distributed across independent participants. A
valid signature requires a threshold of participants to cooperate. No single
compromise is sufficient.

---

## System Components

The system has four components with hard boundaries between them.

### 1. Key Ceremony

**What it is:** A one-time, offline procedure that bootstraps the entire
system. It runs once. It is never repeated unless the system is fully
rebuilt from scratch.

**What it owns:**
- Distributed Key Generation (DKG) using the FROST protocol
- Derivation of the hot wallet address
- Derivation of the cold wallet address (immutable after ceremony)
- Distribution of key shares to N participants
- Generation of the policy seed configuration

**What it does not own:**
- Any runtime transaction logic
- The policy engine configuration beyond the initial seed
- Wallet balances or UTXOs

**Key property:** The complete private key is never assembled during or after
the ceremony. Each participant receives one share. The group public key (and
therefore the wallet addresses) can be derived from the public components of
the shares without ever reconstructing the private key.

**The cold address immutability guarantee:** The cold wallet address is derived
during the ceremony and written into the policy seed config as a hardcoded
constant. No runtime component can change it. An emergency sweep always goes
to this address and nowhere else. This constraint is enforced in code, not by
policy.

---

### 2. Policy Engine

**What it is:** The compliance layer. Runs continuously. Every transaction
request -- whether initiated by an operator, an automated sweep trigger, or an
API call -- must pass through the policy engine before reaching the signing
ceremony. The policy engine either approves, rejects, or queues the
transaction.

**What it owns:**
- Rule evaluation (whitelist, velocity, time window, approver count)
- Tier routing (which signing tier is required for this transaction)
- The sweep trigger logic (balance-threshold and time-based modes)
- The approval workflow (collecting and verifying human approvals)
- The emergency protocol (detecting and routing emergency sweeps)

**What it does not own:**
- Key material of any kind
- Destination addresses (it reads the cold address from the immutable config,
  it does not set it)
- The cryptographic signing operation

**Rule set:**

| Rule | Check | On failure |
|------|-------|------------|
| Address whitelist | destination in approved_addresses | Reject, alert |
| Velocity limit | sum(txns, 24h) + amount <= daily_limit | Reject, escalate |
| Business hours | current_time in allowed_window (UTC) | Queue or emergency override |
| Approver quorum | approval_count >= required_for_tier | Hold, notify approvers |
| Emergency destination | if emergency tier: destination == cold_address | Hard reject |
| Floor balance | hot_balance > floor_balance | Halt all outbound, alert |

**Sweep profiles:**

```
TRADING profile
  top-up trigger:   hot_balance < min_threshold
  sweep-down:       hot_balance > max_threshold
  mechanism:        balance-threshold, continuous monitoring

LIQUIDITY PROVISION profile
  top-up trigger:   time-based (configurable interval, default 30m)
  sweep-down:       post-cycle event-driven
  mechanism:        scheduled + event

HALT condition (either profile)
  trigger:          hot_balance < floor_balance
  action:           suspend all outbound transactions, alert all operators
  resume:           manual operator authorisation only
```

**Authorisation tiers:**

```
TIER 1 -- Normal operations
  threshold:    2-of-3 (small amounts) or 3-of-5 (large amounts)
  amount gate:  configurable per deployment
  permissions:  any whitelisted transaction within velocity limits

TIER 2 -- Emergency sweep
  threshold:    1-of-5 or 2-of-5
  permissions:  ONLY sweep to the hardcoded cold address
  hard limits:  cannot send to any other address
                cannot change whitelist
                cannot change policy config
                cannot modify tier definitions
```

**Duress protocol:** A designated duress PIN, known only to key holders, can
be submitted alongside an approval. The policy engine accepts the transaction
visually but delays broadcast by 24 hours and fires a silent alert to all
registered operators. This provides a defence against physical coercion (the
"5-dollar wrench attack") without alerting the attacker that the delay has
been triggered.

---

### 3. FROST Signing Ceremony

**What it is:** The cryptographic layer. Takes a transaction that the policy
engine has already approved and produces a valid aggregated Schnorr signature
using the FROST threshold signing protocol.

**What it owns:**
- The 2-round FROST signing protocol (nonce commitment + partial signature)
- Lagrange coefficient computation
- Partial signature aggregation
- Producing a final 64-byte Schnorr signature valid on the Bitcoin network

**What it does not own:**
- Transaction routing or destination logic (owned by policy engine)
- Any opinion on whether the transaction is valid from a business perspective
- Key share storage (shares are held by participants, not by this component)

**Critical property -- policy blindness:** The signing ceremony does not know
or care where a transaction is sending funds. By the time a transaction
arrives here, the policy engine has already validated destination, amount,
approvals, and tier. The signing ceremony asks only one question: "Do I have
t valid partial signatures from authorised participants?" If yes, it
aggregates and returns the final signature. This separation means that
compromising the signing layer does not give an attacker control over
destinations.

**The FROST protocol in this system:**

```
Round 1 -- Nonce commitment (before the transaction is known)
  Each participant i generates random nonce pair (d_i, e_i)
  Publishes commitments D_i = d_i*G, E_i = e_i*G
  Commitments are collected by the coordinator

Round 2 -- Partial signature (after transaction is approved by policy engine)
  Binding factor per participant:
    rho_i = H(i || message || all_commitments)
  Challenge hash:
    c = H(group_pubkey || R || message)
  Partial signature:
    s_i = d_i + (e_i * rho_i) + lambda_i * x_i * c
  Where lambda_i is the Lagrange coefficient for participant i

Aggregation (coordinator):
  s = sum(s_i for participating signers)
  R = sum(D_i + rho_i * E_i for participating signers)
  Final signature: (R, s) -- standard 64-byte Schnorr
```

The final signature is indistinguishable on-chain from a single-key spend.
There is no on-chain fingerprint of threshold signing.

**PSBT as the transport format:** Unsigned transactions travel between the
policy engine, the coordinator, and the signing participants as PSBTs (BIP
174). Each participant adds their partial signature to the PSBT. The
coordinator finalises the PSBT and extracts the signed transaction for
broadcast. For cold wallet operations, PSBTs travel on USB or QR code --
no network connection touches cold key material.

---

### 4. Wallet Infrastructure

**What it is:** The two-tier fund storage layer.

**Hot wallet:**
- Online, connected to the Bitcoin network
- Holds the operating balance for day-to-day transactions
- Key shares held on networked HSM-backed machines
- Signing is automated (no human in the loop for routine transactions
  within policy)
- FROST threshold: 2-of-3

**Cold wallet:**
- Air-gapped, never connected to the internet
- Holds the bulk reserve
- Key shares held on offline hardware (hardware wallets or air-gapped
  machines)
- Signing requires physical human presence and quorum
- PSBT transport: USB or QR code only
- FROST threshold: 3-of-5

**Balance management:**

```
hot_balance > sweep_down_threshold  →  sweep excess to cold
hot_balance < top_up_threshold      →  request top-up from cold
hot_balance < floor_balance         →  HALT, alert, no auto top-up
```

---

## Transaction Data Flows

### Flow 1: Normal outbound payment

```
1. Request arrives (API or operator)
2. Policy engine evaluates:
   a. Is destination in whitelist?           → fail: reject
   b. Is amount within velocity limit?       → fail: reject
   c. Is it within business hours?           → fail: queue
   d. Has second approver confirmed?         → fail: hold, notify
3. Policy engine routes to Tier 1 signing
4. FROST coordinator collects nonce commitments from 3 participants
5. Policy engine serialises approved transaction as PSBT
6. FROST coordinator distributes PSBT to 3 participants
7. Each participant computes partial signature, adds to PSBT
8. Coordinator aggregates: final Schnorr signature
9. Finalised transaction broadcast to Bitcoin network
10. Policy engine records transaction, updates velocity counter
```

### Flow 2: Automated hot-to-cold sweep (trading profile)

```
1. Policy engine sweep monitor: hot_balance > sweep_down_threshold
2. Policy engine constructs sweep transaction:
   destination = immutable cold address (from policy seed config)
   amount = hot_balance - target_balance
3. No human approval required (sweep to cold is always permitted)
4. Routes to Tier 1 FROST signing (automated)
5. Signed transaction broadcast
6. Cold wallet UTXO set updated
```

### Flow 3: Cold-to-hot top-up

```
1. Policy engine: hot_balance < top_up_threshold (or time trigger)
2. Policy engine constructs top-up request as PSBT
3. PSBT written to USB / displayed as QR code (no network)
4. Human operator carries PSBT to air-gapped cold signing machine
5. Operator reviews transaction on screen: destination = hot address,
   amount = requested top-up
6. 3-of-5 cold key holders physically present, each sign the PSBT
7. Finalised PSBT returned via USB / QR to coordinator
8. Coordinator broadcasts signed transaction
9. Hot wallet UTXO set updated
```

### Flow 4: Emergency sweep

```
1. Trigger: operator submits emergency request OR automated anomaly
   detection (balance draining abnormally fast)
2. Policy engine validates:
   a. Is this Tier 2? (emergency flag set)
   b. Is the destination == hardcoded cold address?  → if not: hard reject
   c. Does the requester hold a valid Tier 2 key share?
3. Routes to Tier 2 FROST signing: 1-of-5 or 2-of-5
4. Signed sweep transaction broadcast immediately
5. All operators alerted
6. System enters HALT state -- no further outbound transactions until
   manual review and restart
```

---

## Threat Model

Methodology: STRIDE applied per trust boundary.

### Trust boundaries

```
B1: External network → API / operator interface
B2: Policy engine → FROST signing coordinator
B3: Coordinator → individual signing participants
B4: Hot wallet infrastructure → cold wallet (the air gap)
B5: Operator device → policy engine (approval workflow)
```

### STRIDE analysis

**B1 -- External to API**

| Threat | Attack | Control |
|--------|--------|---------|
| Spoofing | Attacker impersonates operator | mTLS client certificates, hardware tokens |
| Tampering | Attacker modifies transaction in transit | Request signing, TLS |
| Repudiation | Operator denies approving a transaction | Append-only approval audit log |
| Info Disclosure | Transaction details leaked | Encrypted transport, minimal logging |
| DoS | Flood API with requests | Rate limiting, circuit breakers |
| Elevation | API caller accesses admin functions | RBAC, separate admin interface |

**B2 -- Policy engine to signing coordinator**

| Threat | Attack | Control |
|--------|--------|---------|
| Tampering | Attacker modifies approved transaction between policy engine and coordinator | Policy engine signs the PSBT hash before forwarding; coordinator verifies signature |
| Spoofing | Fake coordinator intercepts signing requests | Mutual authentication, coordinator identity in policy seed config |
| Elevation | Compromised coordinator changes transaction destination | Coordinator is policy-blind; destination already committed in PSBT |

**B3 -- Coordinator to signing participants**

| Threat | Attack | Control |
|--------|--------|---------|
| Spoofing | Malicious participant pretends to be another | FROST DKG produces participant identity commitments verified per round |
| Tampering | Participant submits malformed partial signature | Aggregation verification: final signature checked against group pubkey before broadcast |
| DoS | Participant withholds signature to block signing | t-of-n threshold: any t of n participants suffice; withheld participant is bypassed |
| Info Disclosure | Partial signature reveals key share | FROST partial signatures are computationally indistinguishable from random without the nonce; binding factor prevents Wagner attack |

**B4 -- Hot to cold (air gap)**

| Threat | Attack | Control |
|--------|--------|---------|
| Tampering | Malicious PSBT on USB changes destination | Cold signing machine displays full transaction for human review before signing |
| Physical theft | USB with PSBT intercepted | PSBT contains no key material; a stolen unsigned PSBT reveals nothing |
| Supply chain | Compromised USB firmware | Verify PSBT hash out-of-band before inserting USB |

**B5 -- Operator device to policy engine**

| Threat | Attack | Control |
|--------|--------|---------|
| Spoofing | Attacker phishes operator credentials | Hardware token 2FA, device attestation |
| Coercion | Operator forced to approve under duress | Duress PIN triggers silent 24h delay and alert |
| Insider threat | Operator approves malicious transaction | Requires second independent approver; velocity limits cap damage |

### What this system does NOT protect against

Being explicit about the threat model boundary is as important as the threats we do address.

- **Consensus-layer attacks:** A 51% attack on Bitcoin affects all custodians equally. Out of scope.
- **Endpoint compromise before the API boundary:** If an operator's laptop is compromised before they submit an approval, the attacker can approve legitimate-looking transactions. Mitigated but not eliminated by hardware tokens.
- **Side-channel attacks on signing machines:** Power analysis, timing attacks on the hardware running FROST participants. Requires physical security controls outside this system's scope.
- **Key ceremony compromise:** If the DKG is run on compromised hardware, all derived key material is compromised. The ceremony's security depends entirely on the physical security of that environment.
- **Cryptographic breaks:** If discrete logarithm is broken (quantum adversary), Schnorr and FROST both fail. Post-quantum migration is a separate workstream.

---

## What We Are Building (Prototype Scope)

This is a research prototype. It implements the full architecture at reduced
scale to demonstrate every concept. Production deployment would require
additional hardening at each layer.

| Component | What we build | What we defer |
|-----------|--------------|---------------|
| Key Ceremony | FROST DKG with SoftHSM2 for share storage | Real HSM hardware (YubiHSM, Thales) |
| Policy Engine | Rules engine in Go: whitelist, velocity, hours, tiers | TEE execution (AWS Nitro), HA deployment |
| FROST Signing | Full 2-round protocol, partial sig aggregation | Hardware-backed participant nodes |
| Wallet Infra | Bitcoin testnet, hot/cold address management | Mainnet, multi-datacenter redundancy |
| PSBT Transport | File-based (simulates USB air gap) | Physical air-gap hardware |
| Sweep Monitor | Balance polling + time-based triggers | Real-time mempool monitoring |
| Audit Log | Append-only local log | Tamper-evident log (Trillian, Certificate Transparency) |
| Duress Protocol | Configurable delay + stdout alert | Out-of-band alerting (PagerDuty, SMS) |

---

## Technology Choices

| Layer | Technology | Why |
|-------|-----------|-----|
| Language | Go | Type safety, strong crypto stdlib, same language as lnaudit and LND |
| HSM interface | PKCS#11 via SoftHSM2 | Industry standard interface; SoftHSM2 lets us develop without hardware |
| FROST | frost-go or implement from spec | Understanding requires implementation |
| Bitcoin | btcd + bitcoind on testnet | btcd for library use, bitcoind for node |
| PSBT | btcd/wire or bitcoin/btcutil | Native Go PSBT support |
| Policy config | YAML + Go struct, validated at startup | Human-readable, version-controllable |
| Audit log | Structured JSON, append-only file | Simple, inspectable, replaceable |

---

## Directory Structure (planned)

```
btc-custody/
  docs/
    architecture.md          ← this document
    threat-model.md          ← detailed STRIDE analysis (to be expanded)
    key-ceremony.md          ← ceremony procedure and runbook
  cmd/
    ceremony/                ← one-time DKG runner
    coordinator/             ← FROST signing coordinator
    policy/                  ← policy engine daemon
    wallet/                  ← wallet monitor and sweep daemon
  internal/
    frost/                   ← FROST DKG and signing implementation
    policy/                  ← rule engine, tier routing, approval workflow
    psbt/                    ← PSBT construction, signing, finalisation
    hsm/                     ← PKCS#11 interface and SoftHSM2 integration
    wallet/                  ← hot/cold wallet, UTXO management, sweep logic
    audit/                   ← append-only audit log
  config/
    policy.yaml              ← policy rules, thresholds, whitelist
    ceremony.yaml            ← DKG parameters, participant count, threshold
```

---

## Build Order

We build bottom-up. Each layer is tested and understood before the next is
added. No layer is skipped.

```
1. FROST implementation
   Understand the math before trusting a library.
   Build DKG, nonce commitment, partial signing, aggregation.
   Test on known vectors.

2. PKCS#11 / HSM integration
   Connect FROST share storage to SoftHSM2 via PKCS#11.
   Understand the key lifecycle: generate, store, use, destroy.

3. PSBT construction and transport
   Build and parse PSBTs for hot and cold flows.
   Simulate the air gap with file-based transport.

4. Policy engine
   Implement rule evaluation, tier routing, approval workflow.
   Every rule is independently tested.

5. Wallet infrastructure
   Hot/cold address management, UTXO tracking, sweep logic.
   Connect to Bitcoin testnet.

6. Integration
   Wire all components together.
   Run full flows: normal payment, sweep, top-up, emergency.

7. Threat model validation
   Attempt to violate each threat control from the threat model.
   Document what works and what doesn't.
```

---

## Open Questions (to be resolved during build)

1. FROST library vs from-scratch: implement from spec for learning, then
   replace with audited library for any production path?
2. SoftHSM2 PKCS#11 attribute model: which key attributes do we set to
   prevent key extraction (CKA_EXTRACTABLE = false)?
3. Sweep automation: how does the policy engine get reliable hot wallet
   balance data without trusting a single Bitcoin node?
4. Emergency sweep atomicity: if the emergency sweep transaction is broadcast
   but unconfirmed, and a second emergency is triggered, how do we avoid
   double-spend or UTXO contention? (We've seen this exact bug in LND PR
   #10816 -- apply the same UTXO leasing fix here.)
5. Audit log integrity: a local append-only file can be deleted by a root
   attacker. What is the minimum viable tamper-evidence for the prototype?
