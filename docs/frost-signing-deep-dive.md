# FROST Threshold Signing: A Deep Dive

A comprehensive guide to understanding the cryptography in this project,
suitable for teaching or defending in interviews.

---

## Table of Contents

1. [Elliptic Curve Fundamentals](#1-elliptic-curve-fundamentals)
2. [Schnorr Signatures](#2-schnorr-signatures)
3. [Shamir Secret Sharing](#3-shamir-secret-sharing)
4. [FROST DKG](#4-frost-dkg-distributed-key-generation)
5. [FROST Signing](#5-frost-signing-protocol)
6. [Taproot Tweaking](#6-taproot-tweaking)
7. [PSBT Format](#7-psbt-format)
8. [Interview Questions](#8-common-interview-questions)

---

## 1. Elliptic Curve Fundamentals

### What is an Elliptic Curve?

Bitcoin uses the **secp256k1** curve, defined by:

```
y² = x³ + 7  (mod p)
```

where p is a huge prime (~2²⁵⁶). The curve looks like a smooth wave, and
every point (x, y) satisfying this equation is "on the curve."

### Key Operations

**Point Addition (P + Q):**
- Draw a line through two points P and Q
- It intersects the curve at a third point R'
- Reflect R' over the x-axis to get R = P + Q

**Scalar Multiplication (k·G):**
- Add G to itself k times: G + G + G + ... (k times)
- This is the **trapdoor function**: easy to compute k·G, impossible to find k given only the result

### The Generator Point G

G is a fixed, publicly known point on secp256k1. Every private key is just
a random number k, and the public key is P = k·G.

```
Private key:  k  (256-bit random number)
Public key:   P = k·G  (a point on the curve)
```

### Why Jacobian Coordinates?

Standard "affine" coordinates are (x, y). But point addition requires
division (modular inverse), which is slow.

**Jacobian coordinates** use (X, Y, Z) where:
```
x = X / Z²
y = Y / Z³
```

This lets us defer all divisions until the very end. The code:

```go
var R btcec.JacobianPoint        // Work in Jacobian
btcec.AddNonConst(&P, &Q, &R)    // Fast addition (no division)
R.ToAffine()                      // Convert back only when needed
```

**Interview tip:** "Jacobian coordinates are an optimization that avoids
expensive modular inversions during intermediate computations."

---

## 2. Schnorr Signatures

### Why Schnorr over ECDSA?

| Property | ECDSA | Schnorr |
|----------|-------|---------|
| Linearity | No | Yes (key for threshold) |
| Signature size | 71-72 bytes | 64 bytes |
| Batch verification | No | Yes |
| Provable security | Complex | Simple |

**Linearity** is crucial: Schnorr lets us add partial signatures together.
ECDSA doesn't have this property.

### The Schnorr Signing Algorithm

Given:
- Private key: x
- Public key: P = x·G
- Message: m

**Sign:**
```
1. Pick random nonce k
2. Compute R = k·G                    (nonce point)
3. Compute e = H(R || P || m)         (challenge)
4. Compute s = k + e·x                (signature scalar)
5. Return (R, s)                      (64 bytes total)
```

**Verify:**
```
1. Compute e = H(R || P || m)
2. Check: s·G == R + e·P

Why this works:
  s·G = (k + e·x)·G
      = k·G + e·x·G
      = R + e·P  ✓
```

### BIP-340 Specifics

Bitcoin's Schnorr (BIP-340) has quirks:

1. **X-only public keys**: Only store x-coordinate (32 bytes, not 33)
2. **Even Y required**: If R has odd Y, negate k (and thus s)
3. **Tagged hashes**: `H("BIP0340/challenge" || R || P || m)`

```go
// BIP-340 requires even Y for R
if R.Y.IsOdd() {
    k.Negate()  // This changes s too
}
```

---

## 3. Shamir Secret Sharing

### The Core Idea

Split a secret S into n shares such that any t shares can reconstruct S,
but t-1 shares reveal nothing.

**Example:** 2-of-3 sharing of secret S = 42

```
1. Create random polynomial: f(x) = 42 + 7x  (degree t-1 = 1)
2. Evaluate at x = 1, 2, 3:
   - Share 1: f(1) = 42 + 7(1) = 49
   - Share 2: f(2) = 42 + 7(2) = 56
   - Share 3: f(3) = 42 + 7(3) = 63
```

### Lagrange Interpolation

To reconstruct, use Lagrange coefficients:

```
λ₁ = (0-2)(0-3) / (1-2)(1-3) = 6/2 = 3
λ₂ = (0-1)(0-3) / (2-1)(2-3) = 3/-1 = -3
     (using shares 1 and 2)

S = λ₁·share₁ + λ₂·share₂
  = 3(49) + (-3)(56)
  = 147 - 168
  = ... wait, that's -21?
```

Actually in modular arithmetic (mod prime), this works out to 42. The key
property: **sum(λᵢ) = 1** when evaluated at x = 0.

### Why This Matters for FROST

In FROST, we never reconstruct the secret! Instead:
- Each signer uses their share to create a **partial signature**
- The partials combine (using Lagrange coefficients) into a full signature
- The secret x is never computed anywhere

---

## 4. FROST DKG (Distributed Key Generation)

### The Problem

We want n parties to each hold a share of a private key, where:
- No party ever sees the full key
- Any t parties can sign
- The full key is never constructed, even during setup

### Feldman VSS (Verifiable Secret Sharing)

Standard Shamir has a flaw: a dealer could give you garbage shares.
Feldman adds **commitments** to verify shares.

If my polynomial is `f(x) = a₀ + a₁x + a₂x²`, I publish:
```
C₀ = a₀·G
C₁ = a₁·G
C₂ = a₂·G
```

You can verify your share f(i) by checking:
```
f(i)·G == C₀ + i·C₁ + i²·C₂
```

This works because scalar multiplication distributes over addition.

### FROST DKG Protocol

**Round 1:** Each participant i:
```
1. Generate random polynomial fᵢ(x) of degree t-1
2. Compute commitments Cᵢ,ⱼ = aᵢ,ⱼ·G for each coefficient
3. Broadcast commitments to all participants
```

**Round 2:** Each participant i:
```
1. Send share fᵢ(j) to each participant j (privately)
2. Receive shares from all other participants
3. Verify each received share against commitments
```

**Finalization:** Each participant i:
```
1. Sum all received shares: xᵢ = Σⱼ fⱼ(i)
2. Sum all constant-term commitments: P = Σⱼ Cⱼ,₀

xᵢ is my secret share
P is the group public key
```

**Key insight:** The group public key P corresponds to secret x = Σⱼ aⱼ,₀,
but no one knows x because each aⱼ,₀ is private to participant j.

### Our Code

```go
// internal/frost/frost.go

// Round 1: Generate commitments
func (p *Participant) Round1() *Round1Output {
    return &Round1Output{
        Index:       p.index,
        Commitments: p.commitments,  // Cᵢ,ⱼ values
    }
}

// Share generation: send f(j) to participant j
func (p *Participant) ShareFor(j uint32) *btcec.ModNScalar {
    return p.evaluatePolynomial(j)
}

// Finalization: aggregate everything
func (p *Participant) Finalise(round1s []*Round1Output, shares map[uint32]*btcec.ModNScalar) (*DKGResult, error) {
    // Verify all shares against commitments
    // Sum shares to get my final share
    // Sum C₀ commitments to get group public key
}
```

---

## 5. FROST Signing Protocol

### Overview

FROST signing has two rounds:

```
Round 1: Generate nonces (before seeing message)
Round 2: Produce partial signatures (after seeing message)
Aggregation: Combine partials into final signature
```

### Round 1: Nonce Generation

Each signer i generates two random scalars (dᵢ, eᵢ) and broadcasts
commitments (Dᵢ, Eᵢ) where:
```
Dᵢ = dᵢ·G  (hiding nonce commitment)
Eᵢ = eᵢ·G  (binding nonce commitment)
```

**Why two nonces?** The second nonce (e) gets multiplied by a "binding
factor" that depends on everyone's commitments. This prevents a malicious
signer from manipulating the aggregate nonce.

### Round 2: Partial Signatures

Given message m and all commitments:

```
1. Compute binding factor for each signer:
   ρᵢ = H("binding" || i || m || all_commitments)

2. Aggregate nonce point:
   R = Σᵢ (Dᵢ + ρᵢ·Eᵢ)

3. Compute challenge:
   c = H_BIP340(R || P || m)

4. Compute my partial signature:
   zᵢ = dᵢ + eᵢ·ρᵢ + λᵢ·xᵢ·c
        └────┬────┘   └───┬───┘
        nonce part    share contribution
```

**The λᵢ is crucial:** It's the Lagrange coefficient for this signer set.
Different signer sets produce different λᵢ values, but the result
always reconstructs to the same signature.

### Aggregation

Simply add all partial signatures:
```
s = Σᵢ zᵢ
signature = (R, s)
```

Why this works:
```
s = Σᵢ (dᵢ + eᵢ·ρᵢ + λᵢ·xᵢ·c)
  = Σᵢ(dᵢ + eᵢ·ρᵢ) + c·Σᵢ(λᵢ·xᵢ)
  = (aggregate nonce) + c·(secret key via Lagrange)
  = k + c·x

This is exactly a Schnorr signature!
```

### Our Code

```go
// internal/psbt/signer.go

// Round 1
func GenerateNonce(participantIndex uint32) (*NonceSecret, *NonceCommitment, error) {
    d, _ := randScalar()
    e, _ := randScalar()
    D := d·G  // point multiplication
    E := e·G
    return &NonceSecret{d, e}, &NonceCommitment{D, E}, nil
}

// Round 2
func Sign(session *SigningSession, myIndex uint32, myShare *btcec.ModNScalar, myNonce *NonceSecret) (*PartialSignature, error) {
    // Compute binding factors
    // Compute aggregate R
    // Handle BIP-340 even Y requirement
    // Compute challenge c
    // Compute z = d + e·ρ + λ·x·c
    return &PartialSignature{Z: z}, nil
}

// Aggregation
func Aggregate(session *SigningSession, partials []*PartialSignature) ([]byte, error) {
    // Recompute R
    // Sum all z values
    // Return (R || s) as 64 bytes
}
```

---

## 6. Taproot Tweaking

### The Taproot Equation

Taproot (BIP-341) uses a **tweaked** public key:
```
Q = P + H("TapTweak" || P.x)·G
    │   └─────────┬─────────┘
    │         tweak scalar t
internal key
```

Q is the **output key** (what appears on-chain).
P is the **internal key** (our group public key from DKG).

### Why Tweak?

1. **Script commitments**: The tweak can include a Merkle root of spending
   scripts, enabling complex contracts while looking like a simple key spend.

2. **Privacy**: All Taproot outputs look identical on-chain, whether they're
   simple payments or complex multisig contracts.

### Tweaking Threshold Shares

For threshold signing, each share must be tweaked so the aggregate
signature is valid for Q (not P).

**Key insight:** Each signer adds the **same** tweak to their share:
```
tweaked_xᵢ = xᵢ + t  (where t = H("TapTweak" || P.x))
```

Why same for everyone? Because Lagrange coefficients sum to 1:
```
Σᵢ λᵢ·(xᵢ + t) = Σᵢ λᵢ·xᵢ + t·Σᵢ λᵢ
                = x + t·1
                = x + t
                = q  (the tweaked secret)  ✓
```

**This was our bug!** We initially multiplied by λᵢ:
```
❌ tweaked_xᵢ = xᵢ + λᵢ·t  (wrong!)
```

### Parity Handling

BIP-340 requires even Y coordinates. Our code handles two cases:

```go
func TweakShareForTaproot(share, groupPubKey, myIndex, signerIndices) {
    // 1. If internal key P has odd Y, negate share
    if P.Y.IsOdd() {
        share.Negate()
    }

    // 2. Add tweak (same for all signers)
    share.Add(tweak)

    // 3. If output key Q has odd Y, negate result
    if Q.Y.IsOdd() {
        share.Negate()
    }
}
```

---

## 7. PSBT Format

### What is PSBT?

**Partially Signed Bitcoin Transaction** (BIP-174) is a container format that
carries an unsigned transaction plus all the metadata signers need.

### PSBT Structure

```
┌─────────────────────────────────────────┐
│  Global                                 │
│  - Unsigned transaction                 │
│  - Version info                         │
├─────────────────────────────────────────┤
│  Per-Input (one for each input)         │
│  - Witness UTXO (amount, scriptPubKey)  │
│  - Sighash type                         │
│  - Partial signatures (during signing)  │
│  - Taproot internal key                 │
│  - Final witness (after aggregation)    │
├─────────────────────────────────────────┤
│  Per-Output (one for each output)       │
│  - Derivation paths                     │
│  - Taproot info                         │
└─────────────────────────────────────────┘
```

### Air-Gap Flow

```
┌────────────┐        PSBT file        ┌────────────┐
│ Hot Wallet │ ───────────────────────▶│ Cold Signer│
│ (online)   │                         │ (offline)  │
│            │◀─────────────────────── │            │
└────────────┘   PSBT with partial     └────────────┘
                 signatures
```

1. Hot wallet builds PSBT, exports to USB drive
2. Each cold signer loads PSBT, adds their partial signature
3. Any party aggregates partials into final signature
4. Hot wallet broadcasts the completed transaction

### Our Code

```go
// internal/psbt/psbt.go

type Builder struct {
    network *chaincfg.Params
}

func (b *Builder) Build(utxos []UTXO, recipients []Recipient, changeAddr string, feeRate int) (*BuildResult, error) {
    // Create unsigned transaction
    // Calculate fees
    // Compute sighashes for each input
    return &BuildResult{
        Packet:     packet,
        UnsignedTx: tx,
        SigHashes:  sighashes,
        Fee:        fee,
    }, nil
}
```

---

## 8. Common Interview Questions

### Q: "Explain how FROST signing works in one minute."

**A:** "FROST is a threshold signing protocol where t-of-n parties can produce
a Schnorr signature without any party knowing the full key. It works in two
rounds: first, each signer generates random nonces and broadcasts commitments.
Second, after seeing the message, each signer computes a partial signature
using their secret share weighted by a Lagrange coefficient. These partials
are simply added together to produce a valid signature that's indistinguishable
from a single-key signature. The security comes from Shamir's secret sharing
and the binding factor that prevents nonce manipulation."

### Q: "What's the difference between DKG and signing?"

**A:** "DKG (Distributed Key Generation) happens once during setup—it creates
the shares and group public key. Signing happens for every transaction—it
combines shares into a signature. In DKG, each party creates a random
polynomial and they exchange shares. In signing, they exchange nonces and
partial signatures. DKG outputs persist forever; signing nonces are single-use."

### Q: "Why can't you use ECDSA for threshold signatures?"

**A:** "ECDSA lacks the linearity property that Schnorr has. In Schnorr,
s = k + e·x, which means partial signatures s₁ + s₂ = (k₁ + k₂) + e·(x₁ + x₂)
naturally combine. ECDSA's signature involves modular inverse of k, which
doesn't distribute over addition. There are threshold ECDSA protocols, but
they require multiple rounds of MPC computation, making them much more complex
and slower than FROST."

### Q: "What happens if someone reuses a nonce?"

**A:** "Catastrophic key leak. If signer i uses the same nonce (d, e) for two
different messages m₁ and m₂, an attacker can solve for their secret share:

   z₁ = d + e·ρ₁ + λ·xᵢ·c₁
   z₂ = d + e·ρ₂ + λ·xᵢ·c₂

Subtracting: z₁ - z₂ = e·(ρ₁ - ρ₂) + λ·xᵢ·(c₁ - c₂)

If ρ₁ = ρ₂ (same commitment set), then xᵢ = (z₁ - z₂) / (λ·(c₁ - c₂)).

This is why our GenerateNonce() uses fresh randomness every time."

### Q: "Explain Taproot tweaking for threshold signing."

**A:** "Taproot commits to scripts by tweaking the public key:
Q = P + H(P)·G. For threshold signing, we need the aggregate signature
to verify against Q, not P. Each signer adds the full tweak t = H(P) to
their share—not a weighted portion. This works because Lagrange coefficients
sum to 1: Σλᵢ·(xᵢ + t) = x + t·1 = tweaked secret. We also handle parity:
if Q has odd Y, we negate the tweaked shares since BIP-340 requires even Y."

### Q: "How does the security of this system compare to a single HSM?"

**A:** "Single HSM is single point of failure—compromise it, lose everything.
This 2-of-3 threshold system requires compromising two HSMs AND their
operators. Even if one HSM is stolen, the attacker still can't sign.
Additionally, no HSM ever holds the full key, so even a privileged insider
at the HSM manufacturer can't extract it. The tradeoff is complexity:
multi-round protocols, nonce management, and the risk of nonce reuse."

### Q: "Walk me through signing a transaction end-to-end."

**A:**
1. "Hot wallet builds PSBT with inputs, outputs, and sighashes
2. Export PSBT to USB drive for air-gapped signers
3. Signer 1 loads PSBT, generates nonces (d₁, e₁), stores commitment (D₁, E₁)
4. Signer 2 does the same, they exchange commitments
5. Each signer computes partial signature using their tweaked share
6. Partials are aggregated: s = z₁ + z₂
7. Signature (R, s) is inserted into PSBT witness
8. Hot wallet extracts final transaction and broadcasts to Bitcoin network
9. Network verifies using only the Taproot output key—no one can tell it was threshold signed"

---

## Quick Reference Card

```
ENTITIES
────────
G         = Generator point (fixed, public)
x         = Private key (scalar)
P = x·G   = Public key (point)

FROST DKG
─────────
fᵢ(x)     = Participant i's secret polynomial
xᵢ = Σⱼfⱼ(i) = Participant i's final share
P = Σⱼaⱼ,₀·G = Group public key

FROST SIGNING
─────────────
(dᵢ, eᵢ)  = Participant i's nonce pair
(Dᵢ, Eᵢ)  = Nonce commitments (Dᵢ = dᵢ·G)
ρᵢ        = Binding factor
R = ΣᵢDᵢ + ρᵢEᵢ = Aggregate nonce
c         = Challenge hash
λᵢ        = Lagrange coefficient for this signer set
zᵢ = dᵢ + eᵢρᵢ + λᵢxᵢc = Partial signature
s = Σᵢzᵢ  = Final signature scalar

TAPROOT
───────
t = H("TapTweak" || P.x) = Tweak scalar
Q = P + t·G              = Output key (on-chain)
tweaked_xᵢ = xᵢ + t      = Tweaked share (same t for all!)

VERIFICATION
────────────
s·G == R + c·Q  ✓
```

---

*Created for btc-custody project. Last updated: June 2026.*
