# FROST DKG -- The Mathematics

This document explains the mathematics behind the FROST Distributed Key
Generation protocol implemented in `internal/frost/frost.go`. Every concept
is built from first principles using small concrete numbers before scaling
to the 256-bit secp256k1 arithmetic Bitcoin uses.

---

## The problem we are solving

A traditional custody system has one machine that holds the complete private
key. That machine is the entire attack surface. If it is compromised, all
funds are gone.

We want a system where the private key is **never assembled anywhere** -- not
at generation, not at signing. We want any t of n participants to be able to
produce a valid signature, without any single participant (or any coalition
smaller than t) ever seeing the full key.

The mathematics that makes this possible is Shamir's Secret Sharing (1979),
extended with Feldman's verifiable commitments (1987), and finally assembled
into the FROST DKG protocol (Komlo & Goldberg, 2020).

---

## Part 1: Shamir's Secret Sharing

### Why a polynomial?

A straight line is defined by exactly **2 points**. Given any 2 points, there
is exactly one line through them. Given only 1 point, infinitely many lines
pass through it -- you learn nothing about which one you are dealing with.

A parabola (degree-2 polynomial) is defined by exactly **3 points**. A cubic
by **4**. The pattern:

```
A polynomial of degree t-1 is uniquely determined by exactly t points.
Fewer than t points: the polynomial could be anything.
```

This is the key insight Shamir used. To split a secret with a t-of-n
threshold, encode the secret as the constant term of a random degree-(t-1)
polynomial, then give each of n participants one evaluation of that polynomial.

### A concrete example

Secret = **5**, threshold t = 2, participants n = 3.

We work in a finite field -- all arithmetic modulo a prime p. We use **p = 17**
here because the numbers are small enough to follow by hand. In the real
implementation, p is the secp256k1 group order: a 256-bit prime.

Choose a random degree-1 polynomial (a line):

```
f(x) = 5 + 3x   (mod 17)
         ^   ^
         |   random coefficient
         the secret
```

Compute the three shares by evaluating at x = 1, 2, 3:

```
f(1) = 5 + 3·1 = 8     → share for participant 1
f(2) = 5 + 3·2 = 11    → share for participant 2
f(3) = 5 + 3·3 = 14    → share for participant 3
```

The secret lives at **f(0) = 5**. Nobody evaluates at x = 0 during the share
distribution phase -- that would hand out the secret directly.

### Reconstruction: Lagrange interpolation

Participants 1 and 2 want to reconstruct the secret. They hold points (1, 8)
and (2, 11). They want f(0).

Lagrange interpolation finds the unique polynomial through t points and
evaluates it at any chosen x. At x = 0 it reveals the secret:

```
f(0) = y₁ · L₁(0) + y₂ · L₂(0)

Lagrange basis polynomials evaluated at 0:
  L₁(0) = (0 - x₂) / (x₁ - x₂) = (0 - 2) / (1 - 2) = -2 / -1 = 2
  L₂(0) = (0 - x₁) / (x₂ - x₁) = (0 - 1) / (2 - 1) = -1 /  1 = -1

f(0) = 8 · 2  +  11 · (-1)
     = 16 - 11
     = 5   ✓
```

The coefficients λ₁ = 2 and λ₂ = -1 are the **Lagrange coefficients**. They
appear in the FROST signing formula as `λᵢ` -- the "weight" each participant's
partial signature contributes to the aggregate.

### Why one share reveals nothing

Participant 1 holds (1, 8). Only one point. Infinitely many lines pass through
(1, 8). The secret could be 0, 1, 2, 3, ..., 16 -- every value in the field
is equally consistent with this single point. One share is zero information.

This is not just intuition -- it is a mathematical proof. Shamir showed that
with fewer than t shares, the secret is information-theoretically hidden: no
amount of computation can help.

---

## Part 2: Feldman VSS -- Verifiable Shares

Shamir's scheme has a problem for distributed systems: how do you know a
participant sent you the correct share? A malicious participant could send a
random number and you would have no way to detect it.

Feldman (1987) solved this by publishing **commitments** to the polynomial
coefficients. The commitments use elliptic curve multiplication.

### The discrete logarithm one-way function

In Bitcoin's secp256k1 elliptic curve:

```
Given scalar s, computing s · G is easy.    (milliseconds)
Given point P = s · G, finding s is hard.   (computationally infeasible)
```

`G` is the generator point -- a specific point on the curve agreed upon by
everyone. Multiplying a scalar by G maps a secret number to a public point
in a way that cannot be reversed. This one-way function is what secures all
of Bitcoin.

### Feldman commitments

For polynomial `f(x) = a₀ + a₁x` with threshold t = 2, publish:

```
C₀ = a₀ · G     (commitment to the secret contribution)
C₁ = a₁ · G     (commitment to the linear coefficient)
```

These are public -- anyone can see them. But they do not reveal a₀ or a₁
because reversing the multiplication is computationally infeasible.

### Share verification

If a participant sends you share `s = f(j) = a₀ + a₁·j`, you can verify it
**without knowing a₀ or a₁**:

```
s · G = (a₀ + a₁·j) · G
      = a₀·G + a₁·j·G       (linearity of scalar multiplication)
      = C₀   + j · C₁        (substituting the commitments)

Verification check: s·G == C₀ + j·C₁
```

If the sender lied and sent a wrong value, this check fails. They cannot
forge a share that passes without knowing the discrete logarithm of C₀
(which means breaking secp256k1 -- not possible with current or near-future
computing).

This is exactly `verifyShare()` in the code:

```go
// LHS: shareValue * G
lhs := scalarBasePoint(shareValue)

// RHS: C₀ + j·C₁ + j²·C₂ + ...  (evaluated committed polynomial)
for k := 0; k < len(commitments); k++ {
    term := scalarMultPoint(xPowForThisJ, &commitments[k])
    rhs  = addPoints(&rhs, &term)
    xPow.Mul(xScalar)
}

return pointsEqual(&lhs, &rhs)
```

---

## Part 3: The FROST DKG -- No Trusted Dealer

Shamir and Feldman still have a problem: one person generates the polynomial
and distributes shares. That person knows the secret. In a custody system,
there can be no trusted dealer -- any single person who knows the group secret
is a catastrophic single point of failure.

FROST DKG (and Pedersen DKG before it) solves this: **every participant
generates their own polynomial, and the group secret is the sum of all
constant terms -- a value nobody individually chose or knows.**

### Everyone generates a polynomial

With 3 participants A, B, C (threshold t = 2), each generates their own
random line:

```
f_A(x) = a_A0 + a_A1·x      (A's polynomial, only A knows this)
f_B(x) = a_B0 + a_B1·x      (B's polynomial, only B knows this)
f_C(x) = a_C0 + a_C1·x      (C's polynomial, only C knows this)
```

### The combined polynomial

Define the combined polynomial as their sum:

```
F(x) = f_A(x) + f_B(x) + f_C(x)
     = (a_A0 + a_B0 + a_C0)  +  (a_A1 + a_B1 + a_C1)·x
```

The **group secret** is:

```
F(0) = a_A0 + a_B0 + a_C0
```

Nobody chose this number. A chose a_A0, B chose a_B0, C chose a_C0. The
group secret is their sum -- a value that emerges from the ceremony and is
never computed by any participant.

### Long-term shares are evaluations of F

Each participant receives shares from all others and sums them:

```
Participant 1's long-term share:
  x₁ = f_A(1) + f_B(1) + f_C(1) = F(1)

Participant 2's long-term share:
  x₂ = f_A(2) + f_B(2) + f_C(2) = F(2)

Participant 3's long-term share:
  x₃ = f_A(3) + f_B(3) + f_C(3) = F(3)
```

These are evaluations of the **combined** polynomial F. Any 2 of the 3
participants can run Lagrange interpolation to find F(0) -- but in FROST
signing, they never do that. Instead they use the Lagrange coefficients
directly to aggregate partial signatures without reconstructing the secret.

In the code:

```go
// x_i = sum(f_j(i) for all j)
secretShare := new(btcec.ModNScalar).SetInt(0)
for _, share := range receivedShares {
    secretShare.Add(share)
}
```

### The group public key

The group public key is the curve point corresponding to the group secret:

```
X = F(0) · G = (a_A0 + a_B0 + a_C0) · G
             = a_A0·G  +  a_B0·G  +  a_C0·G
             = C_A0    +  C_B0    +  C_C0
```

It is the **sum of all participants' first Feldman commitments**. This is
computable from public information -- no secret knowledge required:

```go
var groupPoint btcec.JacobianPoint
for _, r1 := range allRound1 {
    c0 := r1.Commitments[0]
    groupPoint = addPoints(&groupPoint, &c0)
}
```

The group private key F(0) is never computed. It exists only as the elliptic
curve point `X = F(0)·G`. This is the Bitcoin address that the threshold
group controls.

### What the tests proved

The test output `participant 1: x_i * G == X_i ✓` verified:

```
x₁ · G  ==  X₁

where X₁ = sum over all j of (evaluate j's committed polynomial at index 1)
```

Left side: we computed participant 1's secret share x₁ (known only to
participant 1) and multiplied by G.

Right side: we evaluated the committed polynomials from public Round 1
outputs.

They are equal. This proves:
1. The Feldman VSS verification is working correctly.
2. Our polynomial evaluation and point arithmetic is correct.
3. The share aggregation matches the committed polynomial sum.

---

## Part 4: Horner's Method -- Polynomial Evaluation

The code uses Horner's method to evaluate polynomials efficiently:

```go
result := coefficients[last]
for i := last-1; i >= 0; i-- {
    result.Mul(xScalar)          // result = result * x
    result.Add(coefficients[i]) // result = result*x + a_i
}
```

This rewrites `a₀ + a₁x + a₂x²` as `a₀ + x(a₁ + x·a₂)`.

Naive evaluation would compute x¹, x², x³... separately, requiring
multiplications that grow with degree. Horner requires exactly t-1
multiplications and t-1 additions regardless of degree. In the 256-bit
scalar field of secp256k1, each multiplication is non-trivial, so this
matters.

---

## Summary: the full picture in four equations

```
Group public key:     X = sum(a_i0) · G         never compute the scalar, only the point
Participant j share:  x_j = sum(f_i(j))          sum of polynomial evaluations at j
Verification:         x_j · G = X_j              proved by the test output ✓
Lagrange:             F(0) = sum(λ_j · x_j)       used implicitly in FROST signing
```

The security of the entire system rests on one fact: given `X = s·G`,
finding `s` requires solving the discrete logarithm problem on secp256k1.
Bitcoin has staked trillions of dollars on that being computationally
infeasible with any known or near-future algorithm.

---

## Further reading

- Shamir, A. (1979). How to Share a Secret. *Communications of the ACM*.
- Feldman, P. (1987). A Practical Scheme for Non-interactive Verifiable Secret Sharing. *FOCS*.
- Pedersen, T. (1991). Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing. *CRYPTO*.
- Komlo, C. & Goldberg, I. (2020). FROST: Flexible Round-Optimized Schnorr Threshold Signatures. [https://eprint.iacr.org/2020/852.pdf](https://eprint.iacr.org/2020/852.pdf)
- Boneh, D. & Shoup, V. A Graduate Course in Applied Cryptography. [https://toc.cryptobook.us](https://toc.cryptobook.us) -- Chapter 11 covers secret sharing in depth.
