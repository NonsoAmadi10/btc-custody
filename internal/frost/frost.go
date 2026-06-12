// Package frost implements the Distributed Key Generation (DKG) phase of the
// FROST (Flexible Round-Optimized Schnorr Threshold) protocol.
//
// # Why FROST DKG
//
// In a traditional custody system one machine holds the full private key.
// That machine is the entire attack surface. FROST DKG solves this by
// ensuring the private key is NEVER assembled -- not at generation, not at
// signing. Each participant receives a mathematical share. Reconstructing the
// key requires at least t cooperating participants (the threshold).
//
// # Protocol overview
//
// The DKG uses Feldman Verifiable Secret Sharing (VSS) over the secp256k1
// scalar field:
// nolint: misspell
//
//	Round 1 (broadcast):
//	  Each participant i generates a random polynomial f_i(x) of degree t-1.
//	  The constant term a_i0 is their secret contribution to the group key.
//	  They publish Feldman commitments: C_ij = a_ij * G for j = 0..t-1.
//	  These commitments are public -- anyone can verify shares against them.
//
//	Round 2 (peer-to-peer, then local aggregation):
//	  Each participant i evaluates f_i(j) for every other participant j
//	  and sends that value secretly to j.
//	  Participant j verifies the received share against i's commitments:
//	    f_i(j)*G == sum(C_ik * j^k for k = 0..t-1)
//	  If verification passes, j aggregates their long-term secret share:
//	    x_j = sum(f_i(j) for all i)
//	  The group public key is:
//	    X = sum(C_i0 for all i)  (sum of all constant-term commitments)
//
// The result: every participant holds one share x_j. The group public key X
// is derived publicly. The group private key sum(a_i0) is mathematically
// implicit but never computed by anyone.
//
// Reference: https://eprint.iacr.org/2020/852.pdf (Komlo & Goldberg, 2020)
package frost

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
)

// ── Elliptic curve helpers ─────────────────────────────────────────────────
//
// All arithmetic is over the secp256k1 curve used by Bitcoin.
// Scalars are elements of Z_n (integers mod the group order n).
// Points are elements of the curve group.

// randScalar generates a cryptographically random non-zero scalar mod n.
func randScalar() (*btcec.ModNScalar, error) {
	for {
		var b [32]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, fmt.Errorf("frost: reading random bytes: %w", err)
		}
		s := new(btcec.ModNScalar)
		s.SetByteSlice(b[:])
		if !s.IsZero() {
			return s, nil
		}
		// Zero is astronomically unlikely but retry if it happens.
	}
}

// uint32ToScalar converts a small integer (participant index, exponent) to
// a scalar suitable for arithmetic in Z_n.
func uint32ToScalar(v uint32) *btcec.ModNScalar {
	var b [32]byte
	binary.BigEndian.PutUint32(b[28:], v)
	s := new(btcec.ModNScalar)
	s.SetByteSlice(b[:])
	return s
}

// scalarBasePoint computes s * G and returns the result as a JacobianPoint.
// G is the secp256k1 generator. This is how we turn a scalar into a public
// commitment without revealing the scalar.
func scalarBasePoint(s *btcec.ModNScalar) btcec.JacobianPoint {
	var result btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(s, &result)
	result.ToAffine()
	return result
}

// scalarMultPoint computes s * P for an arbitrary point P.
// Used when evaluating Feldman commitments: C_k * index^k.
func scalarMultPoint(s *btcec.ModNScalar, p *btcec.JacobianPoint) btcec.JacobianPoint {
	var result btcec.JacobianPoint
	btcec.ScalarMultNonConst(s, p, &result)
	result.ToAffine()
	return result
}

// addPoints computes P + Q on the curve.
func addPoints(p, q *btcec.JacobianPoint) btcec.JacobianPoint {
	var result btcec.JacobianPoint
	btcec.AddNonConst(p, q, &result)
	result.ToAffine()
	return result
}

// pointsEqual returns true if two affine JacobianPoints represent the same
// curve point (same x and y coordinate).
func pointsEqual(a, b *btcec.JacobianPoint) bool {
	a.ToAffine()
	b.ToAffine()
	return a.X.Equals(&b.X) && a.Y.Equals(&b.Y)
}

// jacobianToPubKey converts a JacobianPoint to a *btcec.PublicKey so it can
// be serialised and transmitted.
func jacobianToPubKey(p *btcec.JacobianPoint) (*btcec.PublicKey, error) {
	p.ToAffine()

	prefix := byte(0x02)
	if p.Y.IsOdd() {
		prefix = 0x03
	}

	xBytes := p.X.Bytes() // [32]byte, big-endian

	compressed := make([]byte, 33)
	compressed[0] = prefix
	copy(compressed[1:], xBytes[:])

	return btcec.ParsePubKey(compressed)
}

// ── Polynomial ─────────────────────────────────────────────────────────────
//
// A polynomial f(x) = a_0 + a_1*x + ... + a_(t-1)*x^(t-1) over Z_n.
// Each participant generates one such polynomial.
// The secret contribution to the group key is the constant term a_0.
// The degree is t-1 where t is the signing threshold.
//
// Why degree t-1? Because a polynomial of degree t-1 is uniquely determined
// by t points. This is Shamir's insight: if you have fewer than t shares
// (evaluations), you learn nothing about the secret; with exactly t shares
// you can reconstruct it via Lagrange interpolation.

type polynomial struct {
	// coefficients[0] is a_0 (the secret contribution)
	// coefficients[k] is a_k
	coefficients []*btcec.ModNScalar
}

// newRandomPolynomial generates a random polynomial of degree t-1.
// The returned polynomial's constant term is the participant's secret
// contribution to the group private key.
func newRandomPolynomial(threshold uint32) (*polynomial, error) {
	if threshold == 0 {
		return nil, fmt.Errorf("frost: threshold must be >= 1")
	}

	coeffs := make([]*btcec.ModNScalar, threshold)
	for i := range coeffs {
		s, err := randScalar()
		if err != nil {
			return nil, err
		}
		coeffs[i] = s
	}

	return &polynomial{coefficients: coeffs}, nil
}

// evaluate computes f(x) using Horner's method.
//
// Horner's method rewrites:
//
//	f(x) = a_0 + a_1*x + a_2*x^2 + ... + a_(t-1)*x^(t-1)
//
// as:
//
//	f(x) = a_0 + x*(a_1 + x*(a_2 + ... + x*a_(t-1)))
//
// This requires only t-1 multiplications and t-1 additions instead of the
// naive O(t^2) approach. More importantly, it avoids computing x^k directly,
// which matters when working in the scalar field.
func (p *polynomial) evaluate(x uint32) *btcec.ModNScalar {
	xScalar := uint32ToScalar(x)

	// Start from the highest-degree coefficient and work down.
	result := new(btcec.ModNScalar).Set(p.coefficients[len(p.coefficients)-1])

	for i := len(p.coefficients) - 2; i >= 0; i-- {
		// result = result * x + coefficients[i]
		result.Mul(xScalar)
		result.Add(p.coefficients[i])
	}

	return result
}

// feldmanCommitments returns the Feldman VSS commitments for this polynomial:
//
//	C_j = a_j * G  for j = 0 .. t-1
//
// These are public values. Publishing them allows any participant to verify
// that a received share is consistent with the polynomial, without learning
// the polynomial's coefficients.
func (p *polynomial) feldmanCommitments() []btcec.JacobianPoint {
	commits := make([]btcec.JacobianPoint, len(p.coefficients))
	for i, coeff := range p.coefficients {
		commits[i] = scalarBasePoint(coeff)
	}
	return commits
}

// ── Share verification ──────────────────────────────────────────────────────
//
// Given a share value s = f_i(j) and participant i's Feldman commitments,
// any participant j can verify the share without knowing the polynomial:
//
//   s * G == sum(C_ik * j^k for k = 0..t-1)
//
// Left side:  s * G is a point. We compute it.
// Right side: evaluating the "committed polynomial" at index j.
//
// If participant i sent an incorrect share, this check will fail.
// This is the security guarantee of Feldman VSS: dishonest participants
// are detected.

// verifyShare returns true if shareValue = f_i(recipientIndex) is consistent
// with the Feldman commitments published by the share's sender.
func verifyShare(
	shareValue *btcec.ModNScalar,
	commitments []btcec.JacobianPoint,
	recipientIndex uint32,
) bool {
	// LHS: shareValue * G
	lhs := scalarBasePoint(shareValue)

	// RHS: sum(C_k * index^k for k = 0..t-1)
	//
	// We compute index^k incrementally:
	//   start with xPow = 1 (= index^0)
	//   multiply by index on each iteration to get index^k
	xScalar := uint32ToScalar(recipientIndex)
	xPow := new(btcec.ModNScalar).SetInt(1) // x^0 = 1

	// Initialise rhs to the identity point (additive identity on the curve).
	var rhs btcec.JacobianPoint // zero value is the point at infinity

	for k := 0; k < len(commitments); k++ {
		// term = C_k * xPow  (= C_k * index^k)
		term := scalarMultPoint(xPow, &commitments[k])

		// rhs += term
		rhs = addPoints(&rhs, &term)

		// xPow = xPow * index  (advance to index^(k+1))
		xPow.Mul(xScalar)
	}

	return pointsEqual(&lhs, &rhs)
}

// ── Participant ─────────────────────────────────────────────────────────────

// Participant holds the mutable state for one DKG participant.
//
// Each participant is identified by a non-zero index (1..n). The index must
// be unique within the ceremony. Index 0 is reserved (it is the secret itself
// in Shamir's scheme -- revealing f(0) reveals the secret).
type Participant struct {
	Index     uint32 // unique identifier for this participant, >= 1
	Threshold uint32 // t: minimum participants required to sign
	Total     uint32 // n: total participants in the ceremony

	poly        *polynomial           // secret polynomial; never shared
	commitments []btcec.JacobianPoint // our own Feldman commitments (public)
}

// NewParticipant creates a participant and generates their secret polynomial.
//
// index:     unique 1-indexed identifier for this participant (1..n)
// threshold: t in t-of-n -- minimum participants required to sign
// total:     n -- total participants in the ceremony
func NewParticipant(index, threshold, total uint32) (*Participant, error) {
	if index == 0 {
		return nil, fmt.Errorf("frost: participant index must be >= 1 (index 0 is the secret)")
	}
	if index > total {
		return nil, fmt.Errorf("frost: participant index %d exceeds total %d", index, total)
	}
	if threshold == 0 || threshold > total {
		return nil, fmt.Errorf("frost: threshold %d invalid for total %d", threshold, total)
	}

	poly, err := newRandomPolynomial(threshold)
	if err != nil {
		return nil, fmt.Errorf("frost: participant %d polynomial generation: %w", index, err)
	}

	return &Participant{
		Index:       index,
		Threshold:   threshold,
		Total:       total,
		poly:        poly,
		commitments: poly.feldmanCommitments(),
	}, nil
}

// Round1Output is what each participant broadcasts to all others after Round 1.
// It contains only public information -- no secret material.
type Round1Output struct {
	ParticipantIndex uint32

	// Commitments are the Feldman VSS commitments for this participant's
	// polynomial: C_j = a_j * G for j = 0..t-1.
	//
	// Commitments[0] = a_0 * G is this participant's contribution to the
	// group public key.
	Commitments []btcec.JacobianPoint
}

// Round1 produces this participant's public broadcast for Round 1.
// Call this for every participant, then distribute all Round1Outputs to
// every other participant before proceeding to Round 2.
func (p *Participant) Round1() *Round1Output {
	return &Round1Output{
		ParticipantIndex: p.Index,
		Commitments:      p.commitments,
	}
}

// ShareFor computes the secret share that this participant must send
// (privately) to participant at peerIndex.
//
// This is f_i(peerIndex) -- evaluating our polynomial at the peer's index.
// The result must be transmitted confidentially (encrypted channel or
// direct physical handoff). It must NOT be broadcast.
func (p *Participant) ShareFor(peerIndex uint32) *btcec.ModNScalar {
	return p.poly.evaluate(peerIndex)
}

// ── DKG Round 2 / Finalise ──────────────────────────────────────────────────

// DKGResult is the output of a successful DKG ceremony for one participant.
type DKGResult struct {
	// GroupPublicKey is the group's combined public key.
	// All participants derive the same value from public information.
	// This is the Bitcoin address controlled by the threshold group.
	GroupPublicKey *btcec.PublicKey

	// SecretShare is this participant's long-term signing share x_i.
	// KEEP THIS SECRET. It must never leave this participant's machine.
	// It is the only secret output of the DKG.
	SecretShare *btcec.ModNScalar

	// VerificationShares maps each participant index to their public
	// verification key X_i = x_i * G.
	// Used during signing to verify partial signatures without revealing shares.
	VerificationShares map[uint32]*btcec.PublicKey

	Threshold       uint32
	NumParticipants uint32
}

// Finalise completes Round 2 for this participant.
//
// Parameters:
//
//	allRound1: the Round1Output broadcast by every participant (including self)
//	receivedShares: map[senderIndex] -> the share f_sender(p.Index) sent to us
//
// What this function does:
//  1. Verifies each received share against the sender's Feldman commitments.
//     A failed verification means the sender is behaving dishonestly.
//  2. Aggregates the long-term secret share: x_i = sum(f_j(i) for all j)
//  3. Derives the group public key: X = sum(C_j0 for all j)
//  4. Derives all verification shares: X_m = sum over j of (committed poly at m)
func (p *Participant) Finalise(
	allRound1 []*Round1Output,
	receivedShares map[uint32]*btcec.ModNScalar,
) (*DKGResult, error) {
	if len(allRound1) != int(p.Total) {
		return nil, fmt.Errorf(
			"frost: expected %d Round1 outputs, got %d",
			p.Total, len(allRound1),
		)
	}

	// Build an index of Round1 outputs for fast lookup by participant index.
	round1ByIndex := make(map[uint32]*Round1Output, len(allRound1))
	for _, r := range allRound1 {
		round1ByIndex[r.ParticipantIndex] = r
	}

	// ── Step 1: Verify each received share ──────────────────────────────
	//
	// For each peer j, verify that the share they sent us is consistent
	// with their published Feldman commitments.
	//
	// Check: f_j(i) * G == sum(C_jk * i^k for k = 0..t-1)
	//
	// If this fails, participant j is dishonest (they sent a share that
	// does not come from the polynomial they committed to).
	for fromIndex, share := range receivedShares {
		r1, ok := round1ByIndex[fromIndex]
		if !ok {
			return nil, fmt.Errorf(
				"frost: received share from participant %d but no Round1 output",
				fromIndex,
			)
		}

		if !verifyShare(share, r1.Commitments, p.Index) {
			return nil, fmt.Errorf(
				"frost: share from participant %d failed Feldman VSS verification "+
					"-- participant %d is behaving dishonestly",
				fromIndex, fromIndex,
			)
		}
	}

	// ── Step 2: Aggregate the long-term secret share ────────────────────
	//
	// x_i = sum(f_j(i) for all j)
	//
	// This is our permanent signing share. The sum of everyone's polynomial
	// evaluated at our index. No single participant (including us) knows the
	// other participants' polynomial coefficients, so none of us can derive
	// the group secret a_0 = sum(a_j0 for all j) from our share alone.
	secretShare := new(btcec.ModNScalar).SetInt(0)

	for _, share := range receivedShares {
		secretShare.Add(share)
	}

	// ── Step 3: Derive the group public key ─────────────────────────────
	//
	// X = sum(C_j0 for all j)
	//
	// C_j0 = a_j0 * G is the first Feldman commitment from each participant --
	// their contribution to the group key in elliptic curve form.
	// The sum is a_0 * G where a_0 = sum(a_j0) is the group secret,
	// but we never compute a_0 -- only its curve point.
	var groupPoint btcec.JacobianPoint // identity (point at infinity)

	for _, r1 := range allRound1 {
		c0 := r1.Commitments[0]
		groupPoint = addPoints(&groupPoint, &c0)
	}

	groupPubKey, err := jacobianToPubKey(&groupPoint)
	if err != nil {
		return nil, fmt.Errorf("frost: deriving group public key: %w", err)
	}

	// ── Step 4: Derive all verification shares ───────────────────────────
	//
	// Verification share for participant m:
	//   X_m = sum over all j of (evaluate committed polynomial of j at m)
	//       = x_m * G   (where x_m is participant m's secret share)
	//
	// This lets any participant verify a partial signature from m during
	// signing without knowing m's secret share.
	verificationShares := make(map[uint32]*btcec.PublicKey, p.Total)

	for m := uint32(1); m <= p.Total; m++ {
		xScalar := uint32ToScalar(m)
		xPow := new(btcec.ModNScalar).SetInt(1) // x^0

		var vmPoint btcec.JacobianPoint // X_m, starts at identity

		for _, r1 := range allRound1 {
			// Evaluate participant r1's committed polynomial at index m:
			//   sum(C_jk * m^k for k = 0..t-1)
			var contribution btcec.JacobianPoint

			xPowForThisJ := new(btcec.ModNScalar).SetInt(1) // reset for each j

			for k := 0; k < len(r1.Commitments); k++ {
				ck := r1.Commitments[k]
				term := scalarMultPoint(xPowForThisJ, &ck)
				contribution = addPoints(&contribution, &term)
				xPowForThisJ.Mul(xScalar)
			}

			vmPoint = addPoints(&vmPoint, &contribution)
		}

		_ = xPow // used only to establish the pattern; actual powers above

		vpk, err := jacobianToPubKey(&vmPoint)
		if err != nil {
			return nil, fmt.Errorf("frost: deriving verification share for participant %d: %w", m, err)
		}
		verificationShares[m] = vpk
	}

	return &DKGResult{
		GroupPublicKey:     groupPubKey,
		SecretShare:        secretShare,
		VerificationShares: verificationShares,
		Threshold:          p.Threshold,
		NumParticipants:    p.Total,
	}, nil
}
