// Package psbt - signer.go implements FROST threshold signing for PSBTs.
//
// # FROST Signing Protocol (2 rounds)
//
// This implements the signing half of FROST (the DKG was in internal/frost).
// Each threshold participant produces a partial signature; t partials combine
// into one valid Schnorr signature indistinguishable from a single-key spend.
//
// Round 1 — Nonce commitment (before seeing the message):
//
//	Each signer i generates random nonce scalars (d_i, e_i).
//	Computes commitment points (D_i = d_i·G, E_i = e_i·G).
//	Broadcasts (D_i, E_i) to all other signers.
//
// Round 2 — Partial signature (after receiving all commitments + sighash):
//
//	Aggregate nonce commitment:
//	  R = sum(D_i + ρ_i·E_i)  where ρ_i = H(i, msg, {D,E})
//
//	Challenge:
//	  c = H_BIP340(R || P || msg)
//
//	Partial signature:
//	  z_i = d_i + e_i·ρ_i + λ_i·x_i·c
//	        └─────────────┘   └───────┘
//	         nonce binding    share contribution
//
// Final aggregation:
//
//	z = sum(z_i)  (just scalar addition)
//	sig = (R, z)  — a valid BIP-340 Schnorr signature
//
// Reference: https://eprint.iacr.org/2020/852.pdf (Komlo & Goldberg, 2020)
package psbt

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// ── Nonce Generation (Round 1) ──────────────────────────────────────────────

// NonceCommitment is a signer's Round 1 output: commitments to their nonces.
type NonceCommitment struct {
	// ParticipantIndex identifies which signer this is (1-indexed).
	ParticipantIndex uint32

	// D is the commitment to the hiding nonce: D = d·G
	D *btcec.PublicKey

	// E is the commitment to the binding nonce: E = e·G
	E *btcec.PublicKey
}

// NonceSecret holds the secret nonces that must never be shared.
// These are single-use: a new pair must be generated for every signing session.
type NonceSecret struct {
	// d is the hiding nonce scalar.
	d *btcec.ModNScalar

	// e is the binding nonce scalar.
	e *btcec.ModNScalar
}

// GenerateNonce produces a fresh nonce pair for a signing session.
// Returns both the secret (kept private) and the commitment (broadcast).
//
// CRITICAL: Nonces are single-use. Reusing a nonce across two signatures
// with different messages reveals the secret share -- catastrophic key leak.
func GenerateNonce(participantIndex uint32) (*NonceSecret, *NonceCommitment, error) {
	d, err := randScalar()
	if err != nil {
		return nil, nil, fmt.Errorf("frost: generating hiding nonce: %w", err)
	}

	e, err := randScalar()
	if err != nil {
		return nil, nil, fmt.Errorf("frost: generating binding nonce: %w", err)
	}

	// D = d·G, E = e·G
	var dPoint, ePoint btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(d, &dPoint)
	btcec.ScalarBaseMultNonConst(e, &ePoint)
	dPoint.ToAffine()
	ePoint.ToAffine()

	D, err := jacobianToPubKey(&dPoint)
	if err != nil {
		return nil, nil, err
	}

	E, err := jacobianToPubKey(&ePoint)
	if err != nil {
		return nil, nil, err
	}

	return &NonceSecret{d: d, e: e},
		&NonceCommitment{ParticipantIndex: participantIndex, D: D, E: E},
		nil
}

// ── Partial Signature (Round 2) ─────────────────────────────────────────────

// PartialSignature is one signer's contribution to the threshold signature.
type PartialSignature struct {
	// ParticipantIndex identifies which signer produced this.
	ParticipantIndex uint32

	// Z is the partial signature scalar z_i.
	Z *btcec.ModNScalar
}

// SigningSession holds all the data needed for Round 2.
type SigningSession struct {
	// Message is the sighash being signed.
	Message []byte

	// GroupPublicKey is the aggregate key from DKG (the Bitcoin address key).
	GroupPublicKey *btcec.PublicKey

	// AllCommitments contains Round 1 output from all participating signers.
	AllCommitments []*NonceCommitment

	// SignerIndices lists which participants are signing (must be >= threshold).
	SignerIndices []uint32
}

// Sign produces a partial signature for the given signer.
//
// Parameters:
//   - session: the signing session with all commitments and the message
//   - myIndex: this signer's participant index
//   - myShare: this signer's secret share from DKG (x_i)
//   - myNonce: the secret nonce generated in Round 1
//
// Returns the partial signature z_i that will be aggregated with others.
func Sign(
	session *SigningSession,
	myIndex uint32,
	myShare *btcec.ModNScalar,
	myNonce *NonceSecret,
) (*PartialSignature, error) {
	// Validate this signer is in the session.
	found := false
	for _, idx := range session.SignerIndices {
		if idx == myIndex {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("frost: signer %d not in session", myIndex)
	}

	// Find our commitment.
	var myCommitment *NonceCommitment
	for _, c := range session.AllCommitments {
		if c.ParticipantIndex == myIndex {
			myCommitment = c
			break
		}
	}
	if myCommitment == nil {
		return nil, fmt.Errorf("frost: no commitment for signer %d", myIndex)
	}

	// Sort commitments by index for deterministic aggregation.
	sortedCommits := make([]*NonceCommitment, len(session.AllCommitments))
	copy(sortedCommits, session.AllCommitments)
	sort.Slice(sortedCommits, func(i, j int) bool {
		return sortedCommits[i].ParticipantIndex < sortedCommits[j].ParticipantIndex
	})

	// Compute binding factors ρ_i for each signer.
	// ρ_i = H("FROST-binding" || i || msg || {D_j, E_j for all j})
	bindingFactors := make(map[uint32]*btcec.ModNScalar)
	for _, c := range sortedCommits {
		rho := computeBindingFactor(c.ParticipantIndex, session.Message, sortedCommits)
		bindingFactors[c.ParticipantIndex] = rho
	}

	// Compute aggregate nonce R = sum(D_i + ρ_i·E_i)
	var R btcec.JacobianPoint
	for _, c := range sortedCommits {
		rho := bindingFactors[c.ParticipantIndex]

		// D_i as Jacobian
		var Di btcec.JacobianPoint
		c.D.AsJacobian(&Di)

		// ρ_i·E_i
		var Ei btcec.JacobianPoint
		c.E.AsJacobian(&Ei)
		var rhoEi btcec.JacobianPoint
		btcec.ScalarMultNonConst(rho, &Ei, &rhoEi)

		// R += D_i + ρ_i·E_i
		var term btcec.JacobianPoint
		btcec.AddNonConst(&Di, &rhoEi, &term)
		btcec.AddNonConst(&R, &term, &R)
	}
	R.ToAffine()

	// If R has odd y, negate all nonces (BIP-340 requires even y).
	negateNonces := R.Y.IsOdd()
	if negateNonces {
		R.Y.Negate(1)
		R.Y.Normalize()
	}

	// Compute Lagrange coefficient λ_i for this signer.
	lambda := lagrangeCoefficient(myIndex, session.SignerIndices)

	// Compute challenge c = H_BIP340(R || P || msg)
	c := computeChallenge(&R, session.GroupPublicKey, session.Message)

	// Partial signature: z_i = d_i + e_i·ρ_i + λ_i·x_i·c
	myRho := bindingFactors[myIndex]

	// Start with d_i
	z := new(btcec.ModNScalar).Set(myNonce.d)

	// If we negated R, negate nonces too
	if negateNonces {
		z.Negate()
	}

	// + e_i·ρ_i
	eRho := new(btcec.ModNScalar).Mul2(myNonce.e, myRho)
	if negateNonces {
		eRho.Negate()
	}
	z.Add(eRho)

	// + λ_i·x_i·c
	lambdaXC := new(btcec.ModNScalar).Mul2(lambda, myShare)
	lambdaXC.Mul(c)
	z.Add(lambdaXC)

	return &PartialSignature{
		ParticipantIndex: myIndex,
		Z:                z,
	}, nil
}

// ── Signature Aggregation ───────────────────────────────────────────────────

// Aggregate combines t partial signatures into a final Schnorr signature.
//
// Parameters:
//   - session: the signing session (same one used for Sign)
//   - partials: the partial signatures from t signers
//
// Returns a 64-byte BIP-340 Schnorr signature (R || s).
func Aggregate(session *SigningSession, partials []*PartialSignature) ([]byte, error) {
	if len(partials) == 0 {
		return nil, fmt.Errorf("frost: no partial signatures")
	}

	// Sort commitments for deterministic R computation.
	sortedCommits := make([]*NonceCommitment, len(session.AllCommitments))
	copy(sortedCommits, session.AllCommitments)
	sort.Slice(sortedCommits, func(i, j int) bool {
		return sortedCommits[i].ParticipantIndex < sortedCommits[j].ParticipantIndex
	})

	// Recompute binding factors.
	bindingFactors := make(map[uint32]*btcec.ModNScalar)
	for _, c := range sortedCommits {
		rho := computeBindingFactor(c.ParticipantIndex, session.Message, sortedCommits)
		bindingFactors[c.ParticipantIndex] = rho
	}

	// Recompute R = sum(D_i + ρ_i·E_i)
	var R btcec.JacobianPoint
	for _, c := range sortedCommits {
		rho := bindingFactors[c.ParticipantIndex]

		var Di btcec.JacobianPoint
		c.D.AsJacobian(&Di)

		var Ei btcec.JacobianPoint
		c.E.AsJacobian(&Ei)
		var rhoEi btcec.JacobianPoint
		btcec.ScalarMultNonConst(rho, &Ei, &rhoEi)

		var term btcec.JacobianPoint
		btcec.AddNonConst(&Di, &rhoEi, &term)
		btcec.AddNonConst(&R, &term, &R)
	}
	R.ToAffine()

	// Negate if odd y.
	if R.Y.IsOdd() {
		R.Y.Negate(1)
		R.Y.Normalize()
	}

	// Aggregate s = sum(z_i)
	s := new(btcec.ModNScalar).SetInt(0)
	for _, p := range partials {
		s.Add(p.Z)
	}

	// Serialize: R (32 bytes x-only) || s (32 bytes)
	sig := make([]byte, 64)

	rBytes := R.X.Bytes()
	copy(sig[0:32], rBytes[:])

	sBytes := s.Bytes()
	copy(sig[32:64], sBytes[:])

	return sig, nil
}

// ── Helper Functions ────────────────────────────────────────────────────────

// randScalar generates a cryptographically random non-zero scalar.
func randScalar() (*btcec.ModNScalar, error) {
	for {
		var b [32]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		s := new(btcec.ModNScalar)
		s.SetByteSlice(b[:])
		if !s.IsZero() {
			return s, nil
		}
	}
}

// jacobianToPubKey converts a JacobianPoint to a PublicKey.
func jacobianToPubKey(p *btcec.JacobianPoint) (*btcec.PublicKey, error) {
	p.ToAffine()

	prefix := byte(0x02)
	if p.Y.IsOdd() {
		prefix = 0x03
	}

	xBytes := p.X.Bytes()
	compressed := make([]byte, 33)
	compressed[0] = prefix
	copy(compressed[1:], xBytes[:])

	return btcec.ParsePubKey(compressed)
}

// computeBindingFactor computes ρ_i = H("binding" || i || msg || commitments).
func computeBindingFactor(
	index uint32,
	message []byte,
	commitments []*NonceCommitment,
) *btcec.ModNScalar {
	h := sha256.New()
	h.Write([]byte("FROST-binding"))

	var idxBuf [4]byte
	binary.BigEndian.PutUint32(idxBuf[:], index)
	h.Write(idxBuf[:])

	h.Write(message)

	for _, c := range commitments {
		h.Write(schnorr.SerializePubKey(c.D))
		h.Write(schnorr.SerializePubKey(c.E))
	}

	digest := h.Sum(nil)
	rho := new(btcec.ModNScalar)
	rho.SetByteSlice(digest)
	return rho
}

// computeChallenge computes c = H_BIP340(R || P || msg).
// This is the standard Schnorr challenge hash used by Bitcoin.
func computeChallenge(R *btcec.JacobianPoint, P *btcec.PublicKey, msg []byte) *btcec.ModNScalar {
	// BIP-340 uses tagged hash: SHA256(SHA256("BIP0340/challenge") || SHA256("BIP0340/challenge") || data)
	// txscript has a helper but we'll compute it directly for clarity.

	// Precomputed tag hash for "BIP0340/challenge"
	tagHash := sha256.Sum256([]byte("BIP0340/challenge"))

	h := sha256.New()
	h.Write(tagHash[:])
	h.Write(tagHash[:])

	// R x-coordinate (32 bytes)
	rBytes := R.X.Bytes()
	h.Write(rBytes[:])

	// P x-coordinate (32 bytes)
	pBytes := schnorr.SerializePubKey(P)
	h.Write(pBytes)

	// Message
	h.Write(msg)

	digest := h.Sum(nil)
	c := new(btcec.ModNScalar)
	c.SetByteSlice(digest)
	return c
}

// lagrangeCoefficient computes λ_i for participant i given the set of signers.
//
// λ_i = product over j≠i of (0 - j) / (i - j)
//
//	= product over j≠i of j / (j - i)
//
// This determines each signer's "weight" in the final signature.
// It's the same Lagrange interpolation used in Shamir, but evaluated at x=0.
func lagrangeCoefficient(i uint32, signers []uint32) *btcec.ModNScalar {
	lambda := new(btcec.ModNScalar).SetInt(1)

	iScalar := uint32ToScalar(i)

	for _, j := range signers {
		if j == i {
			continue
		}

		jScalar := uint32ToScalar(j)

		// numerator = j
		num := new(btcec.ModNScalar).Set(jScalar)

		// denominator = j - i
		denom := new(btcec.ModNScalar).Set(jScalar)
		denom.Add(new(btcec.ModNScalar).NegateVal(iScalar))

		// lambda *= num / denom = num * denom^(-1)
		denomInv := new(btcec.ModNScalar).InverseValNonConst(denom)
		term := new(btcec.ModNScalar).Mul2(num, denomInv)

		lambda.Mul(term)
	}

	return lambda
}

// uint32ToScalar converts an integer to a scalar for arithmetic.
func uint32ToScalar(v uint32) *btcec.ModNScalar {
	var b [32]byte
	binary.BigEndian.PutUint32(b[28:], v)
	s := new(btcec.ModNScalar)
	s.SetByteSlice(b[:])
	return s
}

// ── Integration with PSBT ───────────────────────────────────────────────────

// SignInput adds a partial signature to the PSBT for the given input.
func (p *Packet) SignInput(inputIndex int, partial *PartialSignature) error {
	if inputIndex < 0 || inputIndex >= len(p.Inputs) {
		return fmt.Errorf("psbt: input index %d out of range", inputIndex)
	}

	if p.Inputs[inputIndex].PartialSigs == nil {
		p.Inputs[inputIndex].PartialSigs = make(map[uint32][]byte)
	}

	zBytes := partial.Z.Bytes()
	p.Inputs[inputIndex].PartialSigs[partial.ParticipantIndex] = zBytes[:]

	return nil
}

// FinalizeInput aggregates partial signatures for an input and sets the final sig.
func (p *Packet) FinalizeInput(inputIndex int, session *SigningSession) error {
	if inputIndex < 0 || inputIndex >= len(p.Inputs) {
		return fmt.Errorf("psbt: input index %d out of range", inputIndex)
	}

	input := &p.Inputs[inputIndex]

	// Convert stored partial sigs back to PartialSignature structs.
	var partials []*PartialSignature
	for idx, zBytes := range input.PartialSigs {
		z := new(btcec.ModNScalar)
		z.SetByteSlice(zBytes)
		partials = append(partials, &PartialSignature{
			ParticipantIndex: idx,
			Z:                z,
		})
	}

	// Aggregate into final signature.
	sig, err := Aggregate(session, partials)
	if err != nil {
		return fmt.Errorf("psbt: aggregate input %d: %w", inputIndex, err)
	}

	// Verify the signature before accepting it.
	if !verifySchnorr(session.GroupPublicKey, session.Message, sig) {
		return fmt.Errorf("psbt: aggregated signature verification failed for input %d", inputIndex)
	}

	input.TaprootKeySpendSig = sig
	return nil
}

// verifySchnorr verifies a BIP-340 Schnorr signature.
func verifySchnorr(pubKey *btcec.PublicKey, msg, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}

	signature, err := schnorr.ParseSignature(sig)
	if err != nil {
		return false
	}

	return signature.Verify(msg, pubKey)
}

// TweakShareForTaproot adjusts a DKG secret share for Taproot key-path signing.
//
// Taproot uses a tweaked key: Q = P + H(P)·G
// The corresponding tweaked secret is: q = p + H(P)
//
// For threshold signing, each share x_i must be tweaked:
//
//	tweaked_x_i = x_i + H(P)
//
// where H(P) is the taproot tweak. This ensures:
//
//	sum(λ_i · tweaked_x_i) = sum(λ_i · x_i) + sum(λ_i) · H(P) = p + H(P) = q
//
// (since sum(λ_i) = 1 by Lagrange interpolation properties)
//
// Additionally, BIP-340 requires keys to have even Y. If the internal key P
// has odd Y, we must negate the share. If the output key Q has odd Y,
// we must negate the result.
func TweakShareForTaproot(
	share *btcec.ModNScalar,
	groupPubKey *btcec.PublicKey,
	myIndex uint32,
	signerIndices []uint32,
) *btcec.ModNScalar {
	// Start with the share, potentially negating for internal key parity
	adjustedShare := new(btcec.ModNScalar).Set(share)

	// BIP-340: if internal key has odd Y, negate the private key
	internalKeyBytes := groupPubKey.SerializeCompressed()
	if internalKeyBytes[0] == 0x03 { // odd Y
		adjustedShare.Negate()
	}

	// Compute taproot tweak: H_TapTweak(P)
	// For key-path only (no merkle root), tweak = TaggedHash("TapTweak", P.x)
	xOnlyKey := schnorr.SerializePubKey(groupPubKey)

	// BIP-341 tagged hash
	tagHash := sha256.Sum256([]byte("TapTweak"))
	h := sha256.New()
	h.Write(tagHash[:])
	h.Write(tagHash[:])
	h.Write(xOnlyKey)
	tweakHash := h.Sum(nil)

	tweakScalar := new(btcec.ModNScalar)
	tweakScalar.SetByteSlice(tweakHash)

	// tweaked_share = adjusted_share + tweak (same tweak for ALL signers!)
	result := new(btcec.ModNScalar).Set(adjustedShare)
	result.Add(tweakScalar)

	// Check if output key Q = P + t*G has odd Y; if so, negate result
	// We compute this by adding t*G to P
	var tweakPoint, internalPoint, outputPoint btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(tweakScalar, &tweakPoint)
	groupPubKey.AsJacobian(&internalPoint)

	// Handle internal key parity for output computation
	if internalKeyBytes[0] == 0x03 {
		internalPoint.Y.Negate(1)
		internalPoint.Y.Normalize()
	}

	btcec.AddNonConst(&internalPoint, &tweakPoint, &outputPoint)
	outputPoint.ToAffine()

	if outputPoint.Y.IsOdd() {
		result.Negate()
	}

	return result
}
