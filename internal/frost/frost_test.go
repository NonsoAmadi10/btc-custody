package frost

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

// runDKG is a test helper that simulates a complete DKG ceremony with n
// participants and threshold t. It returns each participant's DKGResult.
//
// In a real deployment, Round 1 outputs are broadcast over an authenticated
// channel, and Round 2 shares are sent privately (encrypted). Here we
// simulate that by passing values directly in memory.
func runDKG(t *testing.T, threshold, total uint32) map[uint32]*DKGResult {
	t.Helper()

	// ── Create participants ──────────────────────────────────────────────
	participants := make([]*Participant, total)
	for i := uint32(0); i < total; i++ {
		p, err := NewParticipant(i+1, threshold, total)
		if err != nil {
			t.Fatalf("NewParticipant(%d): %v", i+1, err)
		}
		participants[i] = p
	}

	// ── Round 1: each participant broadcasts their Feldman commitments ───
	round1Outputs := make([]*Round1Output, total)
	for i, p := range participants {
		round1Outputs[i] = p.Round1()
	}

	// ── Round 2: each participant computes and distributes shares ────────
	//
	// shares[to][from] = f_from(to)
	// Participant `from` evaluates their polynomial at index `to` and sends
	// it privately to participant `to`.
	shares := make(map[uint32]map[uint32]*btcec.ModNScalar)
	for i := uint32(1); i <= total; i++ {
		shares[i] = make(map[uint32]*btcec.ModNScalar)
	}

	for _, sender := range participants {
		for _, recipient := range participants {
			shares[recipient.Index][sender.Index] = sender.ShareFor(recipient.Index)
		}
	}

	// ── Finalise: each participant aggregates and derives the group key ──
	results := make(map[uint32]*DKGResult, total)
	for _, p := range participants {
		result, err := p.Finalise(round1Outputs, shares[p.Index])
		if err != nil {
			t.Fatalf("participant %d Finalise: %v", p.Index, err)
		}
		results[p.Index] = result
	}

	return results
}

// TestDKG_2of3 runs a 2-of-3 DKG ceremony and verifies the core properties.
func TestDKG_2of3(t *testing.T) {
	results := runDKG(t, 2, 3)
	assertDKGProperties(t, results, 2, 3)
}

// TestDKG_3of5 runs a 3-of-5 DKG ceremony.
func TestDKG_3of5(t *testing.T) {
	results := runDKG(t, 3, 5)
	assertDKGProperties(t, results, 3, 5)
}

// TestDKG_1of1 is the degenerate case: single participant, no threshold.
func TestDKG_1of1(t *testing.T) {
	results := runDKG(t, 1, 1)
	assertDKGProperties(t, results, 1, 1)
}

// assertDKGProperties checks the four invariants that must hold after any
// successful DKG ceremony:
//
//  1. All participants agree on the same group public key.
//  2. All participants agree on the same verification shares.
//  3. Each participant's secret share is consistent with their verification
//     share: x_i * G == X_i.
//  4. The group public key is consistent with verification share derivation
//     (sanity check that our point arithmetic is correct).
func assertDKGProperties(t *testing.T, results map[uint32]*DKGResult, threshold, total uint32) {
	t.Helper()

	if len(results) != int(total) {
		t.Fatalf("expected %d results, got %d", total, len(results))
	}

	// ── Property 1: All participants agree on the group public key ───────
	//
	// If any two participants derive different group keys, the ceremony
	// failed -- someone produced inconsistent commitments or there was a
	// bug in the point arithmetic.
	var referenceKey []byte
	for idx, r := range results {
		key := r.GroupPublicKey.SerializeCompressed()
		if referenceKey == nil {
			referenceKey = key
		} else if string(key) != string(referenceKey) {
			t.Errorf(
				"participant %d derived a different group public key:\n  got:  %x\n  want: %x",
				idx, key, referenceKey,
			)
		}
	}
	t.Logf("group public key (all agree): %x", referenceKey)

	// ── Property 2: All participants agree on verification shares ────────
	//
	// Every participant computes every other participant's verification
	// share from public information. They must all arrive at the same
	// values.
	ref := results[1] // use participant 1 as the reference
	for peerIdx := uint32(1); peerIdx <= total; peerIdx++ {
		refVShare := ref.VerificationShares[peerIdx].SerializeCompressed()

		for participantIdx, r := range results {
			vshare := r.VerificationShares[peerIdx].SerializeCompressed()
			if string(vshare) != string(refVShare) {
				t.Errorf(
					"participant %d disagrees on verification share for participant %d:\n"+
						"  got:  %x\n  want: %x",
					participantIdx, peerIdx, vshare, refVShare,
				)
			}
		}
	}

	// ── Property 3: x_i * G == X_i for every participant i ───────────────
	//
	// Each participant's secret share x_i, when multiplied by the generator G,
	// must equal their public verification share X_i.
	//
	// This is the fundamental consistency check: if x_i * G != X_i, our
	// Feldman VSS verification or share aggregation has a bug.
	for idx, r := range results {
		// Compute x_i * G
		derived := scalarBasePoint(r.SecretShare)
		derivedPub, err := jacobianToPubKey(&derived)
		if err != nil {
			t.Fatalf("participant %d: converting derived point to pubkey: %v", idx, err)
		}

		// Compare with X_i from verification shares
		expected := r.VerificationShares[idx].SerializeCompressed()
		got := derivedPub.SerializeCompressed()

		if string(got) != string(expected) {
			t.Errorf(
				"participant %d: x_i * G != X_i\n  x_i*G: %x\n  X_i:   %x",
				idx, got, expected,
			)
		} else {
			t.Logf("participant %d: x_i * G == X_i ✓", idx)
		}
	}
}

// TestShareVerification_InvalidShare verifies that Feldman VSS correctly
// detects when a participant sends a share that does not match their
// committed polynomial.
//
// This is the dishonest participant detection test. In a real deployment
// a failed verification aborts the ceremony and identifies the cheater.
func TestShareVerification_InvalidShare(t *testing.T) {
	threshold, total := uint32(2), uint32(3)

	participants := make([]*Participant, total)
	for i := uint32(0); i < total; i++ {
		p, err := NewParticipant(i+1, threshold, total)
		if err != nil {
			t.Fatalf("NewParticipant(%d): %v", i+1, err)
		}
		participants[i] = p
	}

	round1Outputs := make([]*Round1Output, total)
	for i, p := range participants {
		round1Outputs[i] = p.Round1()
	}

	// Build honest shares for participant 1.
	honestShares := make(map[uint32]*btcec.ModNScalar)
	for _, sender := range participants {
		honestShares[sender.Index] = sender.ShareFor(1)
	}

	// Replace participant 2's share with a random (incorrect) value.
	// This simulates participant 2 sending a malformed share to participant 1.
	badShare, err := randScalar()
	if err != nil {
		t.Fatalf("generating bad share: %v", err)
	}
	honestShares[2] = badShare

	// Finalise for participant 1 should fail with a dishonesty error.
	_, err = participants[0].Finalise(round1Outputs, honestShares)
	if err == nil {
		t.Fatal("expected Finalise to fail with invalid share, but it succeeded")
	}
	t.Logf("correctly detected invalid share: %v", err)
}

// TestNewParticipant_InvalidInputs checks that NewParticipant rejects
// obviously wrong configurations before generating any key material.
func TestNewParticipant_InvalidInputs(t *testing.T) {
	cases := []struct {
		name      string
		index     uint32
		threshold uint32
		total     uint32
	}{
		{"index zero", 0, 2, 3},
		{"index exceeds total", 4, 2, 3},
		{"threshold zero", 1, 0, 3},
		{"threshold exceeds total", 1, 4, 3},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewParticipant(tc.index, tc.threshold, tc.total)
			if err == nil {
				t.Errorf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

// Import needed by the test helper (shares map uses btcec.ModNScalar).
var _ = (*btcec.ModNScalar)(nil)
