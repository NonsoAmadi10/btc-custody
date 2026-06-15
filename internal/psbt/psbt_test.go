package psbt

import (
	"encoding/hex"
	"testing"

	"github.com/0xciph3r/btc-custody/internal/frost"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

// TestFullSigningRoundTrip exercises the complete flow:
// 1. Run FROST DKG with 3 participants, threshold 2
// 2. Derive a Taproot address from the group public key
// 3. Create a simulated UTXO locked to that address
// 4. Build a PSBT spending the UTXO
// 5. Two participants each produce a partial signature
// 6. Aggregate the partials into a final Schnorr signature
// 7. Verify the signature is valid
func TestFullSigningRoundTrip(t *testing.T) {
	// ══════════════════════════════════════════════════════════════════════
	// Phase 1: FROST DKG (same as internal/frost tests)
	// ══════════════════════════════════════════════════════════════════════

	const (
		threshold = 2
		total     = 3
	)

	// Create participants
	participants := make([]*frost.Participant, total)
	for i := uint32(1); i <= total; i++ {
		p, err := frost.NewParticipant(i, threshold, total)
		if err != nil {
			t.Fatalf("NewParticipant(%d): %v", i, err)
		}
		participants[i-1] = p
	}

	// Round 1: each participant broadcasts commitments
	allRound1 := make([]*frost.Round1Output, total)
	for i, p := range participants {
		allRound1[i] = p.Round1()
	}

	// Round 2: each participant sends shares to each other
	// Collect shares: participant i sends f_i(j) to participant j
	allShares := make([]map[uint32]*btcec.ModNScalar, total)
	for i := range allShares {
		allShares[i] = make(map[uint32]*btcec.ModNScalar)
	}

	for senderIdx, sender := range participants {
		for recipientIdx := uint32(1); recipientIdx <= total; recipientIdx++ {
			share := sender.ShareFor(recipientIdx)
			allShares[recipientIdx-1][uint32(senderIdx+1)] = share
		}
	}

	// Finalize: each participant aggregates shares and derives group key
	results := make([]*frost.DKGResult, total)
	for i, p := range participants {
		result, err := p.Finalise(allRound1, allShares[i])
		if err != nil {
			t.Fatalf("participant %d Finalise: %v", i+1, err)
		}
		results[i] = result
	}

	// Verify all participants derived the same group public key
	groupPubKey := results[0].GroupPublicKey
	for i, r := range results[1:] {
		if !groupPubKey.IsEqual(r.GroupPublicKey) {
			t.Fatalf("participant %d has different group key", i+2)
		}
	}

	t.Logf("DKG complete: group public key = %x", groupPubKey.SerializeCompressed())

	// ══════════════════════════════════════════════════════════════════════
	// Phase 2: Derive Taproot address and create simulated UTXO
	// ══════════════════════════════════════════════════════════════════════

	network := &chaincfg.TestNet3Params

	address, err := TaprootAddress(groupPubKey, network)
	if err != nil {
		t.Fatalf("TaprootAddress: %v", err)
	}
	t.Logf("Taproot address: %s", address)

	// Create the pkScript for this address
	pkScript := TaprootPkScript(groupPubKey)
	t.Logf("pkScript: %s", hex.EncodeToString(pkScript))

	// Simulate a UTXO with 100,000 sats locked to our group address
	utxo := UTXO{
		TxID:     "0000000000000000000000000000000000000000000000000000000000000001",
		Vout:     0,
		Value:    100_000,
		PkScript: pkScript,
	}

	// ══════════════════════════════════════════════════════════════════════
	// Phase 3: Build the PSBT
	// ══════════════════════════════════════════════════════════════════════

	builder := NewBuilder(network)

	// Send 50,000 sats to some recipient (another Taproot address for simplicity)
	recipient := Recipient{
		Address: "tb1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqp3mvzv",
		Amount:  50_000,
	}

	result, err := builder.Build(
		[]UTXO{utxo},
		[]Recipient{recipient},
		address, // change goes back to our group address
		2,       // 2 sat/vbyte fee rate
	)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	t.Logf("PSBT built: inputs=%d, outputs=%d, fee=%d sats",
		len(result.UnsignedTx.TxIn),
		len(result.UnsignedTx.TxOut),
		result.Fee)

	if len(result.SigHashes) != 1 {
		t.Fatalf("expected 1 sighash, got %d", len(result.SigHashes))
	}

	sighash := result.SigHashes[0]
	t.Logf("Sighash: %s", hex.EncodeToString(sighash))

	// ══════════════════════════════════════════════════════════════════════
	// Phase 4: FROST Signing Round 1 — Generate nonces
	// ══════════════════════════════════════════════════════════════════════

	// Only participants 1 and 2 will sign (meeting the 2-of-3 threshold)
	signerIndices := []uint32{1, 2}

	nonces := make(map[uint32]*NonceSecret)
	commitments := make([]*NonceCommitment, 0, len(signerIndices))

	for _, idx := range signerIndices {
		secret, commit, err := GenerateNonce(idx)
		if err != nil {
			t.Fatalf("GenerateNonce(%d): %v", idx, err)
		}
		nonces[idx] = secret
		commitments = append(commitments, commit)
	}

	t.Logf("Nonce commitments generated for signers %v", signerIndices)

	// ══════════════════════════════════════════════════════════════════════
	// Phase 5: FROST Signing Round 2 — Produce partial signatures
	// ══════════════════════════════════════════════════════════════════════

	// For Taproot key-path signing, we sign against the OUTPUT key (tweaked),
	// not the internal key. The output key is Q = P + H(P)·G.
	outputKey := txscript.ComputeTaprootOutputKey(groupPubKey, nil)

	session := &SigningSession{
		Message:        sighash,
		GroupPublicKey: outputKey, // Use output key for challenge computation
		AllCommitments: commitments,
		SignerIndices:  signerIndices,
	}

	partials := make([]*PartialSignature, 0, len(signerIndices))

	for _, idx := range signerIndices {
		// Get this participant's secret share from DKG
		share := results[idx-1].SecretShare

		// For Taproot we need to tweak the share
		tweakedShare := TweakShareForTaproot(share, groupPubKey, idx, signerIndices)

		partial, err := Sign(session, idx, tweakedShare, nonces[idx])
		if err != nil {
			t.Fatalf("Sign(%d): %v", idx, err)
		}
		partials = append(partials, partial)

		zBytes := partial.Z.Bytes()
		t.Logf("Partial signature from participant %d: z=%x...",
			idx, zBytes[:8])
	}

	// ══════════════════════════════════════════════════════════════════════
	// Phase 6: Aggregate partial signatures
	// ══════════════════════════════════════════════════════════════════════

	sig, err := Aggregate(session, partials)
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}

	t.Logf("Aggregated signature: %s", hex.EncodeToString(sig))

	// ══════════════════════════════════════════════════════════════════════
	// Phase 7: Verify the signature
	// ══════════════════════════════════════════════════════════════════════

	if !verifySchnorr(outputKey, sighash, sig) {
		t.Fatal("Signature verification failed!")
	}

	t.Log("✓ Signature verified successfully!")

	// ══════════════════════════════════════════════════════════════════════
	// Phase 8: Finalize the PSBT
	// ══════════════════════════════════════════════════════════════════════

	// Store partials in the PSBT
	for _, p := range partials {
		if err := result.Packet.SignInput(0, p); err != nil {
			t.Fatalf("SignInput: %v", err)
		}
	}

	if err := result.Packet.FinalizeInput(0, session); err != nil {
		t.Fatalf("FinalizeInput: %v", err)
	}

	if !result.Packet.IsSigned() {
		t.Fatal("PSBT not fully signed after finalization")
	}

	// Finalize to broadcastable tx
	finalTx, err := result.Packet.Finalize()
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}

	t.Logf("✓ Final transaction ready: %d inputs, %d outputs",
		len(finalTx.TxIn), len(finalTx.TxOut))
	t.Logf("✓ Witness: %x", finalTx.TxIn[0].Witness[0])
}

// TestTaprootAddress verifies Taproot address derivation.
func TestTaprootAddress(t *testing.T) {
	// Generate a random key for testing
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	pubKey := privKey.PubKey()

	// Derive testnet address
	addr, err := TaprootAddress(pubKey, &chaincfg.TestNet3Params)
	if err != nil {
		t.Fatalf("TaprootAddress: %v", err)
	}

	// Should start with tb1p (Bech32m testnet Taproot)
	if addr[:4] != "tb1p" {
		t.Errorf("expected tb1p prefix, got %s", addr[:4])
	}

	t.Logf("Taproot address: %s", addr)
}

// TestPSBTBuild verifies basic PSBT construction.
func TestPSBTBuild(t *testing.T) {
	network := &chaincfg.TestNet3Params
	builder := NewBuilder(network)

	// Create a fake UTXO (in reality would come from blockchain)
	utxo := UTXO{
		TxID:  "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		Vout:  0,
		Value: 100_000,
		PkScript: []byte{0x51, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00},
	}

	recipient := Recipient{
		Address: "tb1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqp3mvzv",
		Amount:  50_000,
	}

	result, err := builder.Build(
		[]UTXO{utxo},
		[]Recipient{recipient},
		"tb1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqp3mvzv",
		1,
	)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if len(result.UnsignedTx.TxIn) != 1 {
		t.Errorf("expected 1 input, got %d", len(result.UnsignedTx.TxIn))
	}

	if len(result.UnsignedTx.TxOut) < 1 {
		t.Errorf("expected at least 1 output, got %d", len(result.UnsignedTx.TxOut))
	}

	if result.Fee <= 0 {
		t.Errorf("expected positive fee, got %d", result.Fee)
	}

	t.Logf("PSBT: inputs=%d, outputs=%d, fee=%d",
		len(result.UnsignedTx.TxIn),
		len(result.UnsignedTx.TxOut),
		result.Fee)
}
