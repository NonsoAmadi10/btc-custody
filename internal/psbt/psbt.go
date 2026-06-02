// Package psbt provides PSBT (BIP-174) construction and parsing for the
// custody system's hot-to-cold sweep workflow.
//
// # Why PSBT
//
// A Partially Signed Bitcoin Transaction is a container format that carries
// an unsigned transaction alongside all the metadata signers need: the UTXOs
// being spent, the scripts to satisfy, the sighash type, and (eventually)
// the partial signatures from each threshold participant.
//
// PSBTs enable air-gapped signing: the hot system constructs the PSBT, exports
// it (USB, QR, file), each cold signer adds their partial signature without
// network access, and the combiner aggregates them into a broadcastable tx.
//
// # Taproot (BIP-341) specifics
//
// This implementation targets Taproot key-path spends exclusively. The group
// public key derived from FROST DKG becomes the Taproot internal key. Spending
// requires a Schnorr signature over the BIP-341 sighash -- which FROST
// threshold signing produces.
//
// Reference: https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
package psbt

import (
	"bytes"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// UTXO represents an unspent transaction output that can be used as an input.
// In a real system this comes from the Bitcoin node or an indexer.
type UTXO struct {
	// TxID is the transaction ID containing this output (hex, big-endian).
	TxID string

	// Vout is the output index within that transaction.
	Vout uint32

	// Value is the amount in satoshis.
	Value int64

	// PkScript is the scriptPubKey locking this output.
	// For Taproot outputs this is OP_1 <32-byte-x-only-pubkey>.
	PkScript []byte
}

// Recipient specifies where funds should be sent.
type Recipient struct {
	// Address is a Bitcoin address string (Bech32m for Taproot).
	Address string

	// Amount is the value in satoshis to send to this address.
	Amount int64
}

// Builder constructs unsigned PSBTs for the custody system.
type Builder struct {
	network *chaincfg.Params
}

// NewBuilder creates a PSBT builder for the given network.
// Use chaincfg.MainNetParams for mainnet, chaincfg.TestNet3Params for testnet,
// chaincfg.SigNetParams for signet.
func NewBuilder(network *chaincfg.Params) *Builder {
	return &Builder{network: network}
}

// BuildResult contains the constructed PSBT and associated metadata.
type BuildResult struct {
	// UnsignedTx is the raw unsigned transaction.
	UnsignedTx *wire.MsgTx

	// Packet is the full PSBT ready for signing.
	Packet *Packet

	// SigHashes contains the precomputed sighash for each input.
	// Signers need this to produce their partial Schnorr signatures.
	SigHashes [][]byte

	// TotalIn is the sum of all input values in satoshis.
	TotalIn int64

	// TotalOut is the sum of all output values in satoshis.
	TotalOut int64

	// Fee is TotalIn - TotalOut.
	Fee int64
}

// Build constructs an unsigned PSBT from the given inputs and outputs.
//
// Parameters:
//   - utxos: the coins to spend (must all be Taproot key-path spendable)
//   - recipients: where to send funds
//   - changeAddress: where to send leftover funds (nil = no change output)
//   - feeRate: satoshis per virtual byte
//
// The builder computes the transaction fee based on the estimated vsize and
// creates a change output if there are leftover funds above the dust threshold.
func (b *Builder) Build(
	utxos []UTXO,
	recipients []Recipient,
	changeAddress string,
	feeRate int64,
) (*BuildResult, error) {
	if len(utxos) == 0 {
		return nil, fmt.Errorf("psbt: no inputs provided")
	}
	if len(recipients) == 0 {
		return nil, fmt.Errorf("psbt: no recipients provided")
	}

	// Create the unsigned transaction.
	tx := wire.NewMsgTx(wire.TxVersion)

	// Add inputs.
	var totalIn int64
	prevOuts := make(map[wire.OutPoint]*wire.TxOut)

	for _, utxo := range utxos {
		hash, err := chainhash.NewHashFromStr(utxo.TxID)
		if err != nil {
			return nil, fmt.Errorf("psbt: invalid txid %q: %w", utxo.TxID, err)
		}

		outpoint := wire.NewOutPoint(hash, utxo.Vout)
		txIn := wire.NewTxIn(outpoint, nil, nil)
		txIn.Sequence = wire.MaxTxInSequenceNum
		tx.AddTxIn(txIn)

		prevOuts[*outpoint] = wire.NewTxOut(utxo.Value, utxo.PkScript)
		totalIn += utxo.Value
	}

	// Add recipient outputs.
	var totalOut int64
	for _, r := range recipients {
		addr, err := btcutil.DecodeAddress(r.Address, b.network)
		if err != nil {
			return nil, fmt.Errorf("psbt: invalid address %q: %w", r.Address, err)
		}

		pkScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return nil, fmt.Errorf("psbt: script for %q: %w", r.Address, err)
		}

		tx.AddTxOut(wire.NewTxOut(r.Amount, pkScript))
		totalOut += r.Amount
	}

	// Estimate fee (P2TR key-path spend: ~58 vbytes per input, ~43 per output).
	// Input: 36 (outpoint) + 1 (script len) + 0 (script) + 4 (sequence) = 41 bytes
	// Witness: 1 (items) + 1 (sig len) + 64 (schnorr sig) = 66 WU = 16.5 vbytes
	// Total per input: 41 + 16.5 = 57.5 vbytes
	// Output (P2TR): 8 (value) + 1 (script len) + 34 (script) = 43 bytes
	// Overhead: 10 (version, locktime, counts) + 0.5 (witness marker) = 10.5 vbytes
	estimatedVsize := 11 + 58*len(utxos) + 43*(len(recipients)+1) // +1 for potential change
	estimatedFee := feeRate * int64(estimatedVsize)

	// Calculate change.
	change := totalIn - totalOut - estimatedFee
	if change < 0 {
		return nil, fmt.Errorf(
			"psbt: insufficient funds: inputs=%d, outputs=%d, fee=%d, shortfall=%d",
			totalIn, totalOut, estimatedFee, -change,
		)
	}

	// Add change output if above dust (546 sats for P2TR).
	const dustThreshold = 546
	if change >= dustThreshold && changeAddress != "" {
		changeAddr, err := btcutil.DecodeAddress(changeAddress, b.network)
		if err != nil {
			return nil, fmt.Errorf("psbt: invalid change address %q: %w", changeAddress, err)
		}

		changePkScript, err := txscript.PayToAddrScript(changeAddr)
		if err != nil {
			return nil, fmt.Errorf("psbt: change script: %w", err)
		}

		tx.AddTxOut(wire.NewTxOut(change, changePkScript))
		totalOut += change
	}

	fee := totalIn - totalOut

	// Build the PSBT packet.
	packet := &Packet{
		UnsignedTx: tx,
		Inputs:     make([]Input, len(utxos)),
		Outputs:    make([]Output, len(tx.TxOut)),
	}

	// Populate input metadata.
	for i, utxo := range utxos {
		packet.Inputs[i] = Input{
			WitnessUtxo: &wire.TxOut{
				Value:    utxo.Value,
				PkScript: utxo.PkScript,
			},
			SighashType: txscript.SigHashDefault,
		}

		// Extract the x-only pubkey from the Taproot pkScript (OP_1 <32 bytes>).
		if len(utxo.PkScript) == 34 && utxo.PkScript[0] == txscript.OP_1 {
			xOnlyKey := utxo.PkScript[2:34]
			packet.Inputs[i].TaprootInternalKey = xOnlyKey
		}
	}

	// Compute sighashes for each input.
	prevOutFetcher := txscript.NewMultiPrevOutFetcher(prevOuts)
	sigHashes := make([][]byte, len(utxos))

	for i := range utxos {
		sigHash, err := txscript.CalcTaprootSignatureHash(
			txscript.NewTxSigHashes(tx, prevOutFetcher),
			txscript.SigHashDefault,
			tx,
			i,
			prevOutFetcher,
		)
		if err != nil {
			return nil, fmt.Errorf("psbt: sighash for input %d: %w", i, err)
		}
		sigHashes[i] = sigHash
	}

	return &BuildResult{
		UnsignedTx: tx,
		Packet:     packet,
		SigHashes:  sigHashes,
		TotalIn:    totalIn,
		TotalOut:   totalOut,
		Fee:        fee,
	}, nil
}

// ── PSBT Packet Structure ───────────────────────────────────────────────────
//
// Simplified PSBT representation focused on Taproot key-path spends.
// A full BIP-174 implementation would have many more fields.

// Packet is a simplified PSBT container.
type Packet struct {
	UnsignedTx *wire.MsgTx
	Inputs     []Input
	Outputs    []Output
}

// Input holds per-input PSBT fields.
type Input struct {
	// WitnessUtxo is the UTXO being spent (required for signing).
	WitnessUtxo *wire.TxOut

	// SighashType specifies how the transaction is hashed for signing.
	SighashType txscript.SigHashType

	// TaprootInternalKey is the x-only internal key (32 bytes).
	TaprootInternalKey []byte

	// TaprootKeySpendSig is the final Schnorr signature (64 bytes).
	// Populated after combining partial signatures.
	TaprootKeySpendSig []byte

	// PartialSigs holds partial signatures from threshold participants.
	// Key is the participant index, value is their z_i scalar (32 bytes).
	PartialSigs map[uint32][]byte
}

// Output holds per-output PSBT fields.
type Output struct {
	// TaprootInternalKey for outputs we control (enables change detection).
	TaprootInternalKey []byte
}

// ── Taproot Address Utilities ───────────────────────────────────────────────

// TaprootAddress derives a Bech32m Taproot address from a group public key.
// This is the address controlled by the threshold group after DKG.
//
// For key-path-only spends (no scripts), the Taproot output key is:
//
//	Q = P + H(P)·G
//
// where P is the internal key and H(P) is the tap tweak hash.
// Bitcoin Core calls this the "tweaked" key.
func TaprootAddress(groupPubKey *btcec.PublicKey, network *chaincfg.Params) (string, error) {
	// Compute the taproot output key (tweaked).
	// For key-path only (no script tree), the tweak is H_TapTweak(internalKey).
	outputKey := txscript.ComputeTaprootOutputKey(groupPubKey, nil)

	// Build the witness program: OP_1 <32-byte-x-only-output-key>
	witnessProgram := schnorr.SerializePubKey(outputKey)

	addr, err := btcutil.NewAddressTaproot(witnessProgram, network)
	if err != nil {
		return "", fmt.Errorf("psbt: taproot address: %w", err)
	}

	return addr.EncodeAddress(), nil
}

// TaprootPkScript returns the scriptPubKey for a Taproot output controlled
// by the given group public key.
func TaprootPkScript(groupPubKey *btcec.PublicKey) []byte {
	outputKey := txscript.ComputeTaprootOutputKey(groupPubKey, nil)
	witnessProgram := schnorr.SerializePubKey(outputKey)

	// OP_1 <32 bytes>
	script := make([]byte, 34)
	script[0] = txscript.OP_1
	script[1] = 0x20 // push 32 bytes
	copy(script[2:], witnessProgram)

	return script
}

// ── Serialization ───────────────────────────────────────────────────────────

// Serialize encodes the PSBT packet to bytes for transport.
// This is a simplified serialization -- a full implementation would use
// the BIP-174 key-value format.
func (p *Packet) Serialize() ([]byte, error) {
	var buf bytes.Buffer

	// Magic bytes: "psbt" + 0xff separator
	buf.WriteString("psbt")
	buf.WriteByte(0xff)

	// For this prototype we serialize the raw tx and metadata in a simple format.
	// A production implementation would use proper BIP-174 encoding.

	// Unsigned tx
	if err := p.UnsignedTx.Serialize(&buf); err != nil {
		return nil, fmt.Errorf("psbt: serialize tx: %w", err)
	}

	return buf.Bytes(), nil
}

// IsSigned returns true if all inputs have final signatures.
func (p *Packet) IsSigned() bool {
	for _, in := range p.Inputs {
		if len(in.TaprootKeySpendSig) != 64 {
			return false
		}
	}
	return true
}

// Finalize converts the PSBT to a fully signed transaction ready for broadcast.
// All inputs must have TaprootKeySpendSig populated.
func (p *Packet) Finalize() (*wire.MsgTx, error) {
	if !p.IsSigned() {
		return nil, fmt.Errorf("psbt: not all inputs are signed")
	}

	tx := p.UnsignedTx.Copy()

	for i, in := range p.Inputs {
		// For Taproot key-path spend, witness is just the signature.
		tx.TxIn[i].Witness = wire.TxWitness{in.TaprootKeySpendSig}
	}

	return tx, nil
}
