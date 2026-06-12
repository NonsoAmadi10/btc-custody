// Package custody integrates all components into a complete custody system.
//
// # Architecture
//
// The CustodySystem orchestrates:
//   - FROST DKG for distributed key generation
//   - HSM storage for secure key share persistence
//   - Wallet for address derivation and UTXO tracking
//   - Policy engine for transaction authorization
//   - PSBT signing for threshold Schnorr signatures
//
// # Usage Flow
//
//  1. Initialize: Run DKG ceremony with N participants
//  2. Store: Each participant stores their share in HSM
//  3. Derive: Generate deposit addresses from group key
//  4. Receive: Monitor addresses for incoming funds
//  5. Spend: Build PSBT → Policy check → Collect signatures → Broadcast
package custody

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/NonsoAmadi10/btc-custody/internal/frost"
	"github.com/NonsoAmadi10/btc-custody/internal/policy"
	"github.com/NonsoAmadi10/btc-custody/internal/psbt"
	"github.com/NonsoAmadi10/btc-custody/internal/wallet"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// CustodySystem is the main orchestrator for the custody solution.
type CustodySystem struct {
	mu sync.RWMutex

	// Configuration
	config Config

	// Components
	wallet *wallet.Wallet
	policy *policy.Engine

	// DKG state
	groupPubKey  *btcec.PublicKey
	participants map[uint32]*ParticipantState

	// Ceremony tracking
	ceremonyID string
	threshold  uint32
	total      uint32
}

// Config configures the custody system.
type Config struct {
	// Network is mainnet, testnet, or regtest
	Network *chaincfg.Params

	// Threshold is the minimum signers required (t in t-of-n)
	Threshold uint32

	// Total is the total number of participants (n in t-of-n)
	Total uint32

	// BlockchainClient queries the blockchain
	BlockchainClient wallet.BlockchainClient

	// PolicyConfig configures authorization rules
	PolicyConfig *policy.Config
}

// ParticipantState tracks a single participant's DKG and signing state.
type ParticipantState struct {
	Index       uint32
	Participant *frost.Participant
	DKGResult   *frost.DKGResult
	ShareStored bool
}

// New creates a new custody system.
func New(cfg Config) (*CustodySystem, error) {
	if cfg.Network == nil {
		return nil, fmt.Errorf("network required")
	}
	if cfg.Threshold == 0 || cfg.Total == 0 {
		return nil, fmt.Errorf("threshold and total must be > 0")
	}
	if cfg.Threshold > cfg.Total {
		return nil, fmt.Errorf("threshold cannot exceed total")
	}
	if cfg.BlockchainClient == nil {
		return nil, fmt.Errorf("blockchain client required")
	}

	// Build policy engine if config provided
	var policyEngine *policy.Engine
	if cfg.PolicyConfig != nil {
		var err error
		policyEngine, err = cfg.PolicyConfig.BuildEngine()
		if err != nil {
			return nil, fmt.Errorf("building policy engine: %w", err)
		}
	} else {
		// Default: empty engine (deny all without rules)
		policyEngine = policy.NewEngine()
	}

	return &CustodySystem{
		config:       cfg,
		policy:       policyEngine,
		participants: make(map[uint32]*ParticipantState),
		threshold:    cfg.Threshold,
		total:        cfg.Total,
		ceremonyID:   fmt.Sprintf("ceremony-%d", time.Now().Unix()),
	}, nil
}

// ═══════════════════════════════════════════════════════════════════════════
// DKG Ceremony
// ═══════════════════════════════════════════════════════════════════════════

// InitializeDKG creates all participants for the DKG ceremony.
// In a real deployment, each participant would run on a separate machine.
func (c *CustodySystem) InitializeDKG() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i := uint32(1); i <= c.total; i++ {
		p, err := frost.NewParticipant(i, c.threshold, c.total)
		if err != nil {
			return fmt.Errorf("creating participant %d: %w", i, err)
		}
		c.participants[i] = &ParticipantState{
			Index:       i,
			Participant: p,
		}
	}

	return nil
}

// RunDKGCeremony executes the full DKG protocol.
// Returns the group public key on success.
func (c *CustodySystem) RunDKGCeremony() (*btcec.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.participants) == 0 {
		return nil, fmt.Errorf("DKG not initialized; call InitializeDKG first")
	}

	// Round 1: Each participant generates commitments
	allRound1 := make([]*frost.Round1Output, 0, c.total)
	for i := uint32(1); i <= c.total; i++ {
		output := c.participants[i].Participant.Round1()
		allRound1 = append(allRound1, output)
	}

	// Round 2: Each participant sends shares to each other
	allShares := make([]map[uint32]*btcec.ModNScalar, c.total)
	for i := range allShares {
		allShares[i] = make(map[uint32]*btcec.ModNScalar)
	}

	for senderIdx := uint32(1); senderIdx <= c.total; senderIdx++ {
		sender := c.participants[senderIdx].Participant
		for recipientIdx := uint32(1); recipientIdx <= c.total; recipientIdx++ {
			share := sender.ShareFor(recipientIdx)
			allShares[recipientIdx-1][senderIdx] = share
		}
	}

	// Finalization: Each participant aggregates shares
	var groupPubKey *btcec.PublicKey
	for i := uint32(1); i <= c.total; i++ {
		result, err := c.participants[i].Participant.Finalise(allRound1, allShares[i-1])
		if err != nil {
			return nil, fmt.Errorf("participant %d finalize: %w", i, err)
		}
		c.participants[i].DKGResult = result

		// All participants should derive the same group key
		if groupPubKey == nil {
			groupPubKey = result.GroupPublicKey
		} else if !groupPubKey.IsEqual(result.GroupPublicKey) {
			return nil, fmt.Errorf("participant %d derived different group key", i)
		}
	}

	c.groupPubKey = groupPubKey
	return groupPubKey, nil
}

// GetParticipantShare returns a participant's secret share (for HSM storage).
func (c *CustodySystem) GetParticipantShare(index uint32) (*btcec.ModNScalar, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	p, ok := c.participants[index]
	if !ok {
		return nil, fmt.Errorf("participant %d not found", index)
	}
	if p.DKGResult == nil {
		return nil, fmt.Errorf("DKG not complete for participant %d", index)
	}

	return p.DKGResult.SecretShare, nil
}

// ═══════════════════════════════════════════════════════════════════════════
// Wallet Management
// ═══════════════════════════════════════════════════════════════════════════

// InitializeWallet creates the wallet after DKG is complete.
func (c *CustodySystem) InitializeWallet(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.groupPubKey == nil {
		return fmt.Errorf("DKG not complete; run ceremony first")
	}

	w, err := wallet.NewWallet(wallet.WalletConfig{
		GroupPubKey: c.groupPubKey,
		Network:     c.config.Network,
		Client:      c.config.BlockchainClient,
		GapLimit:    20,
	})
	if err != nil {
		return fmt.Errorf("creating wallet: %w", err)
	}

	if err := w.Initialize(ctx); err != nil {
		return fmt.Errorf("initializing wallet: %w", err)
	}

	c.wallet = w
	return nil
}

// GetDepositAddress returns a fresh address for receiving deposits.
func (c *CustodySystem) GetDepositAddress() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.wallet == nil {
		return "", fmt.Errorf("wallet not initialized")
	}

	addr, err := c.wallet.NewHotAddress()
	if err != nil {
		return "", err
	}

	return addr.Address, nil
}

// SyncWallet refreshes UTXO data from the blockchain.
func (c *CustodySystem) SyncWallet(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.wallet == nil {
		return fmt.Errorf("wallet not initialized")
	}

	return c.wallet.Sync(ctx)
}

// GetBalance returns the confirmed balance.
func (c *CustodySystem) GetBalance() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.wallet == nil {
		return 0
	}

	return c.wallet.Balance()
}

// ═══════════════════════════════════════════════════════════════════════════
// Transaction Signing
// ═══════════════════════════════════════════════════════════════════════════

// SpendRequest represents a request to send funds.
type SpendRequest struct {
	// Destinations are the recipients
	Destinations []psbt.Recipient

	// FeeRate in satoshis per vbyte
	FeeRate int64

	// RequestedBy identifies who initiated the request
	RequestedBy string

	// Approvals are human sign-offs (for policy)
	Approvals []policy.Approval

	// SignerIndices are which participants will sign (must meet threshold)
	SignerIndices []uint32
}

// SpendResult contains the result of a spend operation.
type SpendResult struct {
	// TxID is the transaction ID (if broadcast)
	TxID string

	// RawTx is the signed transaction hex
	RawTx string

	// Fee is the transaction fee in satoshis
	Fee int64

	// PolicyDecision explains if/why the request was approved/denied
	PolicyDecision policy.Decision
}

// Spend builds, signs, and optionally broadcasts a transaction.
func (c *CustodySystem) Spend(ctx context.Context, req SpendRequest, broadcast bool) (*SpendResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.wallet == nil {
		return nil, fmt.Errorf("wallet not initialized")
	}

	if len(req.SignerIndices) < int(c.threshold) {
		return nil, fmt.Errorf("need at least %d signers, got %d", c.threshold, len(req.SignerIndices))
	}

	// Calculate total amount
	var totalAmount int64
	destinations := make([]policy.Destination, len(req.Destinations))
	for i, d := range req.Destinations {
		totalAmount += d.Amount
		destinations[i] = policy.Destination{
			Address: d.Address,
			Amount:  d.Amount,
		}
	}

	// Check policy
	policyReq := &policy.TransactionRequest{
		ID:           fmt.Sprintf("spend-%d", time.Now().UnixNano()),
		Destinations: destinations,
		TotalAmount:  totalAmount,
		RequestedBy:  req.RequestedBy,
		RequestedAt:  time.Now(),
		Approvals:    req.Approvals,
	}

	decision := c.policy.Evaluate(policyReq)
	if !decision.Allowed {
		return &SpendResult{
			PolicyDecision: decision,
		}, fmt.Errorf("policy denied: %s", decision.Reason)
	}

	// Select UTXOs
	utxos := c.wallet.Spendable()
	if len(utxos) == 0 {
		return nil, fmt.Errorf("no spendable UTXOs")
	}

	// Convert to PSBT UTXOs
	psbtUTXOs := make([]psbt.UTXO, len(utxos))
	for i, u := range utxos {
		psbtUTXOs[i] = psbt.UTXO{
			TxID:     u.TxID,
			Vout:     u.Vout,
			Value:    u.Amount,
			PkScript: u.PkScript,
		}
	}

	// Get change address
	changeAddr, err := c.wallet.NewHotAddress()
	if err != nil {
		return nil, fmt.Errorf("getting change address: %w", err)
	}

	// Build PSBT
	builder := psbt.NewBuilder(c.config.Network)
	buildResult, err := builder.Build(psbtUTXOs, req.Destinations, changeAddr.Address, req.FeeRate)
	if err != nil {
		return nil, fmt.Errorf("building PSBT: %w", err)
	}

	// Generate nonces for each signer
	nonces := make(map[uint32]*psbt.NonceSecret)
	commitments := make([]*psbt.NonceCommitment, 0, len(req.SignerIndices))

	for _, idx := range req.SignerIndices {
		secret, commit, err := psbt.GenerateNonce(idx)
		if err != nil {
			return nil, fmt.Errorf("generating nonce for %d: %w", idx, err)
		}
		nonces[idx] = secret
		commitments = append(commitments, commit)
	}

	// Compute the Taproot output key (tweaked) for signature verification
	outputKey := computeTaprootOutputKey(c.groupPubKey)

	// Sign each input
	for inputIdx, sighash := range buildResult.SigHashes {
		session := &psbt.SigningSession{
			Message:        sighash,
			GroupPublicKey: outputKey, // Use output key for challenge
			AllCommitments: commitments,
			SignerIndices:  req.SignerIndices,
		}

		var partials []*psbt.PartialSignature

		for _, idx := range req.SignerIndices {
			p := c.participants[idx]
			if p == nil || p.DKGResult == nil {
				return nil, fmt.Errorf("participant %d not ready", idx)
			}

			// Tweak share for Taproot
			tweakedShare := psbt.TweakShareForTaproot(
				p.DKGResult.SecretShare,
				c.groupPubKey,
				idx,
				req.SignerIndices,
			)

			partial, err := psbt.Sign(session, idx, tweakedShare, nonces[idx])
			if err != nil {
				return nil, fmt.Errorf("signing by %d: %w", idx, err)
			}
			partials = append(partials, partial)
		}

		// Aggregate signatures
		sig, err := psbt.Aggregate(session, partials)
		if err != nil {
			return nil, fmt.Errorf("aggregating signatures: %w", err)
		}

		// Store in PSBT
		for _, p := range partials {
			buildResult.Packet.SignInput(inputIdx, p)
		}
		buildResult.Packet.FinalizeInput(inputIdx, session)

		_ = sig // signature is stored in packet
	}

	// Finalize transaction
	finalTx, err := buildResult.Packet.Finalize()
	if err != nil {
		return nil, fmt.Errorf("finalizing: %w", err)
	}

	// Serialize
	var txBuf []byte
	txBuf, err = serializeTx(finalTx)
	if err != nil {
		return nil, fmt.Errorf("serializing tx: %w", err)
	}
	txHex := fmt.Sprintf("%x", txBuf)

	result := &SpendResult{
		RawTx:          txHex,
		Fee:            buildResult.Fee,
		PolicyDecision: decision,
	}

	// Broadcast if requested
	if broadcast {
		txid, err := c.wallet.BroadcastTx(ctx, txHex)
		if err != nil {
			return result, fmt.Errorf("broadcasting: %w", err)
		}
		result.TxID = txid

		// Mark UTXOs as spent
		for _, u := range utxos {
			c.wallet.UTXOs().MarkSpent(u.TxID, u.Vout, txid)
		}
	}

	return result, nil
}

// serializeTx serializes a wire.MsgTx to bytes.
func serializeTx(tx *wire.MsgTx) ([]byte, error) {
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ═══════════════════════════════════════════════════════════════════════════
// Status and Info
// ═══════════════════════════════════════════════════════════════════════════

// Status returns the current system status.
type Status struct {
	CeremonyID       string
	Threshold        uint32
	Total            uint32
	DKGComplete      bool
	WalletReady      bool
	ParticipantCount int
	Balance          int64
	Network          string
}

// GetStatus returns the current system status.
func (c *CustodySystem) GetStatus() Status {
	c.mu.RLock()
	defer c.mu.RUnlock()

	s := Status{
		CeremonyID:       c.ceremonyID,
		Threshold:        c.threshold,
		Total:            c.total,
		DKGComplete:      c.groupPubKey != nil,
		WalletReady:      c.wallet != nil,
		ParticipantCount: len(c.participants),
	}

	if c.wallet != nil {
		s.Balance = c.wallet.Balance()
		s.Network = c.config.Network.Name
	}

	return s
}

// GroupPublicKey returns the group public key (nil if DKG not complete).
func (c *CustodySystem) GroupPublicKey() *btcec.PublicKey {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.groupPubKey
}

// computeTaprootOutputKey computes Q = P + H(P)·G for Taproot.
func computeTaprootOutputKey(internalKey *btcec.PublicKey) *btcec.PublicKey {
	return txscript.ComputeTaprootOutputKey(internalKey, nil)
}
