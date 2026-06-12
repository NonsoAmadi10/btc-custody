package wallet

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// UTXO represents an unspent transaction output.
type UTXO struct {
	// TxID is the transaction hash (hex, big-endian as shown in explorers)
	TxID string

	// Vout is the output index within the transaction
	Vout uint32

	// Amount is the value in satoshis
	Amount int64

	// PkScript is the locking script
	PkScript []byte

	// Address is the Bitcoin address this UTXO is locked to
	Address string

	// Confirmations is the number of confirmations (0 = mempool)
	Confirmations int

	// BlockHeight is the block this UTXO was confirmed in (0 = unconfirmed)
	BlockHeight uint32

	// Timestamp is when we first saw this UTXO
	Timestamp time.Time

	// Spent indicates if this UTXO has been spent
	Spent bool

	// SpentInTxID is the transaction that spent this UTXO (if spent)
	SpentInTxID string
}

// OutPoint returns the canonical outpoint string "txid:vout".
func (u *UTXO) OutPoint() string {
	return fmt.Sprintf("%s:%d", u.TxID, u.Vout)
}

// IsConfirmed returns true if the UTXO has at least one confirmation.
func (u *UTXO) IsConfirmed() bool {
	return u.Confirmations > 0
}

// IsMature returns true if the UTXO has enough confirmations for spending.
// For regular UTXOs, 1 confirmation is enough.
// For coinbase UTXOs (not typical in our use case), 100 confirmations are needed.
func (u *UTXO) IsMature() bool {
	return u.Confirmations >= 1
}

// UTXOSet manages a collection of UTXOs for the wallet.
type UTXOSet struct {
	mu    sync.RWMutex
	utxos map[string]*UTXO // keyed by "txid:vout"
}

// NewUTXOSet creates an empty UTXO set.
func NewUTXOSet() *UTXOSet {
	return &UTXOSet{
		utxos: make(map[string]*UTXO),
	}
}

// Add inserts or updates a UTXO in the set.
func (s *UTXOSet) Add(utxo *UTXO) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := utxo.OutPoint()
	if existing, ok := s.utxos[key]; ok {
		// Update confirmations if UTXO already exists
		existing.Confirmations = utxo.Confirmations
		existing.BlockHeight = utxo.BlockHeight
	} else {
		s.utxos[key] = utxo
	}
}

// Remove deletes a UTXO from the set.
func (s *UTXOSet) Remove(txid string, vout uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := fmt.Sprintf("%s:%d", txid, vout)
	delete(s.utxos, key)
}

// MarkSpent marks a UTXO as spent by a given transaction.
func (s *UTXOSet) MarkSpent(txid string, vout uint32, spentInTxID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := fmt.Sprintf("%s:%d", txid, vout)
	if utxo, ok := s.utxos[key]; ok {
		utxo.Spent = true
		utxo.SpentInTxID = spentInTxID
		return true
	}
	return false
}

// Get retrieves a specific UTXO.
func (s *UTXOSet) Get(txid string, vout uint32) (*UTXO, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := fmt.Sprintf("%s:%d", txid, vout)
	utxo, ok := s.utxos[key]
	return utxo, ok
}

// Unspent returns all unspent UTXOs.
func (s *UTXOSet) Unspent() []*UTXO {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*UTXO
	for _, utxo := range s.utxos {
		if !utxo.Spent {
			result = append(result, utxo)
		}
	}
	return result
}

// Spendable returns all UTXOs that are unspent and confirmed.
func (s *UTXOSet) Spendable() []*UTXO {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*UTXO
	for _, utxo := range s.utxos {
		if !utxo.Spent && utxo.IsMature() {
			result = append(result, utxo)
		}
	}
	return result
}

// ForAddress returns all UTXOs for a specific address.
func (s *UTXOSet) ForAddress(address string) []*UTXO {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*UTXO
	for _, utxo := range s.utxos {
		if utxo.Address == address {
			result = append(result, utxo)
		}
	}
	return result
}

// Balance returns the total balance of unspent, confirmed UTXOs.
func (s *UTXOSet) Balance() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var total int64
	for _, utxo := range s.utxos {
		if !utxo.Spent && utxo.IsMature() {
			total += utxo.Amount
		}
	}
	return total
}

// UnconfirmedBalance returns the balance of unconfirmed (mempool) UTXOs.
func (s *UTXOSet) UnconfirmedBalance() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var total int64
	for _, utxo := range s.utxos {
		if !utxo.Spent && !utxo.IsConfirmed() {
			total += utxo.Amount
		}
	}
	return total
}

// Count returns the number of UTXOs in the set.
func (s *UTXOSet) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.utxos)
}

// SelectCoins selects UTXOs to cover a target amount plus fees.
// Uses a simple largest-first strategy.
//
// Parameters:
//   - target: amount needed in satoshis (excluding fees)
//   - feeRate: satoshis per virtual byte
//   - inputSize: estimated vbytes per input (68 for P2TR key-path)
//
// Returns selected UTXOs and total value, or error if insufficient funds.
func (s *UTXOSet) SelectCoins(target int64, feeRate int, inputSize int) ([]*UTXO, int64, error) {
	spendable := s.Spendable()
	if len(spendable) == 0 {
		return nil, 0, fmt.Errorf("no spendable UTXOs")
	}

	// Sort by amount descending (largest first)
	sort.Slice(spendable, func(i, j int) bool {
		return spendable[i].Amount > spendable[j].Amount
	})

	var selected []*UTXO
	var total int64

	for _, utxo := range spendable {
		selected = append(selected, utxo)
		total += utxo.Amount

		// Estimate fee with current selection
		estimatedFee := int64(len(selected)*inputSize*feeRate) + int64(50*feeRate) // +50 vbytes for outputs/overhead

		if total >= target+estimatedFee {
			return selected, total, nil
		}
	}

	return nil, 0, fmt.Errorf("insufficient funds: have %d, need %d + fees", total, target)
}

// Clear removes all UTXOs from the set.
func (s *UTXOSet) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.utxos = make(map[string]*UTXO)
}

// All returns all UTXOs (spent and unspent).
func (s *UTXOSet) All() []*UTXO {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*UTXO, 0, len(s.utxos))
	for _, utxo := range s.utxos {
		result = append(result, utxo)
	}
	return result
}
