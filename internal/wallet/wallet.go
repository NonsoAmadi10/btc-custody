package wallet

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
)

// Wallet manages addresses and UTXOs for a FROST group key.
type Wallet struct {
	mu sync.RWMutex

	// Address derivation
	deriver *AddressDeriver

	// UTXO tracking
	utxos *UTXOSet

	// Blockchain queries
	client BlockchainClient

	// Tracked addresses
	hotAddresses  []*DerivedAddress
	coldAddresses []*DerivedAddress

	// Indices
	nextHotIndex  uint32
	nextColdIndex uint32

	// Gap limit: how many unused addresses to track
	gapLimit uint32
}

// WalletConfig configures a new wallet.
type WalletConfig struct {
	// GroupPubKey is the FROST group public key from DKG.
	GroupPubKey *btcec.PublicKey

	// Network is mainnet, testnet, or regtest.
	Network *chaincfg.Params

	// Client queries the blockchain.
	Client BlockchainClient

	// GapLimit is how many unused addresses to pre-derive.
	// Default: 20 (standard BIP-44 gap limit)
	GapLimit uint32
}

// NewWallet creates a wallet for the given group key.
func NewWallet(cfg WalletConfig) (*Wallet, error) {
	if cfg.GroupPubKey == nil {
		return nil, fmt.Errorf("group public key required")
	}
	if cfg.Network == nil {
		return nil, fmt.Errorf("network required")
	}
	if cfg.Client == nil {
		return nil, fmt.Errorf("blockchain client required")
	}

	gapLimit := cfg.GapLimit
	if gapLimit == 0 {
		gapLimit = 20
	}

	return &Wallet{
		deriver:      NewAddressDeriver(cfg.GroupPubKey, cfg.Network),
		utxos:        NewUTXOSet(),
		client:       cfg.Client,
		gapLimit:     gapLimit,
		hotAddresses: make([]*DerivedAddress, 0),
		coldAddresses: make([]*DerivedAddress, 0),
	}, nil
}

// Initialize derives initial addresses and syncs UTXOs.
func (w *Wallet) Initialize(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Derive initial hot addresses
	for i := uint32(0); i < w.gapLimit; i++ {
		addr, err := w.deriver.DeriveHot(i)
		if err != nil {
			return fmt.Errorf("deriving hot address %d: %w", i, err)
		}
		w.hotAddresses = append(w.hotAddresses, addr)
	}
	w.nextHotIndex = w.gapLimit

	// Derive initial cold addresses
	for i := uint32(0); i < w.gapLimit; i++ {
		addr, err := w.deriver.DeriveCold(i)
		if err != nil {
			return fmt.Errorf("deriving cold address %d: %w", i, err)
		}
		w.coldAddresses = append(w.coldAddresses, addr)
	}
	w.nextColdIndex = w.gapLimit

	// Sync UTXOs for all addresses
	return w.syncUTXOsLocked(ctx)
}

// Sync refreshes UTXO data from the blockchain.
func (w *Wallet) Sync(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.syncUTXOsLocked(ctx)
}

// syncUTXOsLocked fetches UTXOs for all tracked addresses. Must hold mu.
func (w *Wallet) syncUTXOsLocked(ctx context.Context) error {
	// Collect all addresses
	var addresses []string
	for _, addr := range w.hotAddresses {
		addresses = append(addresses, addr.Address)
	}
	for _, addr := range w.coldAddresses {
		addresses = append(addresses, addr.Address)
	}

	// Clear existing UTXOs
	w.utxos.Clear()

	// Fetch UTXOs for each address
	for _, address := range addresses {
		utxos, err := w.client.GetUTXOs(ctx, address)
		if err != nil {
			return fmt.Errorf("fetching UTXOs for %s: %w", address, err)
		}
		for _, utxo := range utxos {
			w.utxos.Add(utxo)
		}
	}

	return nil
}

// NewHotAddress generates a fresh hot address for receiving deposits.
func (w *Wallet) NewHotAddress() (*DerivedAddress, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	addr, err := w.deriver.DeriveHot(w.nextHotIndex)
	if err != nil {
		return nil, err
	}

	w.hotAddresses = append(w.hotAddresses, addr)
	w.nextHotIndex++

	return addr, nil
}

// NewColdAddress generates a fresh cold address for long-term storage.
func (w *Wallet) NewColdAddress() (*DerivedAddress, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	addr, err := w.deriver.DeriveCold(w.nextColdIndex)
	if err != nil {
		return nil, err
	}

	w.coldAddresses = append(w.coldAddresses, addr)
	w.nextColdIndex++

	return addr, nil
}

// HotAddresses returns all tracked hot addresses.
func (w *Wallet) HotAddresses() []*DerivedAddress {
	w.mu.RLock()
	defer w.mu.RUnlock()

	result := make([]*DerivedAddress, len(w.hotAddresses))
	copy(result, w.hotAddresses)
	return result
}

// ColdAddresses returns all tracked cold addresses.
func (w *Wallet) ColdAddresses() []*DerivedAddress {
	w.mu.RLock()
	defer w.mu.RUnlock()

	result := make([]*DerivedAddress, len(w.coldAddresses))
	copy(result, w.coldAddresses)
	return result
}

// Balance returns the confirmed balance across all addresses.
func (w *Wallet) Balance() int64 {
	return w.utxos.Balance()
}

// UnconfirmedBalance returns the unconfirmed balance.
func (w *Wallet) UnconfirmedBalance() int64 {
	return w.utxos.UnconfirmedBalance()
}

// Spendable returns all UTXOs that can be spent.
func (w *Wallet) Spendable() []*UTXO {
	return w.utxos.Spendable()
}

// SelectCoins selects UTXOs to cover a target amount.
// See UTXOSet.SelectCoins for details.
func (w *Wallet) SelectCoins(target int64, feeRate int) ([]*UTXO, int64, error) {
	// P2TR key-path input is ~68 vbytes
	return w.utxos.SelectCoins(target, feeRate, 68)
}

// BroadcastTx submits a signed transaction to the network.
func (w *Wallet) BroadcastTx(ctx context.Context, txHex string) (string, error) {
	return w.client.BroadcastTx(ctx, txHex)
}

// WaitForConfirmation polls until a transaction is confirmed.
func (w *Wallet) WaitForConfirmation(ctx context.Context, txid string, pollInterval time.Duration) error {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			confirmed, _, err := w.client.GetTxStatus(ctx, txid)
			if err != nil {
				return err
			}
			if confirmed {
				return nil
			}
		}
	}
}

// Summary returns a human-readable summary of the wallet state.
func (w *Wallet) Summary() WalletSummary {
	w.mu.RLock()
	defer w.mu.RUnlock()

	return WalletSummary{
		HotAddressCount:    len(w.hotAddresses),
		ColdAddressCount:   len(w.coldAddresses),
		UTXOCount:          w.utxos.Count(),
		Balance:            w.utxos.Balance(),
		UnconfirmedBalance: w.utxos.UnconfirmedBalance(),
		Network:            w.deriver.Network().Name,
	}
}

// WalletSummary contains wallet statistics.
type WalletSummary struct {
	HotAddressCount    int
	ColdAddressCount   int
	UTXOCount          int
	Balance            int64 // satoshis
	UnconfirmedBalance int64
	Network            string
}

// FormatBTC converts satoshis to BTC string.
func FormatBTC(sats int64) string {
	return fmt.Sprintf("%.8f BTC", float64(sats)/100_000_000)
}

// GroupPubKey returns the underlying FROST group public key.
func (w *Wallet) GroupPubKey() *btcec.PublicKey {
	return w.deriver.GroupPubKey()
}

// Network returns the Bitcoin network.
func (w *Wallet) Network() *chaincfg.Params {
	return w.deriver.Network()
}

// UTXOs returns the underlying UTXO set (for advanced use).
func (w *Wallet) UTXOs() *UTXOSet {
	return w.utxos
}
