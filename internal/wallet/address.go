// Package wallet manages Bitcoin addresses and UTXOs for the custody system.
//
// # Architecture
//
// The wallet tracks two types of addresses derived from the FROST group key:
//
//   - Hot addresses: for receiving deposits, monitored online
//   - Cold addresses: for long-term storage, keys kept offline
//
// Both use BIP-86 style Taproot key-path derivation from the group public key.
// The derivation uses a simple index scheme since we don't have BIP-32 xpubs
// (the group key is created via DKG, not from a seed).
//
// # Address Derivation
//
// For a group public key P, we derive child addresses as:
//
//	child_i = P + H("btc-custody/derive" || P || i)·G
//
// This is deterministic and verifiable by all DKG participants.
package wallet

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

// AddressType distinguishes hot vs cold addresses.
type AddressType string

const (
	AddressTypeHot  AddressType = "hot"
	AddressTypeCold AddressType = "cold"
)

// DerivedAddress represents a Taproot address derived from the group key.
type DerivedAddress struct {
	// Index is the derivation index (0, 1, 2, ...)
	Index uint32

	// Type indicates hot or cold
	Type AddressType

	// Address is the bech32m Taproot address (bc1p... or tb1p...)
	Address string

	// PkScript is the scriptPubKey for this address
	PkScript []byte

	// InternalKey is the tweaked public key before Taproot output key derivation
	InternalKey *btcec.PublicKey

	// OutputKey is the final Taproot output key (appears on-chain)
	OutputKey *btcec.PublicKey
}

// AddressDeriver generates deterministic addresses from a group public key.
type AddressDeriver struct {
	groupPubKey *btcec.PublicKey
	network     *chaincfg.Params
}

// NewAddressDeriver creates a deriver for the given group key and network.
func NewAddressDeriver(groupPubKey *btcec.PublicKey, network *chaincfg.Params) *AddressDeriver {
	return &AddressDeriver{
		groupPubKey: groupPubKey,
		network:     network,
	}
}

// Derive generates an address at the given index and type.
//
// The derivation is:
//  1. Compute tweak: t = H("btc-custody/derive" || type || P || index)
//  2. Derive internal key: P' = P + t·G
//  3. Compute Taproot output key: Q = P' + H_TapTweak(P')·G
//  4. Encode as bech32m address
func (d *AddressDeriver) Derive(index uint32, addrType AddressType) (*DerivedAddress, error) {
	// Step 1: Compute derivation tweak
	tweak := d.computeTweak(index, addrType)

	// Step 2: Derive internal key: P' = P + tweak·G
	internalKey, err := d.deriveInternalKey(tweak)
	if err != nil {
		return nil, fmt.Errorf("deriving internal key: %w", err)
	}

	// Step 3: Compute Taproot output key
	outputKey := txscript.ComputeTaprootOutputKey(internalKey, nil)

	// Step 4: Create address
	address, err := d.taprootAddress(outputKey)
	if err != nil {
		return nil, fmt.Errorf("creating address: %w", err)
	}

	// Step 5: Create pkScript
	pkScript, err := d.taprootPkScript(outputKey)
	if err != nil {
		return nil, fmt.Errorf("creating pkScript: %w", err)
	}

	return &DerivedAddress{
		Index:       index,
		Type:        addrType,
		Address:     address,
		PkScript:    pkScript,
		InternalKey: internalKey,
		OutputKey:   outputKey,
	}, nil
}

// DeriveHot is a convenience method for deriving hot addresses.
func (d *AddressDeriver) DeriveHot(index uint32) (*DerivedAddress, error) {
	return d.Derive(index, AddressTypeHot)
}

// DeriveCold is a convenience method for deriving cold addresses.
func (d *AddressDeriver) DeriveCold(index uint32) (*DerivedAddress, error) {
	return d.Derive(index, AddressTypeCold)
}

// DeriveRange generates a range of addresses [start, end).
func (d *AddressDeriver) DeriveRange(start, end uint32, addrType AddressType) ([]*DerivedAddress, error) {
	if end <= start {
		return nil, fmt.Errorf("end (%d) must be greater than start (%d)", end, start)
	}

	addrs := make([]*DerivedAddress, 0, end-start)
	for i := start; i < end; i++ {
		addr, err := d.Derive(i, addrType)
		if err != nil {
			return nil, fmt.Errorf("deriving index %d: %w", i, err)
		}
		addrs = append(addrs, addr)
	}
	return addrs, nil
}

// computeTweak generates the derivation tweak for an index and type.
func (d *AddressDeriver) computeTweak(index uint32, addrType AddressType) *btcec.ModNScalar {
	// Tagged hash: H("btc-custody/derive" || type || P || index)
	h := sha256.New()
	h.Write([]byte("btc-custody/derive"))
	h.Write([]byte(addrType))
	h.Write(schnorr.SerializePubKey(d.groupPubKey))

	var indexBytes [4]byte
	binary.BigEndian.PutUint32(indexBytes[:], index)
	h.Write(indexBytes[:])

	digest := h.Sum(nil)

	tweak := new(btcec.ModNScalar)
	tweak.SetByteSlice(digest)
	return tweak
}

// deriveInternalKey computes P' = P + tweak·G
func (d *AddressDeriver) deriveInternalKey(tweak *btcec.ModNScalar) (*btcec.PublicKey, error) {
	// tweak·G
	var tweakPoint btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(tweak, &tweakPoint)

	// P (as Jacobian)
	var groupPoint btcec.JacobianPoint
	d.groupPubKey.AsJacobian(&groupPoint)

	// P' = P + tweak·G
	var resultPoint btcec.JacobianPoint
	btcec.AddNonConst(&groupPoint, &tweakPoint, &resultPoint)
	resultPoint.ToAffine()

	// Convert back to PublicKey
	return pubKeyFromJacobian(&resultPoint)
}

// taprootAddress creates a bech32m address from a Taproot output key.
func (d *AddressDeriver) taprootAddress(outputKey *btcec.PublicKey) (string, error) {
	addr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(outputKey),
		d.network,
	)
	if err != nil {
		return "", err
	}
	return addr.EncodeAddress(), nil
}

// taprootPkScript creates the scriptPubKey for a Taproot output.
func (d *AddressDeriver) taprootPkScript(outputKey *btcec.PublicKey) ([]byte, error) {
	return txscript.PayToTaprootScript(outputKey)
}

// GroupPubKey returns the underlying group public key.
func (d *AddressDeriver) GroupPubKey() *btcec.PublicKey {
	return d.groupPubKey
}

// Network returns the Bitcoin network.
func (d *AddressDeriver) Network() *chaincfg.Params {
	return d.network
}

// pubKeyFromJacobian converts a JacobianPoint to a PublicKey.
func pubKeyFromJacobian(p *btcec.JacobianPoint) (*btcec.PublicKey, error) {
	p.ToAffine()

	// Determine prefix based on Y parity
	prefix := byte(0x02)
	if p.Y.IsOdd() {
		prefix = 0x03
	}

	// Serialize compressed
	xBytes := p.X.Bytes()
	compressed := make([]byte, 33)
	compressed[0] = prefix
	copy(compressed[1:], xBytes[:])

	return btcec.ParsePubKey(compressed)
}
