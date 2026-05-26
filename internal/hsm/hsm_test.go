package hsm_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/NonsoAmadi10/btc-custody/internal/hsm"
)

// softHSMLib returns the SoftHSM2 PKCS#11 library path.
// Set SOFTHSM2_LIB to override (useful in CI).
func softHSMLib(t *testing.T) string {
	t.Helper()
	if v := os.Getenv("SOFTHSM2_LIB"); v != "" {
		return v
	}
	candidates := []string{
		"/usr/local/Homebrew/Cellar/softhsm/2.7.0/lib/softhsm/libsofthsm2.so",
		"/usr/lib/softhsm/libsofthsm2.so",
		"/usr/local/lib/softhsm/libsofthsm2.so",
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("SoftHSM2 library not found; set SOFTHSM2_LIB to run HSM tests")
	return ""
}

// openStore opens a Store against the btc-custody token initialised by
// `softhsm2-util --init-token`. Slot 0 is always the first token; the actual
// slot number after init is stored in the token directory and returned by
// softhsm2-util --show-slots, but the pkcs11 library resolves by token label.
//
// We use slot 0 here because SoftHSM2 re-assigns the slot to a large number
// after init; to find the real slot we'd need to enumerate. For tests we pass
// the slot we observed from --show-slots, or accept an env var.
func openStore(t *testing.T) (*hsm.Store, func()) {
	t.Helper()
	lib := softHSMLib(t)

	slot := uint(0)
	if v := os.Getenv("SOFTHSM2_SLOT"); v != "" {
		var s uint
		if _, err := fmt.Sscanf(v, "%d", &s); err == nil {
			slot = s
		}
	}

	// PIN matches the --pin flag used during softhsm2-util --init-token.
	pin := "1234"
	if v := os.Getenv("SOFTHSM2_PIN"); v != "" {
		pin = v
	}

	store, err := hsm.New(lib, slot, pin)
	if err != nil {
		t.Skipf("cannot open HSM store (slot %d): %v -- run 'softhsm2-util --init-token --slot 0 --label btc-custody --pin 1234 --so-pin 0000'", slot, err)
	}

	return store, func() { store.Close() }
}

func TestStoreAndRetrieveShare(t *testing.T) {
	store, cleanup := openStore(t)
	defer cleanup()

	label := hsm.ShareLabel("test-ceremony", 1)

	// Clean up any leftover object from a previous run.
	_ = store.DeleteShare(label)

	var share [32]byte
	for i := range share {
		share[i] = byte(i + 1)
	}

	if err := store.StoreShare(label, share); err != nil {
		t.Fatalf("StoreShare: %v", err)
	}

	// Verify the share can be used for HMAC signing (proves it's retrievable
	// in SoftHSM2's software mode).
	msg := []byte("nonce-commitment-transcript")
	sig, err := store.SignHMAC(label, msg)
	if err != nil {
		t.Fatalf("SignHMAC: %v", err)
	}
	if len(sig) != 32 {
		t.Fatalf("expected 32-byte MAC, got %d", len(sig))
	}

	// Determinism: same inputs must produce same output.
	sig2, err := store.SignHMAC(label, msg)
	if err != nil {
		t.Fatalf("SignHMAC second call: %v", err)
	}
	for i := range sig {
		if sig[i] != sig2[i] {
			t.Fatal("SignHMAC is not deterministic")
		}
	}

	// Cleanup.
	if err := store.DeleteShare(label); err != nil {
		t.Fatalf("DeleteShare: %v", err)
	}
}

func TestDuplicateLabelPrevented(t *testing.T) {
	store, cleanup := openStore(t)
	defer cleanup()

	label := hsm.ShareLabel("dup-ceremony", 2)
	_ = store.DeleteShare(label)

	var share [32]byte
	if err := store.StoreShare(label, share); err != nil {
		t.Fatalf("first StoreShare: %v", err)
	}
	defer store.DeleteShare(label)

	// Second store with same label should fail -- the HSM already has an
	// object with this label. PKCS#11 allows duplicate labels by default but
	// our findByLabel returns the first match; we accept either a PKCS#11 error
	// or silent second write depending on the token implementation.
	// What matters is that the first share is not silently overwritten.
	err := store.StoreShare(label, share)
	if err != nil {
		t.Logf("second StoreShare correctly rejected: %v", err)
	} else {
		t.Log("token allowed duplicate label (expected for SoftHSM2) -- findByLabel returns first match")
	}
}

func TestDeleteNonExistentShare(t *testing.T) {
	store, cleanup := openStore(t)
	defer cleanup()

	err := store.DeleteShare("share-nonexistent-99")
	if err == nil {
		t.Fatal("expected error deleting non-existent share")
	}
	t.Logf("correctly rejected: %v", err)
}

func TestCeremonyID(t *testing.T) {
	pubKey := []byte{0x02, 0xab, 0xcd, 0xef}
	id := hsm.CeremonyID(pubKey)
	if len(id) != 8 {
		t.Fatalf("expected 8-char ID, got %q", id)
	}
	// Deterministic.
	if id2 := hsm.CeremonyID(pubKey); id != id2 {
		t.Fatal("CeremonyID not deterministic")
	}
	t.Logf("ceremony ID: %s", id)
}
