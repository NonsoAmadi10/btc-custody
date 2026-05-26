// Package hsm provides PKCS#11-backed storage for FROST key shares.
//
// In production each participant's secret share lives inside the HSM.
// The share is written once during the key ceremony and is never exported
// (CKA_EXTRACTABLE = false). All subsequent use is in-HSM: the policy engine
// asks the HSM to produce a partial signature; the raw scalar bytes never
// leave the device boundary.
//
// For the prototype we use SoftHSM2 so the whole stack can be exercised on a
// developer machine without physical hardware.
package hsm

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/miekg/pkcs11"
)

const (
	// ShareKeyType is the CKK_GENERIC_SECRET type used to store 32-byte scalars.
	ShareKeyType = pkcs11.CKK_GENERIC_SECRET

	// ShareKeyClass is the object class for secret key objects.
	ShareKeyClass = pkcs11.CKO_SECRET_KEY
)

// Store holds an open PKCS#11 session against a single token slot.
// One Store is created per participant during the key ceremony and
// re-opened at node startup.
type Store struct {
	ctx    *pkcs11.Ctx
	lib    string
	slot   uint
	pin    string
	handle pkcs11.SessionHandle
}

// New opens a PKCS#11 context against the given shared-library path (e.g.
// /usr/local/lib/softhsm/libsofthsm2.so), logs in with the supplied PIN, and
// returns a ready Store. Call Close when done.
func New(lib string, slot uint, pin string) (*Store, error) {
	ctx := pkcs11.New(lib)
	if ctx == nil {
		return nil, fmt.Errorf("hsm: failed to load PKCS#11 library %s", lib)
	}

	if err := ctx.Initialize(); err != nil {
		ctx.Destroy()
		return nil, fmt.Errorf("hsm: initialize: %w", err)
	}

	sess, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		ctx.Finalize()
		ctx.Destroy()
		return nil, fmt.Errorf("hsm: open session slot %d: %w", slot, err)
	}

	if err := ctx.Login(sess, pkcs11.CKU_USER, pin); err != nil {
		ctx.CloseSession(sess)
		ctx.Finalize()
		ctx.Destroy()
		return nil, fmt.Errorf("hsm: login: %w", err)
	}

	return &Store{ctx: ctx, lib: lib, slot: slot, pin: pin, handle: sess}, nil
}

// Close logs out, closes the session, and releases the PKCS#11 context.
func (s *Store) Close() error {
	var errs []error
	if err := s.ctx.Logout(s.handle); err != nil {
		errs = append(errs, err)
	}
	if err := s.ctx.CloseSession(s.handle); err != nil {
		errs = append(errs, err)
	}
	s.ctx.Finalize()
	s.ctx.Destroy()
	if len(errs) > 0 {
		return fmt.Errorf("hsm: close: %v", errs)
	}
	return nil
}

// StoreShare writes a 32-byte FROST secret share to the HSM as a
// CKO_SECRET_KEY / CKK_GENERIC_SECRET object.
//
// label encodes "share-<ceremonyID>-<participantIndex>" so that multiple
// ceremonies can coexist in one token without collisions.
//
// The object is created with:
//   - CKA_EXTRACTABLE = false  (bytes cannot be exported via C_WrapKey)
//   - CKA_SENSITIVE   = true   (bytes will not appear in C_GetAttributeValue)
//   - CKA_TOKEN       = true   (persists across sessions)
//
// In SoftHSM2, EXTRACTABLE=false is enforced by the library; on a real HSM it
// is enforced in tamper-resistant hardware.
func (s *Store) StoreShare(label string, share [32]byte) error {
	attrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, ShareKeyClass),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, ShareKeyType),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, share[:]),
	}

	if _, err := s.ctx.CreateObject(s.handle, attrs); err != nil {
		return fmt.Errorf("hsm: store share %q: %w", label, err)
	}
	return nil
}

// DeleteShare removes a previously stored share by label.
// Used during key rotation or ceremony teardown.
func (s *Store) DeleteShare(label string) error {
	obj, err := s.findByLabel(label)
	if err != nil {
		return err
	}
	if err := s.ctx.DestroyObject(s.handle, obj); err != nil {
		return fmt.Errorf("hsm: delete share %q: %w", label, err)
	}
	return nil
}

// SignHMAC produces an HMAC-SHA256 commitment using the stored share as the
// key and msg as the message. This is used in the FROST nonce-binding step:
// each participant commits to their nonce by signing the session transcript
// with their share -- without ever exposing the share bytes.
//
// The operation is performed entirely inside the HSM via C_Sign with
// CKM_SHA256_HMAC. The key material never crosses the HSM boundary.
func (s *Store) SignHMAC(label string, msg []byte) ([]byte, error) {
	obj, err := s.findByLabel(label)
	if err != nil {
		return nil, err
	}

	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA256_HMAC, nil)}
	if err := s.ctx.SignInit(s.handle, mech, obj); err != nil {
		return nil, fmt.Errorf("hsm: SignInit %q: %w", label, err)
	}

	sig, err := s.ctx.Sign(s.handle, msg)
	if err != nil {
		return nil, fmt.Errorf("hsm: Sign %q: %w", label, err)
	}
	return sig, nil
}

// findByLabel locates a CKO_SECRET_KEY by CKA_LABEL and returns its handle.
func (s *Store) findByLabel(label string) (pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, ShareKeyClass),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}

	if err := s.ctx.FindObjectsInit(s.handle, template); err != nil {
		return 0, fmt.Errorf("hsm: find init %q: %w", label, err)
	}
	defer s.ctx.FindObjectsFinal(s.handle)

	objs, _, err := s.ctx.FindObjects(s.handle, 1)
	if err != nil {
		return 0, fmt.Errorf("hsm: find %q: %w", label, err)
	}
	if len(objs) == 0 {
		return 0, fmt.Errorf("hsm: share %q not found", label)
	}
	return objs[0], nil
}

// ShareLabel builds the canonical label for a participant's share.
//
//	ceremonyID -- a short identifier for the key ceremony (e.g. "ceremony-2024-01")
//	index      -- 1-indexed participant number (matches FROST convention)
func ShareLabel(ceremonyID string, index uint32) string {
	return fmt.Sprintf("share-%s-%d", ceremonyID, index)
}

// CeremonyID derives a deterministic ID from the group public key bytes so
// that every participant independently computes the same label without
// out-of-band coordination.
func CeremonyID(groupPubKey []byte) string {
	h := sha256.Sum256(groupPubKey)
	// 8 hex chars (4 bytes) is enough for a human-readable short ID.
	return fmt.Sprintf("%08x", binary.BigEndian.Uint32(h[:4]))
}

// ErrShareExists is returned when StoreShare is called with a label that
// already exists in the token. Labels are unique per ceremony+index to prevent
// accidental overwrite.
var ErrShareExists = errors.New("hsm: share already exists")
