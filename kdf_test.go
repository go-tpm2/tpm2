// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/tpm2 authors. All rights reserved.

package tpm2

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"testing"

	"github.com/go-tpm2/common"
)

// TestKDFaSingleBlockConstruction pins KDFa's exact SP800-108 counter-mode
// input layout for a byte-aligned single-block (256-bit) request, derived by
// hand independent of the implementation. TCG "Part 1", "Key Derivation
// Functions" (KDFa).
func TestKDFaSingleBlockConstruction(t *testing.T) {
	key := bytes.Repeat([]byte{0x5A}, 32)
	ctxU := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	ctxV := []byte{0x01, 0x02}

	got := KDFa(key, "INTEGRITY", ctxU, ctxV, 256)

	// One HMAC block = 32 bytes = exactly 256 bits, so a single iteration.
	//   K_1 = HMAC(key, BE32(1) || "INTEGRITY" || 0x00 || ctxU || ctxV || BE32(256))
	h := hmac.New(sha256.New, key)
	h.Write([]byte{0x00, 0x00, 0x00, 0x01})    // counter
	h.Write(append([]byte("INTEGRITY"), 0x00)) // label || NUL
	h.Write(ctxU)                              // PartyUInfo
	h.Write(ctxV)                              // PartyVInfo
	h.Write([]byte{0x00, 0x00, 0x01, 0x00})    // 256 bits
	want := h.Sum(nil)

	if !bytes.Equal(got, want) {
		t.Fatalf("KDFa\n got %x\nwant %x", got, want)
	}
	if len(got) != 32 {
		t.Fatalf("len = %d, want 32", len(got))
	}
}

// TestKDFaMultiBlock checks that a request larger than one hash block runs
// multiple counter iterations and concatenates them.
func TestKDFaMultiBlock(t *testing.T) {
	key := []byte("key")
	got := KDFa(key, "STORAGE", nil, nil, 384) // 48 bytes -> 2 iterations

	var want []byte
	for ctr := uint32(1); ctr <= 2; ctr++ {
		h := hmac.New(sha256.New, key)
		h.Write(common.PutU32(nil, ctr))
		h.Write(append([]byte("STORAGE"), 0x00))
		h.Write([]byte{0x00, 0x00, 0x01, 0x80}) // 384
		want = append(want, h.Sum(nil)...)
	}
	want = want[:48]
	if !bytes.Equal(got, want) {
		t.Fatalf("KDFa multiblock\n got %x\nwant %x", got, want)
	}
}

// TestKDFaBitMasking exercises the non-byte-aligned path: the excess
// low-order bits of the final byte must be zeroed.
func TestKDFaBitMasking(t *testing.T) {
	key := []byte("k")
	got := KDFa(key, "L", nil, nil, 12) // 12 bits -> 2 bytes, low 4 bits masked
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	// Recompute the raw single block and mask its second byte's low nibble.
	h := hmac.New(sha256.New, key)
	h.Write([]byte{0x00, 0x00, 0x00, 0x01})
	h.Write([]byte{'L', 0x00})
	h.Write([]byte{0x00, 0x00, 0x00, 0x0C})
	raw := h.Sum(nil)
	want := []byte{raw[0], raw[1] & 0xF0}
	if !bytes.Equal(got, want) {
		t.Fatalf("KDFa masked\n got %x\nwant %x", got, want)
	}
}

// TestKDFeSingleBlockConstruction pins KDFe's exact SP800-56A input layout
// for a 256-bit request. TCG "Part 1", "Key Derivation Functions" (KDFe).
func TestKDFeSingleBlockConstruction(t *testing.T) {
	z := bytes.Repeat([]byte{0x11}, 32)
	u := bytes.Repeat([]byte{0x22}, 32)
	v := bytes.Repeat([]byte{0x33}, 32)

	got := KDFe(z, "IDENTITY", u, v, 256)

	//   K_1 = H(BE32(1) || Z || "IDENTITY" || 0x00 || U || V)
	h := sha256.New()
	h.Write([]byte{0x00, 0x00, 0x00, 0x01})
	h.Write(z)
	h.Write(append([]byte("IDENTITY"), 0x00))
	h.Write(u)
	h.Write(v)
	want := h.Sum(nil)

	if !bytes.Equal(got, want) {
		t.Fatalf("KDFe\n got %x\nwant %x", got, want)
	}
}

// TestKDFeMultiBlockAndMask exercises the multi-iteration and bit-mask paths
// of KDFe together.
func TestKDFeMultiBlockAndMask(t *testing.T) {
	z := []byte{0xAB}
	got := KDFe(z, "X", nil, nil, 260) // 33 bytes -> 2 iterations, last byte masked
	if len(got) != 33 {
		t.Fatalf("len = %d, want 33", len(got))
	}
	var raw []byte
	for ctr := uint32(1); ctr <= 2; ctr++ {
		h := sha256.New()
		h.Write(common.PutU32(nil, ctr))
		h.Write(z)
		h.Write([]byte{'X', 0x00})
		// KDFe (SP800-56A) has NO trailing bit-length field (unlike KDFa).
		raw = append(raw, h.Sum(nil)...)
	}
	want := append([]byte(nil), raw[:33]...)
	want[32] &= 0xF0 // 260 % 8 = 4 -> keep top 4 bits of last byte
	if !bytes.Equal(got, want) {
		t.Fatalf("KDFe multiblock+mask\n got %x\nwant %x", got, want)
	}
}

// TestLabelBytesAlreadyTerminated covers the branch where a label already
// ends in 0x00 (it must not be double-terminated).
func TestLabelBytesAlreadyTerminated(t *testing.T) {
	if got := labelBytes("AB\x00"); !bytes.Equal(got, []byte{'A', 'B', 0x00}) {
		t.Fatalf("labelBytes terminated = %x", got)
	}
	if got := labelBytes(""); !bytes.Equal(got, []byte{0x00}) {
		t.Fatalf("labelBytes empty = %x", got)
	}
}
