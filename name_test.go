// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/tpm2 authors. All rights reserved.

package tpm2

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// TestObjectNameConstruction pins Name = nameAlg || H(TPMT_PUBLIC), derived
// by hand. TCG "Part 1", "Names".
func TestObjectNameConstruction(t *testing.T) {
	// A minimal well-formed public area: type=ECC(0023) nameAlg=SHA256(000B)
	// then arbitrary trailing bytes (the whole area is hashed regardless).
	pub := []byte{0x00, 0x23, 0x00, 0x0B, 0xDE, 0xAD, 0xBE, 0xEF}

	got, err := ObjectName(pub)
	if err != nil {
		t.Fatalf("ObjectName: %v", err)
	}
	d := sha256.Sum256(pub)
	want := append([]byte{0x00, 0x0B}, d[:]...)
	if !bytes.Equal(got, want) {
		t.Fatalf("ObjectName\n got %x\nwant %x", got, want)
	}
	if len(got) != 2+32 {
		t.Fatalf("len = %d, want 34", len(got))
	}
}

// TestObjectNameShortBuffer covers the too-short public area branch.
func TestObjectNameShortBuffer(t *testing.T) {
	if _, err := ObjectName([]byte{0x00, 0x23, 0x00}); err == nil {
		t.Fatalf("expected error for short public area")
	}
}

// TestObjectNameUnsupportedNameAlg covers the non-SHA256 nameAlg branch.
func TestObjectNameUnsupportedNameAlg(t *testing.T) {
	pub := []byte{0x00, 0x23, 0x00, 0x0C, 0x00} // nameAlg = SHA384 (000C)
	if _, err := ObjectName(pub); err != ErrUnsupportedNameAlg {
		t.Fatalf("err = %v, want ErrUnsupportedNameAlg", err)
	}
}
