// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/tpm2 authors. All rights reserved.

package tpm2

import (
	"bytes"
	"testing"

	"github.com/go-tpm2/common"
)

// tpmReportedName reads the Name the TPM put at the end of a CreatePrimary
// response: handle, parameterSize, outPublic, creationData, creationHash,
// creationTicket (tag, hierarchy, digest), name.
func tpmReportedName(t *testing.T, rp []byte) []byte {
	t.Helper()
	// header (10) || handle (4) || parameterSize (4)
	rest := rp[10+8:]
	var err error
	for i := 0; i < 3; i++ { // outPublic, creationData, creationHash
		if _, rest, err = common.UnmarshalTPM2B(rest); err != nil {
			t.Fatal(err)
		}
	}
	rest = rest[2+4:] // creationTicket tag, hierarchy
	if _, rest, err = common.UnmarshalTPM2B(rest); err != nil {
		t.Fatal(err)
	}
	name, _, err := common.UnmarshalTPM2B(rest)
	if err != nil {
		t.Fatal(err)
	}
	return name
}

func TestSwtpmEKIdentity(t *testing.T) {
	tpm, rec := startSwtpmRec(t)

	// EKName, computed from the public point, is the Name the TPM reports.
	h, pub, err := tpm.CreateEK()
	if err != nil {
		t.Fatal(err)
	}
	reported := tpmReportedName(t, rec.last)
	computed, err := EKName(pub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reported, computed) || len(computed) != 34 {
		t.Fatalf("computed EK name %x, the TPM reports %x", computed, reported)
	}
	if err := tpm.FlushContext(h); err != nil {
		t.Fatal(err)
	}
	// Flushed means gone: a second flush is TPM_RC_HANDLE.
	if err := tpm.FlushContext(h); rcOf(err)&0x3F != 0x0B {
		t.Fatalf("second flush: %v", err)
	}

	// The identity is stable, and leaves nothing loaded: swtpm has room for a
	// handful of transient objects, so ten calls would fail on a leak.
	first, err := tpm.EKIdentity()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		again, err := tpm.EKIdentity()
		if err != nil || !bytes.Equal(again, first) {
			t.Fatalf("call %d: %x (%v), want %x", i, again, err, first)
		}
	}
	if !bytes.Equal(first, computed) {
		t.Fatalf("EKIdentity %x differs from the name of CreateEK %x", first, computed)
	}
	// The control: without the flush the table fills up. If this stops
	// failing, the loop above no longer shows that EKIdentity flushes.
	var full error
	for i := 0; i < 10 && full == nil; i++ {
		_, _, full = tpm.CreateEK()
	}
	if full == nil {
		t.Fatal("ten unflushed EKs fit: the leak check above proves nothing")
	}
}

// Two software TPMs are two EKs: the property theca#39 relies on.
func TestSwtpmTwoTPMsTwoIdentities(t *testing.T) {
	a, b := startSwtpm(t), startSwtpm(t)
	na, err := a.EKIdentity()
	if err != nil {
		t.Fatal(err)
	}
	nb, err := b.EKIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(na, nb) {
		t.Fatalf("two TPMs, one identity %x", na)
	}
}
