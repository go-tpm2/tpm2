// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/tpm2 authors. All rights reserved.

package tpm2

import (
	"bytes"
	"errors"
	"testing"

	"github.com/go-tpm2/common"
)

// failedTries reads TPM_PT_LOCKOUT_COUNTER.
func failedTries(t *testing.T, tpm *TPM) uint32 {
	t.Helper()
	props, err := tpm.GetTPMProperties(PTLockoutCounter, 1)
	if err != nil || len(props) != 1 || props[0].Property != PTLockoutCounter {
		t.Fatalf("lockout counter: %v %v", props, err)
	}
	return props[0].Value
}

// An endorsement password: the EK is made with it and only with it, and a
// wrong one is TPM_RC_BAD_AUTH that does not count toward the DA lockout (TCG
// Part 1 rev 1.59, 19.8.1: a permanent entity other than lockoutAuth is not DA
// protected).
func TestSwtpmEKAuth(t *testing.T) {
	tpm := startSwtpm(t)
	empty, err := tpm.EKIdentity()
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("endorsement-secret")
	if err := tpm.HierarchyChangeAuth(RHEndorsement, nil, secret); err != nil {
		t.Fatal(err)
	}
	before := failedTries(t, tpm)

	for name, fn := range map[string]func() error{
		"empty":     func() error { _, err := tpm.EKIdentity(); return err },
		"wrong":     func() error { _, err := tpm.EKIdentityAuth([]byte("wrong")); return err },
		"wrong-key": func() error { _, _, err := tpm.CreateEKAuth([]byte("wrong")); return err },
	} {
		rc := rcOf(fn())
		// Format one, TPM_RC_BAD_AUTH (0x22) plus the session number (here 0
		// after the handle area: 0x0A2 | N<<8 with N = 1 for session 1).
		if rc&0x80 == 0 || rc&0x3F != 0x22 {
			t.Fatalf("%s: rc %#x, want TPM_RC_BAD_AUTH", name, rc)
		}
	}
	if after := failedTries(t, tpm); after != before {
		t.Fatalf("failedTries %d -> %d: a wrong endorsement auth counted toward the lockout", before, after)
	}

	got, err := tpm.EKIdentityAuth(secret)
	if err != nil || !bytes.Equal(got, empty) {
		t.Fatalf("with the right auth: %x (%v), want the same identity %x", got, err, empty)
	}
	// Back to empty: the old path works again.
	if err := tpm.HierarchyChangeAuth(RHEndorsement, secret, nil); err != nil {
		t.Fatal(err)
	}
	if got, err := tpm.EKIdentity(); err != nil || !bytes.Equal(got, empty) {
		t.Fatalf("after clearing: %x (%v)", got, err)
	}
}

func TestHierarchyChangeAuthBytes(t *testing.T) {
	ft := &fakeTransport{rsp: sessOK(nil)}
	sent := func() []byte { return ft.gotCmd }
	tpm := New(ft)
	if err := tpm.HierarchyChangeAuth(RHEndorsement, []byte("a"), []byte("bc")); err != nil {
		t.Fatal(err)
	}
	var body []byte
	body = common.PutU32(body, RHEndorsement)
	auth := marshalAuth([]byte("a"))
	body = common.PutU32(body, uint32(len(auth)))
	body = append(body, auth...)
	body = append(body, common.MarshalTPM2B([]byte("bc"))...)
	want := common.BuildCommand(uint16(common.TagSessions), uint32(ccHierarchyChangeAuth), body)
	if !bytes.Equal(sent(), want) {
		t.Fatalf("sent %x, want %x", sent(), want)
	}
	if err := New(&fakeTransport{err: errors.New("boom")}).HierarchyChangeAuth(RHOwner, nil, nil); err == nil {
		t.Fatal("want transport error")
	}
}
