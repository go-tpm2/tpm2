// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/tpm2 authors. All rights reserved.

package tpm2

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/go-tpm2/common"
)

func TestFlushContextRequestBytes(t *testing.T) {
	ft := &fakeTransport{rsp: noSessOK(nil)}
	if err := New(ft).FlushContext(0x80000001); err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0x80, 0x01, // TagNoSessions
		0x00, 0x00, 0x00, 0x0E, // commandSize
		0x00, 0x00, 0x01, 0x65, // TPM2_FlushContext
		0x80, 0x00, 0x00, 0x01, // flushHandle
	}
	if !bytes.Equal(ft.gotCmd, want) {
		t.Fatalf("FlushContext request\n got %x\nwant %x", ft.gotCmd, want)
	}
}

func TestEKNameIsTheHashOfTheFilledTemplate(t *testing.T) {
	x := bytes.Repeat([]byte{0x11}, 32)
	y := bytes.Repeat([]byte{0x22}, 32)
	got, err := EKName(EKPublic{X: x, Y: y})
	if err != nil {
		t.Fatal(err)
	}
	// Hand-derived: the template of ekTemplateInner with its two empty
	// unique fields replaced by the 32-byte coordinates.
	inner := ekTemplateInner()
	inner = inner[:len(inner)-4]
	inner = append(inner, common.MarshalTPM2B(x)...)
	inner = append(inner, common.MarshalTPM2B(y)...)
	d := sha256.Sum256(inner)
	want := append([]byte{0x00, 0x0B}, d[:]...)
	if !bytes.Equal(got, want) || len(got) != 34 {
		t.Fatalf("EKName %x, want %x", got, want)
	}
	// A different point is a different name.
	other, _ := EKName(EKPublic{X: x, Y: bytes.Repeat([]byte{0x23}, 32)})
	if bytes.Equal(other, got) {
		t.Fatal("two points, one name")
	}
}

func TestEKNameRefusesAnOversizedPoint(t *testing.T) {
	big := make([]byte, 33)
	for _, p := range []EKPublic{{X: big, Y: nil}, {X: nil, Y: big}} {
		if _, err := EKName(p); !errors.Is(err, ErrEKPoint) {
			t.Fatalf("EKName(%d,%d bytes): %v", len(p.X), len(p.Y), err)
		}
	}
}

func TestEKIdentityCreatesThenFlushes(t *testing.T) {
	x := bytes.Repeat([]byte{0xAA}, 32)
	y := bytes.Repeat([]byte{0xBB}, 32)
	st := &seqTransport{rsps: [][]byte{ekResp(0x80000000, x, y), noSessOK(nil)}}
	name, err := New(st).EKIdentity()
	if err != nil {
		t.Fatal(err)
	}
	want, _ := EKName(EKPublic{X: x, Y: y})
	if !bytes.Equal(name, want) {
		t.Fatalf("name %x, want %x", name, want)
	}
	if len(st.cmds) != 2 {
		t.Fatalf("%d commands, want CreatePrimary then FlushContext", len(st.cmds))
	}
	// The flush names the handle CreatePrimary returned.
	if !bytes.Equal(st.cmds[1][10:], []byte{0x80, 0x00, 0x00, 0x00}) {
		t.Fatalf("flush request %x", st.cmds[1])
	}
}

func TestEKIdentityErrors(t *testing.T) {
	x := bytes.Repeat([]byte{0xAA}, 32)
	y := bytes.Repeat([]byte{0xBB}, 32)
	boom := errors.New("bus")

	// CreatePrimary fails: nothing to flush, one command.
	st := &seqTransport{rsps: [][]byte{nil}, err: boom, errAt: 0}
	if _, err := New(st).EKIdentity(); !errors.Is(err, boom) || len(st.cmds) != 1 {
		t.Fatalf("create failure: %v after %d commands", err, len(st.cmds))
	}
	// The flush fails: reported, with a good name not returned as a success.
	st = &seqTransport{rsps: [][]byte{ekResp(0x80000000, x, y), nil}, err: boom, errAt: 1}
	if _, err := New(st).EKIdentity(); !errors.Is(err, boom) {
		t.Fatalf("flush failure: %v", err)
	}
	// An oversized point: refused, and the key is still flushed.
	st = &seqTransport{rsps: [][]byte{ekResp(0x80000000, make([]byte, 33), y), noSessOK(nil)}}
	if _, err := New(st).EKIdentity(); !errors.Is(err, ErrEKPoint) {
		t.Fatalf("oversized point: %v", err)
	}
	if len(st.cmds) != 2 {
		t.Fatalf("an oversized point left the key loaded: %d commands", len(st.cmds))
	}
}
