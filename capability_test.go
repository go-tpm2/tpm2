// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/tpm2 authors. All rights reserved.

package tpm2

import (
	"bytes"
	"errors"
	"testing"

	"github.com/go-tpm2/common"
)

// capData wraps a union member as a TPMS_CAPABILITY_DATA reply for the given
// capability: moreData(0) || capability(u32) || member.
func capData(capSel uint32, member []byte) []byte {
	out := []byte{0x00} // moreData = NO
	out = common.PutU32(out, capSel)
	out = append(out, member...)
	return noSessOK(out)
}

// --- getCapabilityData request bytes (hand-derived) via a typed decoder ---

func TestGetCapabilityRequestBytes(t *testing.T) {
	// TPM_CAP_TPM_PROPERTIES at PT_MANUFACTURER, count 1; member = empty list.
	member := []byte{0x00, 0x00, 0x00, 0x00} // count 0
	ft := &fakeTransport{rsp: capData(capTPMProperties, member)}
	tpm := New(ft)
	if _, err := tpm.GetTPMProperties(PTManufacturer, 1); err != nil {
		t.Fatalf("GetTPMProperties: %v", err)
	}
	wantBody := concat(
		[]byte{0x00, 0x00, 0x00, 0x06}, // TPM_CAP_TPM_PROPERTIES
		[]byte{0x00, 0x00, 0x01, 0x05}, // property = PT_MANUFACTURER (0x100+5)
		[]byte{0x00, 0x00, 0x00, 0x01}, // count = 1
	)
	want := common.BuildCommand(uint16(common.TagNoSessions), uint32(common.CCGetCapability), wantBody)
	if !bytes.Equal(ft.gotCmd, want) {
		t.Fatalf("GetCapability request bytes\n got %x\nwant %x", ft.gotCmd, want)
	}
}

// --- PCR banks ---

func TestGetPCRBanks(t *testing.T) {
	// One bank: SHA256, sizeofSelect 3, all of PCR[0..23] implemented.
	member := concat(
		[]byte{0x00, 0x00, 0x00, 0x01}, // count = 1
		[]byte{0x00, 0x0B},             // hash = SHA256
		[]byte{0x03},                   // sizeofSelect = 3
		[]byte{0xFF, 0xFF, 0xFF},       // all 24 PCRs present
	)
	ft := &fakeTransport{rsp: capData(capPCRs, member)}
	tpm := New(ft)
	banks, err := tpm.GetPCRBanks()
	if err != nil {
		t.Fatalf("GetPCRBanks: %v", err)
	}
	if len(banks) != 1 || banks[0].Hash != algSHA256 || len(banks[0].PCRs) != 24 {
		t.Fatalf("GetPCRBanks = %+v", banks)
	}
}

func TestGetPCRBanksError(t *testing.T) {
	ft := &fakeTransport{err: errors.New("boom")}
	tpm := New(ft)
	if _, err := tpm.GetPCRBanks(); err == nil {
		t.Fatal("GetPCRBanks: want transport error")
	}
}

func TestGetPCRBanksBadList(t *testing.T) {
	// count claims 1 bank but the selection is truncated.
	member := []byte{0x00, 0x00, 0x00, 0x01}
	ft := &fakeTransport{rsp: capData(capPCRs, member)}
	tpm := New(ft)
	if _, err := tpm.GetPCRBanks(); err == nil {
		t.Fatal("GetPCRBanks bad list: want error")
	}
}

// --- TPM properties ---

func TestGetTPMProperties(t *testing.T) {
	member := concat(
		[]byte{0x00, 0x00, 0x00, 0x02}, // count = 2
		[]byte{0x00, 0x00, 0x01, 0x05}, // PT_MANUFACTURER
		[]byte{0x49, 0x42, 0x4D, 0x00}, // value "IBM\0"
		[]byte{0x00, 0x00, 0x01, 0x00}, // PT_FIXED group base
		[]byte{0x00, 0x00, 0x00, 0x2A}, // value 42
	)
	ft := &fakeTransport{rsp: capData(capTPMProperties, member)}
	tpm := New(ft)
	props, err := tpm.GetTPMProperties(PTFixed, 2)
	if err != nil {
		t.Fatalf("GetTPMProperties: %v", err)
	}
	if len(props) != 2 ||
		props[0].Property != PTManufacturer || props[0].Value != 0x49424D00 ||
		props[1].Property != PTFixed || props[1].Value != 42 {
		t.Fatalf("GetTPMProperties = %+v", props)
	}
}

func TestGetTPMPropertiesError(t *testing.T) {
	ft := &fakeTransport{err: errors.New("boom")}
	tpm := New(ft)
	if _, err := tpm.GetTPMProperties(PTFixed, 1); err == nil {
		t.Fatal("GetTPMProperties: want transport error")
	}
}

func TestGetTPMPropertiesShortCount(t *testing.T) {
	ft := &fakeTransport{rsp: capData(capTPMProperties, []byte{0x00})}
	tpm := New(ft)
	if _, err := tpm.GetTPMProperties(PTFixed, 1); err != common.ErrShortBuffer {
		t.Fatalf("GetTPMProperties short count: got %v", err)
	}
}

func TestGetTPMPropertiesShortProperty(t *testing.T) {
	// count=1 but no room for the property tag.
	member := concat([]byte{0x00, 0x00, 0x00, 0x01}, []byte{0x00, 0x00})
	ft := &fakeTransport{rsp: capData(capTPMProperties, member)}
	tpm := New(ft)
	if _, err := tpm.GetTPMProperties(PTFixed, 1); err != common.ErrShortBuffer {
		t.Fatalf("GetTPMProperties short property: got %v", err)
	}
}

func TestGetTPMPropertiesShortValue(t *testing.T) {
	// count=1, property present, value truncated.
	member := concat(
		[]byte{0x00, 0x00, 0x00, 0x01},
		[]byte{0x00, 0x00, 0x01, 0x05},
		[]byte{0x00, 0x00}, // half a value
	)
	ft := &fakeTransport{rsp: capData(capTPMProperties, member)}
	tpm := New(ft)
	if _, err := tpm.GetTPMProperties(PTFixed, 1); err != common.ErrShortBuffer {
		t.Fatalf("GetTPMProperties short value: got %v", err)
	}
}

// --- Manufacturer convenience ---

func TestGetManufacturer(t *testing.T) {
	member := concat(
		[]byte{0x00, 0x00, 0x00, 0x01},
		[]byte{0x00, 0x00, 0x01, 0x05}, // PT_MANUFACTURER
		[]byte{0x49, 0x42, 0x4D, 0x00}, // "IBM\0"
	)
	ft := &fakeTransport{rsp: capData(capTPMProperties, member)}
	tpm := New(ft)
	v, err := tpm.GetManufacturer()
	if err != nil {
		t.Fatalf("GetManufacturer: %v", err)
	}
	if v != 0x49424D00 {
		t.Fatalf("GetManufacturer = %#x", v)
	}
}

func TestGetManufacturerError(t *testing.T) {
	ft := &fakeTransport{err: errors.New("boom")}
	tpm := New(ft)
	if _, err := tpm.GetManufacturer(); err == nil {
		t.Fatal("GetManufacturer: want transport error")
	}
}

func TestGetManufacturerNotFound(t *testing.T) {
	// Empty property list -> ErrPropertyNotFound.
	ft := &fakeTransport{rsp: capData(capTPMProperties, []byte{0x00, 0x00, 0x00, 0x00})}
	tpm := New(ft)
	if _, err := tpm.GetManufacturer(); err != ErrPropertyNotFound {
		t.Fatalf("GetManufacturer not found: got %v", err)
	}
}

func TestGetManufacturerWrongProperty(t *testing.T) {
	// A property is returned but it is not PT_MANUFACTURER.
	member := concat(
		[]byte{0x00, 0x00, 0x00, 0x01},
		[]byte{0x00, 0x00, 0x01, 0x00}, // PT_FIXED, not MANUFACTURER
		[]byte{0x00, 0x00, 0x00, 0x01},
	)
	ft := &fakeTransport{rsp: capData(capTPMProperties, member)}
	tpm := New(ft)
	if _, err := tpm.GetManufacturer(); err != ErrPropertyNotFound {
		t.Fatalf("GetManufacturer wrong property: got %v", err)
	}
}

// --- Algorithms ---

func TestGetAlgorithms(t *testing.T) {
	member := concat(
		[]byte{0x00, 0x00, 0x00, 0x02}, // count = 2
		[]byte{0x00, 0x0B},             // SHA256
		[]byte{0x00, 0x00, 0x00, 0x04}, // attrs (hash bit)
		[]byte{0x00, 0x23},             // ECC
		[]byte{0x00, 0x00, 0x00, 0x01}, // attrs (asymmetric)
	)
	ft := &fakeTransport{rsp: capData(capAlgs, member)}
	tpm := New(ft)
	algs, err := tpm.GetAlgorithms(0, 2)
	if err != nil {
		t.Fatalf("GetAlgorithms: %v", err)
	}
	if len(algs) != 2 || algs[0].Alg != algSHA256 || algs[1].Alg != AlgECC ||
		algs[1].Attributes != 1 {
		t.Fatalf("GetAlgorithms = %+v", algs)
	}
}

func TestGetAlgorithmsError(t *testing.T) {
	ft := &fakeTransport{err: errors.New("boom")}
	tpm := New(ft)
	if _, err := tpm.GetAlgorithms(0, 1); err == nil {
		t.Fatal("GetAlgorithms: want transport error")
	}
}

func TestGetAlgorithmsShortCount(t *testing.T) {
	ft := &fakeTransport{rsp: capData(capAlgs, []byte{0x00})}
	tpm := New(ft)
	if _, err := tpm.GetAlgorithms(0, 1); err != common.ErrShortBuffer {
		t.Fatalf("GetAlgorithms short count: got %v", err)
	}
}

func TestGetAlgorithmsShortAlg(t *testing.T) {
	member := concat([]byte{0x00, 0x00, 0x00, 0x01}, []byte{0x00}) // count 1, half alg
	ft := &fakeTransport{rsp: capData(capAlgs, member)}
	tpm := New(ft)
	if _, err := tpm.GetAlgorithms(0, 1); err != common.ErrShortBuffer {
		t.Fatalf("GetAlgorithms short alg: got %v", err)
	}
}

func TestGetAlgorithmsShortAttrs(t *testing.T) {
	member := concat([]byte{0x00, 0x00, 0x00, 0x01}, []byte{0x00, 0x0B}, []byte{0x00})
	ft := &fakeTransport{rsp: capData(capAlgs, member)}
	tpm := New(ft)
	if _, err := tpm.GetAlgorithms(0, 1); err != common.ErrShortBuffer {
		t.Fatalf("GetAlgorithms short attrs: got %v", err)
	}
}

// --- Handles ---

func TestGetHandles(t *testing.T) {
	member := concat(
		[]byte{0x00, 0x00, 0x00, 0x02}, // count = 2
		[]byte{0x81, 0x00, 0x00, 0x01}, // persistent handle
		[]byte{0x81, 0x00, 0x00, 0x02},
	)
	ft := &fakeTransport{rsp: capData(capHandles, member)}
	tpm := New(ft)
	hs, err := tpm.GetHandles(0x81000000, 2)
	if err != nil {
		t.Fatalf("GetHandles: %v", err)
	}
	if len(hs) != 2 || hs[0] != 0x81000001 || hs[1] != 0x81000002 {
		t.Fatalf("GetHandles = %#x", hs)
	}
}

func TestGetHandlesError(t *testing.T) {
	ft := &fakeTransport{err: errors.New("boom")}
	tpm := New(ft)
	if _, err := tpm.GetHandles(0x80000000, 1); err == nil {
		t.Fatal("GetHandles: want transport error")
	}
}

func TestGetHandlesShortCount(t *testing.T) {
	ft := &fakeTransport{rsp: capData(capHandles, []byte{0x00})}
	tpm := New(ft)
	if _, err := tpm.GetHandles(0x80000000, 1); err != common.ErrShortBuffer {
		t.Fatalf("GetHandles short count: got %v", err)
	}
}

func TestGetHandlesShortHandle(t *testing.T) {
	member := concat([]byte{0x00, 0x00, 0x00, 0x01}, []byte{0x81, 0x00}) // count 1, half handle
	ft := &fakeTransport{rsp: capData(capHandles, member)}
	tpm := New(ft)
	if _, err := tpm.GetHandles(0x80000000, 1); err != common.ErrShortBuffer {
		t.Fatalf("GetHandles short handle: got %v", err)
	}
}

// --- getCapabilityData boundary errors ---

func TestGetCapabilityDataShortEcho(t *testing.T) {
	// moreData present but no full capability u32 after it.
	ft := &fakeTransport{rsp: noSessOK([]byte{0x00, 0x00})}
	tpm := New(ft)
	if _, err := tpm.GetPCRBanks(); err != common.ErrShortBuffer {
		t.Fatalf("getCapabilityData short echo: got %v", err)
	}
}

func TestGetCapabilityDataWrongCapability(t *testing.T) {
	// The TPM echoes a different capability selector than requested.
	ft := &fakeTransport{rsp: capData(capAlgs, []byte{0x00, 0x00, 0x00, 0x00})}
	tpm := New(ft)
	if _, err := tpm.GetPCRBanks(); err != ErrUnexpectedCapability {
		t.Fatalf("getCapabilityData wrong capability: got %v", err)
	}
}

func TestGetCapabilityRawError(t *testing.T) {
	// GetCapability response with missing moreData flag -> ErrShortBuffer
	// surfaced from the raw layer through getCapabilityData.
	ft := &fakeTransport{rsp: noSessOK(nil)}
	tpm := New(ft)
	if _, err := tpm.GetPCRBanks(); err != common.ErrShortBuffer {
		t.Fatalf("GetCapability raw short: got %v", err)
	}
}
