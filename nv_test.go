// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/tpm2 authors. All rights reserved.

package tpm2

import (
	"bytes"
	"errors"
	"testing"

	"github.com/go-tpm2/common"
)

// nvIndex is the validation index handle (TPM_HT_NV_INDEX range).
const testNVIndex uint32 = 0x01500000

// --- NV_DefineSpace request bytes (hand-derived) ---

func TestNVDefineSpaceRequestBytes(t *testing.T) {
	ft := &fakeTransport{rsp: sessOK(nil)}
	tpm := New(ft)
	pub := NVPublic{
		Index:      testNVIndex,
		NameAlg:    algSHA256,
		Attributes: nvOrdinaryAttributes,
		AuthPolicy: nil,
		DataSize:   32,
	}
	if err := tpm.NVDefineSpace(pub); err != nil {
		t.Fatalf("NVDefineSpace: %v", err)
	}
	// Hand-derived body:
	//   authHandle        = 0x40000001 (TPM_RH_OWNER)
	//   authSize          = 0x00000009
	//   auth (RS_PW)      = 40000009 0000 01 0000
	//   inSensitive auth  = 0x0000 (empty TPM2B_AUTH)
	//   TPM2B_NV_PUBLIC   = size 0x000E ||
	//        nvIndex 0x01500000 | nameAlg 0x000B | attrs 0x00060006 |
	//        authPolicy 0x0000 | dataSize 0x0020
	//   inner TPMS_NV_PUBLIC = 4+2+4+2+2 = 14 (0x0E) bytes.
	wantBody := concat(
		[]byte{0x40, 0x00, 0x00, 0x01}, // authHandle = RH_OWNER
		[]byte{0x00, 0x00, 0x00, 0x09}, // authorizationSize
		rsPWAuth(),                     // TPMS_AUTH_COMMAND
		[]byte{0x00, 0x00},             // inSensitive: empty TPM2B_AUTH
		[]byte{0x00, 0x0E},             // TPM2B_NV_PUBLIC size = 14
		[]byte{0x01, 0x50, 0x00, 0x00}, // nvIndex
		[]byte{0x00, 0x0B},             // nameAlg = SHA256
		[]byte{0x00, 0x06, 0x00, 0x06}, // attributes = 0x00060006
		[]byte{0x00, 0x00},             // authPolicy: empty
		[]byte{0x00, 0x20},             // dataSize = 32
	)
	want := common.BuildCommand(uint16(common.TagSessions), uint32(ccNVDefineSpace), wantBody)
	if !bytes.Equal(ft.gotCmd, want) {
		t.Fatalf("NVDefineSpace request bytes\n got %x\nwant %x", ft.gotCmd, want)
	}
}

func TestNVDefineSpaceError(t *testing.T) {
	ft := &fakeTransport{err: errors.New("boom")}
	tpm := New(ft)
	if err := tpm.NVDefineSpace(NVPublic{}); err == nil {
		t.Fatal("NVDefineSpace: want transport error")
	}
}

// --- NV_UndefineSpace ---

func TestNVUndefineSpaceRequestBytes(t *testing.T) {
	ft := &fakeTransport{rsp: sessOK(nil)}
	tpm := New(ft)
	if err := tpm.NVUndefineSpace(testNVIndex); err != nil {
		t.Fatalf("NVUndefineSpace: %v", err)
	}
	wantBody := concat(
		[]byte{0x40, 0x00, 0x00, 0x01}, // authHandle = RH_OWNER
		[]byte{0x01, 0x50, 0x00, 0x00}, // nvIndex
		[]byte{0x00, 0x00, 0x00, 0x09}, // authorizationSize
		rsPWAuth(),
	)
	want := common.BuildCommand(uint16(common.TagSessions), uint32(ccNVUndefineSpace), wantBody)
	if !bytes.Equal(ft.gotCmd, want) {
		t.Fatalf("NVUndefineSpace request bytes\n got %x\nwant %x", ft.gotCmd, want)
	}
}

func TestNVUndefineSpaceError(t *testing.T) {
	ft := &fakeTransport{err: errors.New("boom")}
	tpm := New(ft)
	if err := tpm.NVUndefineSpace(testNVIndex); err == nil {
		t.Fatal("NVUndefineSpace: want transport error")
	}
}

// --- NV_Write ---

func TestNVWriteRequestBytes(t *testing.T) {
	ft := &fakeTransport{rsp: sessOK(nil)}
	tpm := New(ft)
	data := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	if err := tpm.NVWrite(testNVIndex, data, 0); err != nil {
		t.Fatalf("NVWrite: %v", err)
	}
	wantBody := concat(
		[]byte{0x40, 0x00, 0x00, 0x01}, // authHandle = RH_OWNER
		[]byte{0x01, 0x50, 0x00, 0x00}, // nvIndex
		[]byte{0x00, 0x00, 0x00, 0x09}, // authorizationSize
		rsPWAuth(),
		[]byte{0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD}, // TPM2B_MAX_NV_BUFFER data
		[]byte{0x00, 0x00},                         // offset
	)
	want := common.BuildCommand(uint16(common.TagSessions), uint32(ccNVWrite), wantBody)
	if !bytes.Equal(ft.gotCmd, want) {
		t.Fatalf("NVWrite request bytes\n got %x\nwant %x", ft.gotCmd, want)
	}
}

func TestNVWriteError(t *testing.T) {
	ft := &fakeTransport{err: errors.New("boom")}
	tpm := New(ft)
	if err := tpm.NVWrite(testNVIndex, []byte{1}, 0); err == nil {
		t.Fatal("NVWrite: want transport error")
	}
}

// --- NV_Read ---

func TestNVReadRequestAndDecode(t *testing.T) {
	data := []byte{0x11, 0x22, 0x33, 0x44}
	// Response (TagSessions): parameterSize (u32) || TPM2B_MAX_NV_BUFFER data.
	params := concat(
		[]byte{0x00, 0x00, 0x00, 0x06}, // parameterSize
		common.MarshalTPM2B(data),      // data
	)
	ft := &fakeTransport{rsp: sessOK(params)}
	tpm := New(ft)
	got, err := tpm.NVRead(testNVIndex, 4, 0)
	if err != nil {
		t.Fatalf("NVRead: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("NVRead data = %x, want %x", got, data)
	}
	wantBody := concat(
		[]byte{0x40, 0x00, 0x00, 0x01}, // authHandle = RH_OWNER
		[]byte{0x01, 0x50, 0x00, 0x00}, // nvIndex
		[]byte{0x00, 0x00, 0x00, 0x09}, // authorizationSize
		rsPWAuth(),
		[]byte{0x00, 0x04}, // size = 4
		[]byte{0x00, 0x00}, // offset = 0
	)
	want := common.BuildCommand(uint16(common.TagSessions), uint32(ccNVRead), wantBody)
	if !bytes.Equal(ft.gotCmd, want) {
		t.Fatalf("NVRead request bytes\n got %x\nwant %x", ft.gotCmd, want)
	}
}

func TestNVReadError(t *testing.T) {
	ft := &fakeTransport{err: errors.New("boom")}
	tpm := New(ft)
	if _, err := tpm.NVRead(testNVIndex, 4, 0); err == nil {
		t.Fatal("NVRead: want transport error")
	}
}

func TestNVReadShortParameterSize(t *testing.T) {
	// Response too short to hold the parameterSize u32.
	ft := &fakeTransport{rsp: sessOK([]byte{0x00, 0x00})}
	tpm := New(ft)
	if _, err := tpm.NVRead(testNVIndex, 4, 0); err != common.ErrShortBuffer {
		t.Fatalf("NVRead short paramSize: got %v, want ErrShortBuffer", err)
	}
}

func TestNVReadShortData(t *testing.T) {
	// parameterSize present but the TPM2B data size overruns the buffer.
	params := concat(
		[]byte{0x00, 0x00, 0x00, 0x02}, // parameterSize
		[]byte{0x00, 0x10},             // TPM2B size = 16 with no payload
	)
	ft := &fakeTransport{rsp: sessOK(params)}
	tpm := New(ft)
	if _, err := tpm.NVRead(testNVIndex, 4, 0); err == nil {
		t.Fatal("NVRead short data: want error")
	}
}

// --- NV_ReadPublic ---

func TestNVReadPublicRequestAndDecode(t *testing.T) {
	// Build a realistic response: TPM2B_NV_PUBLIC || TPM2B_NAME.
	innerPub := concat(
		[]byte{0x01, 0x50, 0x00, 0x00}, // nvIndex
		[]byte{0x00, 0x0B},             // nameAlg = SHA256
		[]byte{0x00, 0x06, 0x00, 0x06}, // attributes
		[]byte{0x00, 0x00},             // authPolicy: empty
		[]byte{0x00, 0x20},             // dataSize = 32
	)
	name := []byte{0x00, 0x0B, 0xAA, 0xBB} // a TPM2B_NAME payload
	params := concat(
		common.MarshalTPM2B(innerPub),
		common.MarshalTPM2B(name),
	)
	ft := &fakeTransport{rsp: noSessOK(params)}
	tpm := New(ft)
	pub, gotName, err := tpm.NVReadPublic(testNVIndex)
	if err != nil {
		t.Fatalf("NVReadPublic: %v", err)
	}
	if pub.Index != testNVIndex || pub.NameAlg != algSHA256 ||
		pub.Attributes != nvOrdinaryAttributes || pub.DataSize != 32 ||
		len(pub.AuthPolicy) != 0 {
		t.Fatalf("NVReadPublic decoded = %+v", pub)
	}
	if !bytes.Equal(gotName, name) {
		t.Fatalf("NVReadPublic name = %x, want %x", gotName, name)
	}
	// Request: TagNoSessions, just the nvIndex.
	want := common.BuildCommand(uint16(common.TagNoSessions), uint32(ccNVReadPublic),
		[]byte{0x01, 0x50, 0x00, 0x00})
	if !bytes.Equal(ft.gotCmd, want) {
		t.Fatalf("NVReadPublic request bytes\n got %x\nwant %x", ft.gotCmd, want)
	}
}

func TestNVReadPublicError(t *testing.T) {
	ft := &fakeTransport{err: errors.New("boom")}
	tpm := New(ft)
	if _, _, err := tpm.NVReadPublic(testNVIndex); err == nil {
		t.Fatal("NVReadPublic: want transport error")
	}
}

func TestNVReadPublicShortPublic(t *testing.T) {
	// TPM2B_NV_PUBLIC size overruns the buffer.
	ft := &fakeTransport{rsp: noSessOK([]byte{0x00, 0x40})}
	tpm := New(ft)
	if _, _, err := tpm.NVReadPublic(testNVIndex); err == nil {
		t.Fatal("NVReadPublic short public: want error")
	}
}

func TestNVReadPublicBadInnerPublic(t *testing.T) {
	// A TPM2B_NV_PUBLIC whose inner bytes are too short to be a TPMS_NV_PUBLIC.
	params := common.MarshalTPM2B([]byte{0x01, 0x50}) // 2-byte inner, truncated
	ft := &fakeTransport{rsp: noSessOK(params)}
	tpm := New(ft)
	if _, _, err := tpm.NVReadPublic(testNVIndex); err == nil {
		t.Fatal("NVReadPublic bad inner public: want error")
	}
}

func TestNVReadPublicShortName(t *testing.T) {
	innerPub := concat(
		[]byte{0x01, 0x50, 0x00, 0x00},
		[]byte{0x00, 0x0B},
		[]byte{0x00, 0x06, 0x00, 0x06},
		[]byte{0x00, 0x00},
		[]byte{0x00, 0x20},
	)
	params := concat(
		common.MarshalTPM2B(innerPub),
		[]byte{0x00, 0x40}, // TPM2B_NAME size 64 with no payload
	)
	ft := &fakeTransport{rsp: noSessOK(params)}
	tpm := New(ft)
	if _, _, err := tpm.NVReadPublic(testNVIndex); err == nil {
		t.Fatal("NVReadPublic short name: want error")
	}
}

// --- parseNVPublic direct error branches not reachable via the wrapper ---

func TestParseNVPublicErrors(t *testing.T) {
	full := concat(
		[]byte{0x01, 0x50, 0x00, 0x00},
		[]byte{0x00, 0x0B},
		[]byte{0x00, 0x06, 0x00, 0x06},
		[]byte{0x00, 0x00},
		[]byte{0x00, 0x20},
	)
	for _, n := range []int{0, 4, 6, 10, 11} {
		if _, _, err := parseNVPublic(full[:n]); err == nil {
			t.Fatalf("parseNVPublic(len %d): want error", n)
		}
	}
	// authPolicy size overruns -> UnmarshalTPM2B error path.
	bad := concat(
		[]byte{0x01, 0x50, 0x00, 0x00},
		[]byte{0x00, 0x0B},
		[]byte{0x00, 0x06, 0x00, 0x06},
		[]byte{0x00, 0x40}, // authPolicy size 64, no payload
	)
	if _, _, err := parseNVPublic(bad); err == nil {
		t.Fatal("parseNVPublic bad authPolicy: want error")
	}
	// authPolicy parses (empty) but no room for dataSize afterwards.
	noDataSize := concat(
		[]byte{0x01, 0x50, 0x00, 0x00},
		[]byte{0x00, 0x0B},
		[]byte{0x00, 0x06, 0x00, 0x06},
		[]byte{0x00, 0x00}, // authPolicy: empty, nothing follows
	)
	if _, _, err := parseNVPublic(noDataSize); err != common.ErrShortBuffer {
		t.Fatalf("parseNVPublic no dataSize: got %v, want ErrShortBuffer", err)
	}
	// Valid public with a non-empty authPolicy (exercises the copy path).
	withPolicy := concat(
		[]byte{0x01, 0x50, 0x00, 0x00},
		[]byte{0x00, 0x0B},
		[]byte{0x00, 0x06, 0x00, 0x06},
		common.MarshalTPM2B([]byte{0x01, 0x02, 0x03}),
		[]byte{0x00, 0x20},
	)
	got, _, err := parseNVPublic(withPolicy)
	if err != nil {
		t.Fatalf("parseNVPublic withPolicy: %v", err)
	}
	if !bytes.Equal(got.AuthPolicy, []byte{0x01, 0x02, 0x03}) {
		t.Fatalf("parseNVPublic authPolicy = %x", got.AuthPolicy)
	}
}
