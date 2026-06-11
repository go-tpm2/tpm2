// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/tpm2 authors. All rights reserved.

package tpm2

import (
	"bytes"
	"errors"
	"testing"

	"github.com/go-tpm2/common"
)

// ekTemplateInner is the hand-derived inner TPMT_PUBLIC of the EK Credential
// Profile L-2 template (before the TPM2B_PUBLIC size prefix):
//
//	type=ECC(0023) nameAlg=SHA256(000B) attrs=000300B2
//	authPolicy=TPM2B(32-byte EK policy)
//	TPMS_ECC_PARMS: AES(0006) 128(0080) CFB(0043) scheme=NULL(0010)
//	                curve=P256(0003) kdf=NULL(0010)
//	unique: x empty(0000) y empty(0000)
func ekTemplateInner() []byte {
	return concat(
		[]byte{0x00, 0x23},             // type = ECC
		[]byte{0x00, 0x0B},             // nameAlg = SHA256
		[]byte{0x00, 0x03, 0x00, 0xB2}, // objectAttributes = 0x000300B2
		[]byte{0x00, 0x20},             // authPolicy TPM2B size = 32
		ekAuthPolicy,                   // the 32-byte well-known EK policy
		[]byte{0x00, 0x06},             // symmetric.algorithm = AES
		[]byte{0x00, 0x80},             // symmetric.keyBits = 128
		[]byte{0x00, 0x43},             // symmetric.mode = CFB
		[]byte{0x00, 0x10},             // scheme = NULL
		[]byte{0x00, 0x03},             // curveID = P256
		[]byte{0x00, 0x10},             // kdf = NULL
		[]byte{0x00, 0x00},             // unique.x: empty
		[]byte{0x00, 0x00},             // unique.y: empty
	)
}

// ekTemplate wraps ekTemplateInner in its TPM2B_PUBLIC size prefix.
func ekTemplate() []byte {
	return common.MarshalTPM2B(ekTemplateInner())
}

// ekResp builds a realistic TPM2_CreatePrimary response for the EK with the
// given (x, y) public point: objectHandle || parameterSize || TPM2B_PUBLIC
// outPublic || trailing creation bytes (consumed by not being read).
func ekResp(handle uint32, x, y []byte) []byte {
	outPublic := common.MarshalTPM2B(concat(
		[]byte{0x00, 0x23},             // type = ECC
		[]byte{0x00, 0x0B},             // nameAlg = SHA256
		[]byte{0x00, 0x03, 0x00, 0xB2}, // objectAttributes
		[]byte{0x00, 0x20},             // authPolicy size 32
		ekAuthPolicy,
		[]byte{0x00, 0x06}, // AES
		[]byte{0x00, 0x80}, // 128
		[]byte{0x00, 0x43}, // CFB
		[]byte{0x00, 0x10}, // scheme NULL
		[]byte{0x00, 0x03}, // P256
		[]byte{0x00, 0x10}, // kdf NULL
		common.MarshalTPM2B(x),
		common.MarshalTPM2B(y),
	))
	params := common.PutU32(nil, handle)
	params = common.PutU32(params, 0) // parameterSize (unused after skip)
	params = append(params, outPublic...)
	params = append(params, []byte{0xCA, 0xFE}...) // trailing creation bytes
	return sessOK(params)
}

func TestCreateEKRequestBytes(t *testing.T) {
	x := bytes.Repeat([]byte{0x11}, 32)
	y := bytes.Repeat([]byte{0x22}, 32)
	ft := &fakeTransport{rsp: ekResp(0x80000000, x, y)}
	tpm := New(ft)
	if _, _, err := tpm.CreateEK(); err != nil {
		t.Fatalf("CreateEK: %v", err)
	}
	wantBody := concat(
		[]byte{0x40, 0x00, 0x00, 0x0B}, // primaryHandle = RH_ENDORSEMENT
		[]byte{0x00, 0x00, 0x00, 0x09}, // authorizationSize
		rsPWAuth(),
		[]byte{0x00, 0x04, 0x00, 0x00, 0x00, 0x00}, // TPM2B_SENSITIVE_CREATE (empty)
		ekTemplate(),                               // TPM2B_PUBLIC (EK template)
		[]byte{0x00, 0x00},                         // outsideInfo: empty TPM2B_DATA
		[]byte{0x00, 0x00, 0x00, 0x00},             // creationPCR: count 0
	)
	want := common.BuildCommand(uint16(common.TagSessions), uint32(common.CCCreatePrimary), wantBody)
	if !bytes.Equal(ft.gotCmd, want) {
		t.Fatalf("CreateEK request bytes\n got %x\nwant %x", ft.gotCmd, want)
	}
}

func TestCreateEKDecode(t *testing.T) {
	x := bytes.Repeat([]byte{0xAB}, 32)
	y := bytes.Repeat([]byte{0xCD}, 32)
	ft := &fakeTransport{rsp: ekResp(0x80000123, x, y)}
	tpm := New(ft)
	h, pub, err := tpm.CreateEK()
	if err != nil {
		t.Fatalf("CreateEK: %v", err)
	}
	if h != 0x80000123 {
		t.Fatalf("CreateEK handle = %#x", h)
	}
	if !bytes.Equal(pub.X, x) || !bytes.Equal(pub.Y, y) {
		t.Fatalf("CreateEK point X=%x Y=%x", pub.X, pub.Y)
	}
}

func TestCreateEKTransportError(t *testing.T) {
	ft := &fakeTransport{err: errors.New("boom")}
	tpm := New(ft)
	if _, _, err := tpm.CreateEK(); err == nil {
		t.Fatal("CreateEK: want transport error")
	}
}

func TestCreateEKBadResponse(t *testing.T) {
	// A success reply too short to hold even the objectHandle.
	ft := &fakeTransport{rsp: sessOK([]byte{0x00, 0x00})}
	tpm := New(ft)
	if _, _, err := tpm.CreateEK(); err == nil {
		t.Fatal("CreateEK: want decode error")
	}
}

// TestEKAuthPolicyValue locks the well-known EK policy digest to its TCG-
// published value, so an accidental edit of ekAuthPolicy is caught offline.
func TestEKAuthPolicyValue(t *testing.T) {
	want := []byte{
		0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8,
		0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24,
		0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64,
		0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa,
	}
	if !bytes.Equal(ekAuthPolicy, want) {
		t.Fatalf("ekAuthPolicy = %x", ekAuthPolicy)
	}
}

// TestEKObjectAttributesValue locks the L-2 template TPMA_OBJECT value.
func TestEKObjectAttributesValue(t *testing.T) {
	if ekObjectAttributes != 0x000300B2 {
		t.Fatalf("ekObjectAttributes = %#08x, want 0x000300B2", ekObjectAttributes)
	}
}
