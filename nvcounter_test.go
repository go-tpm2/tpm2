// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/tpm2 authors. All rights reserved.

package tpm2

import (
	"bytes"
	"errors"
	"testing"

	"github.com/go-tpm2/common"
)

// pwAuth is the TPMS_AUTH_COMMAND of an RS_PW session carrying pw.
func pwAuth(pw []byte) []byte {
	return concat(
		[]byte{0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x01},
		common.MarshalTPM2B(pw),
	)
}

func TestNVIncrementRequestBytes(t *testing.T) {
	ft := &fakeTransport{rsp: sessOK(nil)}
	if err := New(ft).NVIncrement(testNVIndex); err != nil {
		t.Fatalf("NVIncrement: %v", err)
	}
	body := concat(
		[]byte{0x40, 0x00, 0x00, 0x01}, // authHandle = TPM_RH_OWNER
		[]byte{0x01, 0x50, 0x00, 0x00}, // nvIndex
		[]byte{0x00, 0x00, 0x00, 0x09}, // authorizationSize
		rsPWAuth(),
	)
	want := common.BuildCommand(uint16(common.TagSessions), 0x00000134, body)
	if !bytes.Equal(ft.gotCmd, want) {
		t.Fatalf("request\n got %x\nwant %x", ft.gotCmd, want)
	}
}

func TestNVIncrementAuthRequestBytes(t *testing.T) {
	ft := &fakeTransport{rsp: sessOK(nil)}
	pw := []byte("pw")
	if err := New(ft).NVIncrementAuth(testNVIndex, pw, testNVIndex); err != nil {
		t.Fatalf("NVIncrementAuth: %v", err)
	}
	a := pwAuth(pw) // 4+2+1+2+2 = 11 bytes
	body := concat(
		[]byte{0x01, 0x50, 0x00, 0x00}, // authHandle = the index itself
		[]byte{0x01, 0x50, 0x00, 0x00}, // nvIndex
		[]byte{0x00, 0x00, 0x00, 0x0B}, // authorizationSize
		a,
	)
	if len(a) != 11 {
		t.Fatalf("auth area is %d bytes", len(a))
	}
	want := common.BuildCommand(uint16(common.TagSessions), 0x00000134, body)
	if !bytes.Equal(ft.gotCmd, want) {
		t.Fatalf("request\n got %x\nwant %x", ft.gotCmd, want)
	}
}

func TestNVIncrementError(t *testing.T) {
	if err := New(&fakeTransport{err: errors.New("boom")}).NVIncrement(testNVIndex); err == nil {
		t.Fatal("want transport error")
	}
}

func TestNVDefineSpaceAuthRequestBytes(t *testing.T) {
	ft := &fakeTransport{rsp: sessOK(nil)}
	pub := NVPublic{Index: testNVIndex, NameAlg: algSHA256, Attributes: CounterAttributes,
		DataSize: 8}
	if err := New(ft).NVDefineSpaceAuth([]byte("o"), []byte("ix"), pub); err != nil {
		t.Fatalf("NVDefineSpaceAuth: %v", err)
	}
	a := pwAuth([]byte("o")) // 10 bytes
	body := concat(
		[]byte{0x40, 0x00, 0x00, 0x01},
		[]byte{0x00, 0x00, 0x00, byte(len(a))},
		a,
		[]byte{0x00, 0x02, 'i', 'x'}, // TPM2B_AUTH
		[]byte{0x00, 0x0E},           // TPM2B_NV_PUBLIC size: 4+2+4+2+2 = 14
		[]byte{0x01, 0x50, 0x00, 0x00},
		[]byte{0x00, 0x0B},
		[]byte{0x00, 0x04, 0x00, 0x14}, // COUNTER 0x10 | AUTHWRITE 0x4 | AUTHREAD 0x40000
		[]byte{0x00, 0x00},             // authPolicy: empty
		[]byte{0x00, 0x08},
	)
	want := common.BuildCommand(uint16(common.TagSessions), uint32(ccNVDefineSpace), body)
	if !bytes.Equal(ft.gotCmd, want) {
		t.Fatalf("request\n got %x\nwant %x", ft.gotCmd, want)
	}
}

// With empty passwords NVDefineSpaceAuth is NVDefineSpace, byte for byte.
func TestNVDefineSpaceAuthEmptyIsNVDefineSpace(t *testing.T) {
	pub := NVPublic{Index: testNVIndex, NameAlg: algSHA256, Attributes: nvOrdinaryAttributes, DataSize: 32}
	a, b := &fakeTransport{rsp: sessOK(nil)}, &fakeTransport{rsp: sessOK(nil)}
	if err := New(a).NVDefineSpace(pub); err != nil {
		t.Fatal(err)
	}
	if err := New(b).NVDefineSpaceAuth(nil, nil, pub); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.gotCmd, b.gotCmd) {
		t.Fatalf("differ\n%x\n%x", a.gotCmd, b.gotCmd)
	}
}

func TestNVUndefineSpaceAuthRequestBytes(t *testing.T) {
	ft := &fakeTransport{rsp: sessOK(nil)}
	if err := New(ft).NVUndefineSpaceAuth([]byte("o"), testNVIndex); err != nil {
		t.Fatal(err)
	}
	body := concat([]byte{0x40, 0, 0, 0x01}, []byte{0x01, 0x50, 0, 0},
		[]byte{0, 0, 0, 10}, pwAuth([]byte("o")))
	want := common.BuildCommand(uint16(common.TagSessions), uint32(ccNVUndefineSpace), body)
	if !bytes.Equal(ft.gotCmd, want) {
		t.Fatalf("request\n got %x\nwant %x", ft.gotCmd, want)
	}
	if err := New(&fakeTransport{err: errors.New("boom")}).NVUndefineSpaceAuth(nil, testNVIndex); err == nil {
		t.Fatal("want transport error")
	}
}

func TestCounterAttributes(t *testing.T) {
	if CounterAttributes != 0x00040014 {
		t.Fatalf("CounterAttributes = %#x", CounterAttributes)
	}
}

// readCounterRsp is a NV_Read response carrying data.
func readCounterRsp(data []byte) []byte {
	tb := common.MarshalTPM2B(data)
	return sessOK(concat([]byte{0, 0, 0, byte(len(tb))}, tb))
}

func TestNVReadCounter(t *testing.T) {
	ft := &fakeTransport{rsp: readCounterRsp([]byte{0, 0, 0, 0, 0, 0, 0x01, 0x02})}
	v, err := New(ft).NVReadCounter([]byte("pw"), testNVIndex)
	if err != nil || v != 0x0102 {
		t.Fatalf("v=%d err=%v", v, err)
	}
	body := concat(
		[]byte{0x01, 0x50, 0x00, 0x00}, []byte{0x01, 0x50, 0x00, 0x00},
		[]byte{0, 0, 0, 0x0B}, pwAuth([]byte("pw")),
		[]byte{0x00, 0x08}, []byte{0x00, 0x00},
	)
	want := common.BuildCommand(uint16(common.TagSessions), uint32(ccNVRead), body)
	if !bytes.Equal(ft.gotCmd, want) {
		t.Fatalf("request\n got %x\nwant %x", ft.gotCmd, want)
	}
	if v, _ := counterValue([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}); v != ^uint64(0) {
		t.Fatalf("max = %d", v)
	}
}

func TestNVReadCounterErrors(t *testing.T) {
	if _, err := New(&fakeTransport{err: errors.New("boom")}).NVReadCounter(nil, testNVIndex); err == nil {
		t.Fatal("want transport error")
	}
	if _, err := New(&fakeTransport{rsp: readCounterRsp([]byte{1, 2, 3})}).NVReadCounter(nil, testNVIndex); !errors.Is(err, ErrCounterSize) {
		t.Fatalf("short value: %v", err)
	}
	if _, err := New(&fakeTransport{rsp: sessOK([]byte{0, 0})}).NVReadCounter(nil, testNVIndex); err == nil {
		t.Fatal("short parameterSize")
	}
	if _, err := New(&fakeTransport{rsp: sessOK([]byte{0, 0, 0, 9, 0, 9})}).NVReadCounter(nil, testNVIndex); err == nil {
		t.Fatal("truncated TPM2B")
	}
}

// NVDefineCounter defines, then reads the Name back.
func TestNVDefineCounter(t *testing.T) {
	pub := NVPublic{Index: testNVIndex, NameAlg: algSHA256, Attributes: CounterAttributes,
		DataSize: 8}
	name := append([]byte{0x00, 0x0B}, bytes.Repeat([]byte{7}, 32)...)
	rsp := noSessOK(concat(common.MarshalTPM2B(marshalNVPublic(pub)[2:]), common.MarshalTPM2B(name)))
	ft := &seqTransport{rsps: [][]byte{sessOK(nil), rsp}}
	got, err := New(ft).NVDefineCounter(nil, nil, testNVIndex)
	if err != nil || !bytes.Equal(got, name) {
		t.Fatalf("name=%x err=%v", got, err)
	}
	if _, err := New(&fakeTransport{err: errors.New("boom")}).NVDefineCounter(nil, nil, testNVIndex); err == nil {
		t.Fatal("want define error")
	}
}

// FuzzNVCounterResponses feeds arbitrary response bytes to every parser the
// counter commands add: none may panic, and a value comes back only for
// exactly 8 data bytes.
func FuzzNVCounterResponses(f *testing.F) {
	f.Add(readCounterRsp(make([]byte, 8)))
	f.Add(sessOK(nil))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, rsp []byte) {
		tpm := New(&fakeTransport{rsp: rsp})
		_, _ = tpm.NVReadCounter(nil, testNVIndex)
		_ = tpm.NVIncrement(testNVIndex)
		_, _ = tpm.NVDefineCounter(nil, nil, testNVIndex)
		if rp, err := parseNVReadResponse(rsp); err == nil {
			if v, err := counterValue(rp); err == nil && len(rp) != CounterSize {
				t.Fatalf("value %d from %d bytes", v, len(rp))
			}
		}
	})
}
