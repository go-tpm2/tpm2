// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/tpm2 authors. All rights reserved.

package tpm2

import (
	"bytes"
	"errors"
	"testing"

	"github.com/go-tpm2/common"
)

// fakeTransport is a hand-built common.Transport. It records the exact
// command buffer the command layer emitted (for byte-for-byte request
// assertions) and returns a canned response (or an error). It deliberately
// does no parsing of its own, so the request assertions test only the
// code under test.
type fakeTransport struct {
	gotCmd []byte // the command buffer the last Send received
	rsp    []byte // the canned response to return
	err    error  // if non-nil, returned instead of rsp
}

func (f *fakeTransport) Send(cmd []byte) ([]byte, error) {
	f.gotCmd = append([]byte(nil), cmd...)
	if f.err != nil {
		return nil, f.err
	}
	return f.rsp, nil
}

// resp builds a well-formed response buffer (header + params) with the
// given response code, so tests can hand-assemble canned replies the way
// ParseResponse expects them.
func resp(tag uint16, rc uint32, params []byte) []byte {
	return common.BuildCommand(tag, rc, params) // same [tag|size|code|params] shape
}

// okResp is resp with TagNoSessions and RCSuccess.
func okResp(params []byte) []byte {
	return resp(uint16(common.TagNoSessions), uint32(common.RCSuccess), params)
}

// --- request byte-for-byte assertions ---

func TestStartupRequestBytes(t *testing.T) {
	ft := &fakeTransport{rsp: okResp(nil)}
	tpm := New(ft)
	if err := tpm.Startup(uint16(common.SUClear)); err != nil {
		t.Fatalf("Startup: %v", err)
	}
	// Hand-derived expected command:
	//   tag         = 0x8001 (TagNoSessions)
	//   commandSize = 0x0000000C (10 header + 2 param)
	//   commandCode = 0x00000144 (TPM2_Startup)
	//   startupType = 0x0000 (TPM_SU_CLEAR)
	want := []byte{
		0x80, 0x01,
		0x00, 0x00, 0x00, 0x0C,
		0x00, 0x00, 0x01, 0x44,
		0x00, 0x00,
	}
	if !bytes.Equal(ft.gotCmd, want) {
		t.Fatalf("Startup request bytes\n got %x\nwant %x", ft.gotCmd, want)
	}
}

func TestShutdownRequestBytes(t *testing.T) {
	ft := &fakeTransport{rsp: okResp(nil)}
	tpm := New(ft)
	if err := tpm.Shutdown(uint16(common.SUState)); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	want := []byte{
		0x80, 0x01,
		0x00, 0x00, 0x00, 0x0C,
		0x00, 0x00, 0x01, 0x45, // TPM2_Shutdown
		0x00, 0x01, // TPM_SU_STATE
	}
	if !bytes.Equal(ft.gotCmd, want) {
		t.Fatalf("Shutdown request bytes\n got %x\nwant %x", ft.gotCmd, want)
	}
}

func TestSelfTestRequestBytes(t *testing.T) {
	for _, tc := range []struct {
		full bool
		yn   byte
	}{{true, 0x01}, {false, 0x00}} {
		ft := &fakeTransport{rsp: okResp(nil)}
		tpm := New(ft)
		if err := tpm.SelfTest(tc.full); err != nil {
			t.Fatalf("SelfTest(%v): %v", tc.full, err)
		}
		want := []byte{
			0x80, 0x01,
			0x00, 0x00, 0x00, 0x0B, // 10 + 1
			0x00, 0x00, 0x01, 0x43, // TPM2_SelfTest
			tc.yn,
		}
		if !bytes.Equal(ft.gotCmd, want) {
			t.Fatalf("SelfTest(%v) request bytes\n got %x\nwant %x", tc.full, ft.gotCmd, want)
		}
	}
}

func TestGetRandomRequestAndResponse(t *testing.T) {
	// Response: TPM2B randomBytes = 0x0004 || DEADBEEF.
	rp := append([]byte{0x00, 0x04}, 0xDE, 0xAD, 0xBE, 0xEF)
	ft := &fakeTransport{rsp: okResp(rp)}
	tpm := New(ft)
	got, err := tpm.GetRandom(4)
	if err != nil {
		t.Fatalf("GetRandom: %v", err)
	}
	want := []byte{
		0x80, 0x01,
		0x00, 0x00, 0x00, 0x0C, // 10 + 2
		0x00, 0x00, 0x01, 0x7B, // TPM2_GetRandom
		0x00, 0x04, // bytesRequested = 4
	}
	if !bytes.Equal(ft.gotCmd, want) {
		t.Fatalf("GetRandom request bytes\n got %x\nwant %x", ft.gotCmd, want)
	}
	if !bytes.Equal(got, []byte{0xDE, 0xAD, 0xBE, 0xEF}) {
		t.Fatalf("GetRandom payload = %x", got)
	}
}

func TestGetCapabilityRequestAndResponse(t *testing.T) {
	// Response: moreData = 0x01, then a raw TPMS_CAPABILITY_DATA blob.
	blob := []byte{0x00, 0x00, 0x00, 0x06, 0xCA, 0xFE} // arbitrary opaque bytes
	rp := append([]byte{0x01}, blob...)
	ft := &fakeTransport{rsp: okResp(rp)}
	tpm := New(ft)
	more, data, err := tpm.GetCapability(0x00000006, 0x00000020, 1)
	if err != nil {
		t.Fatalf("GetCapability: %v", err)
	}
	want := []byte{
		0x80, 0x01,
		0x00, 0x00, 0x00, 0x16, // 10 + 12
		0x00, 0x00, 0x01, 0x7A, // TPM2_GetCapability
		0x00, 0x00, 0x00, 0x06, // capability
		0x00, 0x00, 0x00, 0x20, // property
		0x00, 0x00, 0x00, 0x01, // propertyCount
	}
	if !bytes.Equal(ft.gotCmd, want) {
		t.Fatalf("GetCapability request bytes\n got %x\nwant %x", ft.gotCmd, want)
	}
	if !more {
		t.Fatalf("GetCapability moreData = false, want true")
	}
	if !bytes.Equal(data, blob) {
		t.Fatalf("GetCapability data = %x, want %x", data, blob)
	}
}

func TestPCRReadRequestAndResponse(t *testing.T) {
	ft := &fakeTransport{}
	tpm := New(ft)

	// Selection: SHA-256 bank, PCRs 0 and 7.
	//   PCR 0 -> octet 0 bit 0 -> 0x01
	//   PCR 7 -> octet 0 bit 7 -> 0x80
	//   bitmap = 81 00 00
	sel := []PCRSelection{{Hash: uint16(common.AlgSHA256), PCRs: []int{0, 7}}}

	// Build a canned response:
	//   updateCounter = 0x0000002A
	//   pcrSelectionOut echoed (count 1, sha256, size 3, 81 00 00)
	//   TPML_DIGEST: count 1, then TPM2B 0x0020 || 32 bytes of 0xAB
	digest := bytes.Repeat([]byte{0xAB}, 32)
	rp := []byte{0x00, 0x00, 0x00, 0x2A}
	rp = append(rp, 0x00, 0x00, 0x00, 0x01) // selection count
	rp = append(rp, 0x00, 0x0B)             // sha256
	rp = append(rp, 0x03)                   // sizeofSelect
	rp = append(rp, 0x81, 0x00, 0x00)       // bitmap
	rp = append(rp, 0x00, 0x00, 0x00, 0x01) // digest count
	rp = append(rp, 0x00, 0x20)             // TPM2B size 32
	rp = append(rp, digest...)
	ft.rsp = okResp(rp)

	uc, digests, err := tpm.PCRRead(sel)
	if err != nil {
		t.Fatalf("PCRRead: %v", err)
	}

	// Hand-derived request: TPML_PCR_SELECTION param =
	//   count=00000001 (4), sha256=000B (2), sizeofSelect=03 (1),
	//   bitmap=81 00 00 (3)  => 10 param bytes
	want := []byte{
		0x80, 0x01,
		0x00, 0x00, 0x00, 0x14, // 10 header + 10 param
		0x00, 0x00, 0x01, 0x7E, // TPM2_PCR_Read
		0x00, 0x00, 0x00, 0x01, // count
		0x00, 0x0B, // sha256
		0x03,             // sizeofSelect
		0x81, 0x00, 0x00, // bitmap (PCR 0 and 7)
	}
	if !bytes.Equal(ft.gotCmd, want) {
		t.Fatalf("PCRRead request bytes\n got %x\nwant %x", ft.gotCmd, want)
	}
	if uc != 0x2A {
		t.Fatalf("updateCounter = %d, want 42", uc)
	}
	if len(digests) != 1 || !bytes.Equal(digests[0], digest) {
		t.Fatalf("digests = %x", digests)
	}
}

func TestPCRExtendRequestBytes(t *testing.T) {
	ft := &fakeTransport{rsp: resp(uint16(common.TagSessions), uint32(common.RCSuccess), nil)}
	tpm := New(ft)

	digest := bytes.Repeat([]byte{0x11}, 32) // a SHA-256 digest
	if err := tpm.PCRExtend(3, uint16(common.AlgSHA256), digest); err != nil {
		t.Fatalf("PCRExtend: %v", err)
	}

	// Hand-derived body:
	//   handle:  pcrHandle              = 00 00 00 03
	//   auth:    authorizationSize      = 00 00 00 09
	//            TPMS_AUTH_COMMAND:
	//              sessionHandle        = 40 00 00 09 (TPM_RS_PW)
	//              nonce (empty TPM2B)  = 00 00
	//              sessionAttributes    = 01 (continueSession)
	//              hmac  (empty TPM2B)  = 00 00
	//   params:  TPML_DIGEST_VALUES:
	//              count                = 00 00 00 01
	//              hashAlg              = 00 0B (sha256)
	//              digest               = 32 * 0x11
	// body length = 4 + 4 + 9 + (4+2+32) = 55; commandSize = 10 + 55 = 65 = 0x41
	var body []byte
	body = append(body, 0x00, 0x00, 0x00, 0x03) // pcrHandle
	body = append(body, 0x00, 0x00, 0x00, 0x09) // authorizationSize
	body = append(body, 0x40, 0x00, 0x00, 0x09) // TPM_RS_PW
	body = append(body, 0x00, 0x00)             // nonce empty
	body = append(body, 0x01)                   // continueSession
	body = append(body, 0x00, 0x00)             // hmac empty
	body = append(body, 0x00, 0x00, 0x00, 0x01) // digest-values count
	body = append(body, 0x00, 0x0B)             // sha256
	body = append(body, digest...)              // digest
	want := []byte{0x80, 0x02, 0x00, 0x00, 0x00, 0x41, 0x00, 0x00, 0x01, 0x82}
	want = append(want, body...)

	if !bytes.Equal(ft.gotCmd, want) {
		t.Fatalf("PCRExtend request bytes\n got %x\nwant %x", ft.gotCmd, want)
	}
}

// --- error branches ---

func TestExecuteTransportError(t *testing.T) {
	wantErr := errors.New("io fail")
	ft := &fakeTransport{err: wantErr}
	tpm := New(ft)
	if err := tpm.Startup(0); !errors.Is(err, wantErr) {
		t.Fatalf("Startup err = %v, want %v", err, wantErr)
	}
}

func TestExecuteParseError(t *testing.T) {
	// A 3-byte buffer is shorter than the 10-byte header.
	ft := &fakeTransport{rsp: []byte{0x80, 0x01, 0x00}}
	tpm := New(ft)
	if err := tpm.Startup(0); !errors.Is(err, common.ErrShortBuffer) {
		t.Fatalf("Startup err = %v, want ErrShortBuffer", err)
	}
}

func TestExecuteTPMError(t *testing.T) {
	const rc = 0x00000101 // arbitrary non-success rc (TPM_RC_FAILURE-ish)
	ft := &fakeTransport{rsp: resp(uint16(common.TagNoSessions), rc, nil)}
	tpm := New(ft)
	err := tpm.Startup(0)
	var te *TPMError
	if !errors.As(err, &te) {
		t.Fatalf("Startup err = %v (%T), want *TPMError", err, err)
	}
	if te.RC != rc {
		t.Fatalf("TPMError.RC = 0x%X, want 0x%X", te.RC, rc)
	}
	if te.CC != uint32(common.CCStartup) {
		t.Fatalf("TPMError.CC = 0x%X, want 0x%X", te.CC, uint32(common.CCStartup))
	}
	want := "tpm2: command 0x00000144 failed: rc 0x00000101"
	if te.Error() != want {
		t.Fatalf("TPMError.Error() = %q, want %q", te.Error(), want)
	}
}

// TestExecuteErrorPropagation drives the execute-returned-error guard in
// each command that returns data (the err != nil branch right after the
// transport round-trip), so every command's own early return is exercised.
func TestExecuteErrorPropagation(t *testing.T) {
	wantErr := errors.New("io fail")

	t.Run("GetRandom", func(t *testing.T) {
		ft := &fakeTransport{err: wantErr}
		if _, err := New(ft).GetRandom(4); !errors.Is(err, wantErr) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("GetCapability", func(t *testing.T) {
		ft := &fakeTransport{err: wantErr}
		if _, _, err := New(ft).GetCapability(0, 0, 0); !errors.Is(err, wantErr) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("PCRRead", func(t *testing.T) {
		ft := &fakeTransport{err: wantErr}
		if _, _, err := New(ft).PCRRead(nil); !errors.Is(err, wantErr) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("PCRExtend", func(t *testing.T) {
		ft := &fakeTransport{err: wantErr}
		if err := New(ft).PCRExtend(0, uint16(common.AlgSHA256), nil); !errors.Is(err, wantErr) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestGetRandomUnmarshalError(t *testing.T) {
	// Response param is a single byte: too short for a TPM2B size prefix.
	ft := &fakeTransport{rsp: okResp([]byte{0x00})}
	tpm := New(ft)
	if _, err := tpm.GetRandom(4); !errors.Is(err, common.ErrShortBuffer) {
		t.Fatalf("GetRandom err = %v, want ErrShortBuffer", err)
	}
}

func TestGetCapabilityShortResponse(t *testing.T) {
	// Empty param area: no moreData byte.
	ft := &fakeTransport{rsp: okResp(nil)}
	tpm := New(ft)
	if _, _, err := tpm.GetCapability(0, 0, 0); !errors.Is(err, common.ErrShortBuffer) {
		t.Fatalf("GetCapability err = %v, want ErrShortBuffer", err)
	}
}

func TestPCRReadErrorBranches(t *testing.T) {
	sel := []PCRSelection{{Hash: uint16(common.AlgSHA256), PCRs: []int{0}}}

	t.Run("short updateCounter", func(t *testing.T) {
		ft := &fakeTransport{rsp: okResp([]byte{0x00, 0x00})} // < 4 bytes
		if _, _, err := New(ft).PCRRead(sel); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v, want ErrShortBuffer", err)
		}
	})

	t.Run("bad selection list", func(t *testing.T) {
		// updateCounter present, but the selection list is truncated.
		rp := []byte{0x00, 0x00, 0x00, 0x01, 0x00} // count GetU32 short after the 4-byte counter
		ft := &fakeTransport{rsp: okResp(rp)}
		if _, _, err := New(ft).PCRRead(sel); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v, want ErrShortBuffer", err)
		}
	})

	t.Run("short digest count", func(t *testing.T) {
		// updateCounter + empty selection list (count 0), then no TPML_DIGEST.
		rp := []byte{
			0x00, 0x00, 0x00, 0x01, // updateCounter
			0x00, 0x00, 0x00, 0x00, // selection count = 0
			0x00, 0x00, // a stub 2 bytes: too short for the digest u32 count
		}
		ft := &fakeTransport{rsp: okResp(rp)}
		if _, _, err := New(ft).PCRRead(sel); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v, want ErrShortBuffer", err)
		}
	})

	t.Run("short digest blob", func(t *testing.T) {
		rp := []byte{
			0x00, 0x00, 0x00, 0x01, // updateCounter
			0x00, 0x00, 0x00, 0x00, // selection count = 0
			0x00, 0x00, 0x00, 0x01, // digest count = 1
			0x00, 0x20, // TPM2B says 32 bytes, but none follow
		}
		ft := &fakeTransport{rsp: okResp(rp)}
		if _, _, err := New(ft).PCRRead(sel); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v, want ErrShortBuffer", err)
		}
	})
}

// --- parsePCRSelectionList unit error branches ---

func TestParsePCRSelectionListErrors(t *testing.T) {
	t.Run("short count", func(t *testing.T) {
		if _, _, err := parsePCRSelectionList([]byte{0x00, 0x00}); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("short hash", func(t *testing.T) {
		b := []byte{0x00, 0x00, 0x00, 0x01, 0x00} // count 1, then 1 byte (need 2 for hash)
		if _, _, err := parsePCRSelectionList(b); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("short sizeofSelect", func(t *testing.T) {
		b := []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x0B} // count 1, hash, but no sizeofSelect
		if _, _, err := parsePCRSelectionList(b); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("short bitmap", func(t *testing.T) {
		b := []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x0B, 0x03, 0x81} // sizeofSelect 3 but only 1 bitmap byte
		if _, _, err := parsePCRSelectionList(b); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
}

// --- bitmap helper branches ---

func TestBitmapRoundTrip(t *testing.T) {
	s := PCRSelection{Hash: uint16(common.AlgSHA256), PCRs: []int{0, 7, 8, 23}}
	bm := s.bitmap()
	want := []byte{0x81, 0x01, 0x80}
	if !bytes.Equal(bm, want) {
		t.Fatalf("bitmap = %x, want %x", bm, want)
	}
	got := pcrsFromBitmap(bm)
	wantPCRs := []int{0, 7, 8, 23}
	if len(got) != len(wantPCRs) {
		t.Fatalf("pcrsFromBitmap = %v, want %v", got, wantPCRs)
	}
	for i := range got {
		if got[i] != wantPCRs[i] {
			t.Fatalf("pcrsFromBitmap = %v, want %v", got, wantPCRs)
		}
	}
}

func TestBitmapOutOfRangeIgnored(t *testing.T) {
	// Negative and >=24 indices fall outside the 3-octet window and are
	// dropped silently.
	s := PCRSelection{Hash: uint16(common.AlgSHA256), PCRs: []int{-1, 24, 99, 5}}
	bm := s.bitmap()
	want := []byte{0x20, 0x00, 0x00} // only PCR 5
	if !bytes.Equal(bm, want) {
		t.Fatalf("bitmap = %x, want %x", bm, want)
	}
}

func TestYesNo(t *testing.T) {
	if yesNo(true) != 1 || yesNo(false) != 0 {
		t.Fatalf("yesNo broken: %d %d", yesNo(true), yesNo(false))
	}
}
