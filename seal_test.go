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

// sessResp (a TagSessions success response) is defined in attest_test.go and
// reused here.

// --- PolicyPCRDigest: hand-derived construction ---

// TestPolicyPCRDigestConstruction pins the exact policy digest construction
// (TCG Part 1, "Policy PCR") so a regression in the field order or hashing
// is caught offline, independent of any TPM.
func TestPolicyPCRDigestConstruction(t *testing.T) {
	sel := []PCRSelection{{Hash: uint16(common.AlgSHA256), PCRs: []int{16}}}
	pcrVal := bytes.Repeat([]byte{0xAA}, 32)

	got := PolicyPCRDigest(sel, [][]byte{pcrVal})

	// Re-derive by hand, the long way:
	//   pcrDigest = SHA256(pcrVal)
	//   policyDigest = SHA256( 0*32 || 0x0000017F || TPML_PCR_SELECTION || pcrDigest )
	pcrDigest := sha256.Sum256(pcrVal)

	// TPML_PCR_SELECTION for {sha256:{16}}:
	//   count        = 00000001
	//   hash         = 000B
	//   sizeofSelect = 03
	//   pcrSelect    = PCR16 -> octet 2 bit 0 -> 00 00 01
	selBytes := []byte{
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x0B,
		0x03,
		0x00, 0x00, 0x01,
	}
	h := sha256.New()
	h.Write(make([]byte, 32))               // policyDigestold = 0*32
	h.Write([]byte{0x00, 0x00, 0x01, 0x7F}) // TPM_CC_PolicyPCR
	h.Write(selBytes)                       // TPML_PCR_SELECTION
	h.Write(pcrDigest[:])                   // pcrDigest
	want := h.Sum(nil)

	if !bytes.Equal(got, want) {
		t.Fatalf("PolicyPCRDigest\n got %x\nwant %x", got, want)
	}
	if len(got) != 32 {
		t.Fatalf("policyDigest length = %d, want 32", len(got))
	}
}

// --- CreateStoragePrimary request bytes ---

func TestCreateStoragePrimaryRequestBytes(t *testing.T) {
	// Response: objectHandle || parameterSize || (rest ignored).
	rp := []byte{0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	ft := &fakeTransport{rsp: sessResp(rp)}
	tpm := New(ft)

	h, err := tpm.CreateStoragePrimary()
	if err != nil {
		t.Fatalf("CreateStoragePrimary: %v", err)
	}
	if h != 0x80000001 {
		t.Fatalf("handle = %#x, want 0x80000001", h)
	}

	// Hand-derived param area:
	//   handle: TPM_RH_OWNER                = 40 00 00 01
	//   auth:   authorizationSize           = 00 00 00 09
	//           RS_PW session               = 40 00 00 09 00 00 01 00 00
	//   inSensitive: TPM2B_SENSITIVE_CREATE = 00 04 00 00 00 00
	//   inPublic: TPM2B_PUBLIC ...
	//   outsideInfo: 00 00
	//   creationPCR: 00 00 00 00
	//
	// TPMT_PUBLIC (storage ECC):
	//   type=0023 nameAlg=000B objectAttributes=00030072 authPolicy=0000
	//   sym: AES(0006) keyBits 0080 mode CFB(0043)
	//   scheme NULL(0010) curve P256(0003) kdf NULL(0010)
	//   unique x=0000 y=0000
	// inner length = 2+2+4+2 +2+2+2 +2+2+2 +2+2 = 28 = 0x1C
	inner := []byte{
		0x00, 0x23, 0x00, 0x0B, 0x00, 0x03, 0x00, 0x72, 0x00, 0x00,
		0x00, 0x06, 0x00, 0x80, 0x00, 0x43,
		0x00, 0x10, 0x00, 0x03, 0x00, 0x10,
		0x00, 0x00, 0x00, 0x00,
	}
	pub2b := append([]byte{0x00, byte(len(inner))}, inner...)

	var params []byte
	params = append(params, 0x40, 0x00, 0x00, 0x01) // RH_OWNER
	params = append(params, 0x00, 0x00, 0x00, 0x09) // authorizationSize
	params = append(params, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x01, 0x00, 0x00)
	params = append(params, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00) // sensitiveCreate
	params = append(params, pub2b...)
	params = append(params, 0x00, 0x00)             // outsideInfo
	params = append(params, 0x00, 0x00, 0x00, 0x00) // creationPCR

	want := common.BuildCommand(uint16(common.TagSessions), uint32(common.CCCreatePrimary), params)
	if !bytes.Equal(ft.gotCmd, want) {
		t.Fatalf("CreateStoragePrimary request bytes\n got %x\nwant %x", ft.gotCmd, want)
	}
}

// --- Create request bytes: authPolicy must equal PolicyPCRDigest ---

func TestCreateRequestBytesAuthPolicy(t *testing.T) {
	parent := uint32(0x80000001)
	secret := []byte("GO-TPM2-SEALED-SECRET")
	sel := []PCRSelection{{Hash: uint16(common.AlgSHA256), PCRs: []int{16}}}
	pcrVal := bytes.Repeat([]byte{0xAA}, 32)
	policy := PolicyPCRDigest(sel, [][]byte{pcrVal})

	// Response: parameterSize || TPM2B_PRIVATE || TPM2B_PUBLIC (+ trailing).
	priv := []byte{0xDE, 0xAD}
	pub := []byte{0xBE, 0xEF, 0x00}
	var rpParams []byte
	rpParams = common.PutU32(rpParams, 0) // parameterSize (value unused by parser)
	rpParams = append(rpParams, common.MarshalTPM2B(priv)...)
	rpParams = append(rpParams, common.MarshalTPM2B(pub)...)
	ft := &fakeTransport{rsp: sessResp(rpParams)}
	tpm := New(ft)

	gotPriv, gotPub, err := tpm.Create(parent, secret, policy)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !bytes.Equal(gotPriv, priv) || !bytes.Equal(gotPub, pub) {
		t.Fatalf("Create returned priv=%x pub=%x", gotPriv, gotPub)
	}

	// Hand-derived param area.
	//   handle: parent = 80 00 00 01
	//   auth:   00 00 00 09 || RS_PW
	//   inSensitive: TPM2B_SENSITIVE_CREATE { userAuth 0000, data TPM2B(secret) }
	//       inner = 0000 || (00 15 || secret)   (len(secret)=21=0x15)
	//   inPublic: TPM2B_PUBLIC keyedhash sealed:
	//       type 0008 nameAlg 000B attrs 00000012 authPolicy TPM2B(policy=32)
	//       scheme NULL 0010 unique 0000
	//   outsideInfo 0000 ; creationPCR 00000000
	innerSens := []byte{0x00, 0x00}
	innerSens = append(innerSens, common.MarshalTPM2B(secret)...)
	sens2b := common.MarshalTPM2B(innerSens)

	var innerPub []byte
	innerPub = append(innerPub, 0x00, 0x08, 0x00, 0x0B) // type, nameAlg
	innerPub = append(innerPub, 0x00, 0x00, 0x00, 0x12) // objectAttributes
	innerPub = append(innerPub, common.MarshalTPM2B(policy)...)
	innerPub = append(innerPub, 0x00, 0x10) // scheme NULL
	innerPub = append(innerPub, 0x00, 0x00) // unique empty
	pub2b := common.MarshalTPM2B(innerPub)

	var params []byte
	params = append(params, 0x80, 0x00, 0x00, 0x01)
	params = append(params, 0x00, 0x00, 0x00, 0x09)
	params = append(params, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x01, 0x00, 0x00)
	params = append(params, sens2b...)
	params = append(params, pub2b...)
	params = append(params, 0x00, 0x00)
	params = append(params, 0x00, 0x00, 0x00, 0x00)

	want := common.BuildCommand(uint16(common.TagSessions), uint32(common.CCCreate), params)
	if !bytes.Equal(ft.gotCmd, want) {
		t.Fatalf("Create request bytes\n got %x\nwant %x", ft.gotCmd, want)
	}

	// Explicit assertion: the authPolicy on the wire IS PolicyPCRDigest.
	// Locate the TPM2B(policy) we constructed and confirm its 32 bytes.
	if !bytes.Contains(ft.gotCmd, append([]byte{0x00, 0x20}, policy...)) {
		t.Fatalf("Create wire does not carry authPolicy = PolicyPCRDigest")
	}
}

// --- Load request bytes ---

func TestLoadRequestBytes(t *testing.T) {
	priv := []byte{0x01, 0x02}
	pub := []byte{0x03, 0x04, 0x05}
	// Response: objectHandle || parameterSize || TPM2B_NAME.
	rp := []byte{0x80, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	ft := &fakeTransport{rsp: sessResp(rp)}
	tpm := New(ft)

	h, err := tpm.Load(0x80000001, priv, pub)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if h != 0x80000002 {
		t.Fatalf("handle = %#x", h)
	}

	var params []byte
	params = append(params, 0x80, 0x00, 0x00, 0x01)
	params = append(params, 0x00, 0x00, 0x00, 0x09)
	params = append(params, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x01, 0x00, 0x00)
	params = append(params, common.MarshalTPM2B(priv)...)
	params = append(params, common.MarshalTPM2B(pub)...)
	want := common.BuildCommand(uint16(common.TagSessions), uint32(common.CCLoad), params)
	if !bytes.Equal(ft.gotCmd, want) {
		t.Fatalf("Load request bytes\n got %x\nwant %x", ft.gotCmd, want)
	}
}

// --- StartAuthSession request/response bytes ---

func TestStartAuthSessionRequestAndResponse(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x5A}, 32)
	nonceTPM := bytes.Repeat([]byte{0xA5}, 32)
	// Response: sessionHandle || TPM2B_NONCE nonceTPM. StartAuthSession is
	// TagNoSessions, so its response has NO parameterSize.
	var rp []byte
	rp = common.PutU32(rp, 0x03000000) // a policy session handle
	rp = append(rp, common.MarshalTPM2B(nonceTPM)...)
	ft := &fakeTransport{rsp: okResp(rp)}
	tpm := New(ft)

	h, nt, err := tpm.StartAuthSession(nonce)
	if err != nil {
		t.Fatalf("StartAuthSession: %v", err)
	}
	if h != 0x03000000 {
		t.Fatalf("session handle = %#x", h)
	}
	if !bytes.Equal(nt, nonceTPM) {
		t.Fatalf("nonceTPM = %x", nt)
	}

	//   tpmKey  = 40 00 00 07 (RH_NULL)
	//   bind    = 40 00 00 07
	//   nonceCaller = 00 20 || 32*5A
	//   encryptedSalt = 00 00
	//   sessionType = 01 (TPM_SE_POLICY)
	//   symmetric = 00 10 (NULL)
	//   authHash = 00 0B (SHA256)
	var params []byte
	params = append(params, 0x40, 0x00, 0x00, 0x07)
	params = append(params, 0x40, 0x00, 0x00, 0x07)
	params = append(params, common.MarshalTPM2B(nonce)...)
	params = append(params, 0x00, 0x00)
	params = append(params, 0x01)
	params = append(params, 0x00, 0x10)
	params = append(params, 0x00, 0x0B)
	want := common.BuildCommand(uint16(common.TagNoSessions), uint32(ccStartAuthSession), params)
	if !bytes.Equal(ft.gotCmd, want) {
		t.Fatalf("StartAuthSession request bytes\n got %x\nwant %x", ft.gotCmd, want)
	}
}

// --- PolicyPCR request bytes ---

func TestPolicyPCRRequestBytes(t *testing.T) {
	sel := []PCRSelection{{Hash: uint16(common.AlgSHA256), PCRs: []int{16}}}
	ft := &fakeTransport{rsp: okResp(nil)}
	tpm := New(ft)
	if err := tpm.PolicyPCR(0x03000000, sel); err != nil {
		t.Fatalf("PolicyPCR: %v", err)
	}
	//   policySession = 03 00 00 00
	//   pcrDigest     = 00 00 (empty TPM2B)
	//   pcrs          = TPML_PCR_SELECTION {sha256:{16}}
	var params []byte
	params = append(params, 0x03, 0x00, 0x00, 0x00)
	params = append(params, 0x00, 0x00)
	params = append(params, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0B, 0x03, 0x00, 0x00, 0x01)
	want := common.BuildCommand(uint16(common.TagNoSessions), uint32(ccPolicyPCR), params)
	if !bytes.Equal(ft.gotCmd, want) {
		t.Fatalf("PolicyPCR request bytes\n got %x\nwant %x", ft.gotCmd, want)
	}
}

// --- PolicyGetDigest request/response ---

func TestPolicyGetDigestRequestAndResponse(t *testing.T) {
	digest := bytes.Repeat([]byte{0x77}, 32)
	ft := &fakeTransport{rsp: okResp(common.MarshalTPM2B(digest))}
	tpm := New(ft)
	got, err := tpm.PolicyGetDigest(0x03000000)
	if err != nil {
		t.Fatalf("PolicyGetDigest: %v", err)
	}
	if !bytes.Equal(got, digest) {
		t.Fatalf("digest = %x", got)
	}
	want := common.BuildCommand(uint16(common.TagNoSessions), uint32(ccPolicyGetDigest),
		[]byte{0x03, 0x00, 0x00, 0x00})
	if !bytes.Equal(ft.gotCmd, want) {
		t.Fatalf("PolicyGetDigest request bytes\n got %x\nwant %x", ft.gotCmd, want)
	}
}

// --- Unseal request bytes: auth area carries the POLICY SESSION handle ---

func TestUnsealRequestBytesPolicySession(t *testing.T) {
	secret := []byte("GO-TPM2-SEALED-SECRET")
	// Response: parameterSize || TPM2B_SENSITIVE_DATA(secret).
	var rp []byte
	rp = common.PutU32(rp, 0)
	rp = append(rp, common.MarshalTPM2B(secret)...)
	ft := &fakeTransport{rsp: sessResp(rp)}
	tpm := New(ft)

	got, err := tpm.Unseal(0x80000002, 0x03000000)
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("secret = %x", got)
	}

	//   itemHandle        = 80 00 00 02
	//   authorizationSize = 00 00 00 09
	//   TPMS_AUTH_COMMAND carrying the POLICY SESSION:
	//       sessionHandle = 03 00 00 00   (NOT 40 00 00 09 RS_PW!)
	//       nonce         = 00 00
	//       attributes    = 01 (continueSession)
	//       hmac          = 00 00
	var params []byte
	params = append(params, 0x80, 0x00, 0x00, 0x02)
	params = append(params, 0x00, 0x00, 0x00, 0x09)
	params = append(params, 0x03, 0x00, 0x00, 0x00) // the policy session handle
	params = append(params, 0x00, 0x00, 0x01, 0x00, 0x00)
	want := common.BuildCommand(uint16(common.TagSessions), uint32(ccUnseal), params)
	if !bytes.Equal(ft.gotCmd, want) {
		t.Fatalf("Unseal request bytes\n got %x\nwant %x", ft.gotCmd, want)
	}
	// Guard against a regression to RS_PW: the password handle must NOT appear.
	if bytes.Contains(ft.gotCmd, []byte{0x40, 0x00, 0x00, 0x09}) {
		t.Fatalf("Unseal auth area wrongly carries TPM_RS_PW instead of the session")
	}
}

// --- High-level helpers ---

func TestSealToPCR(t *testing.T) {
	sel := []PCRSelection{{Hash: uint16(common.AlgSHA256), PCRs: []int{16}}}
	pcrVal := bytes.Repeat([]byte{0xAA}, 32)
	priv := []byte{0x11}
	pub := []byte{0x22}
	var rp []byte
	rp = common.PutU32(rp, 0)
	rp = append(rp, common.MarshalTPM2B(priv)...)
	rp = append(rp, common.MarshalTPM2B(pub)...)
	ft := &fakeTransport{rsp: sessResp(rp)}
	tpm := New(ft)

	gotPriv, gotPub, policy, err := tpm.SealToPCR(0x80000001, []byte("s"), sel, [][]byte{pcrVal})
	if err != nil {
		t.Fatalf("SealToPCR: %v", err)
	}
	if !bytes.Equal(gotPriv, priv) || !bytes.Equal(gotPub, pub) {
		t.Fatalf("SealToPCR priv/pub = %x/%x", gotPriv, gotPub)
	}
	if !bytes.Equal(policy, PolicyPCRDigest(sel, [][]byte{pcrVal})) {
		t.Fatalf("SealToPCR policy mismatch")
	}
}

// scriptedTransport returns a queued sequence of responses (one per Send),
// for exercising multi-command helpers. An error entry short-circuits.
type scriptedTransport struct {
	rsps [][]byte
	errs []error
	i    int
	cmds [][]byte
}

func (s *scriptedTransport) Send(cmd []byte) ([]byte, error) {
	s.cmds = append(s.cmds, append([]byte(nil), cmd...))
	idx := s.i
	s.i++
	if idx < len(s.errs) && s.errs[idx] != nil {
		return nil, s.errs[idx]
	}
	return s.rsps[idx], nil
}

func TestUnsealWithPCR(t *testing.T) {
	sel := []PCRSelection{{Hash: uint16(common.AlgSHA256), PCRs: []int{16}}}
	secret := []byte("GO-TPM2-SEALED-SECRET")

	// Load resp: objectHandle || parameterSize || TPM2B_NAME(empty).
	loadRsp := sessResp([]byte{0x80, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	// StartAuthSession resp (TagNoSessions): sessionHandle || TPM2B_NONCE.
	var sasParams []byte
	sasParams = common.PutU32(sasParams, 0x03000000)
	sasParams = append(sasParams, common.MarshalTPM2B(bytes.Repeat([]byte{0x01}, 32))...)
	sasRsp := okResp(sasParams)
	// PolicyPCR resp: empty.
	polRsp := okResp(nil)
	// Unseal resp: parameterSize || TPM2B_SENSITIVE_DATA(secret).
	var unsealParams []byte
	unsealParams = common.PutU32(unsealParams, 0)
	unsealParams = append(unsealParams, common.MarshalTPM2B(secret)...)
	unsealRsp := sessResp(unsealParams)

	st := &scriptedTransport{rsps: [][]byte{loadRsp, sasRsp, polRsp, unsealRsp}}
	tpm := New(st)

	got, err := tpm.UnsealWithPCR(0x80000001, []byte("p"), []byte("u"), sel, bytes.Repeat([]byte{0x5A}, 32))
	if err != nil {
		t.Fatalf("UnsealWithPCR: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("secret = %x", got)
	}
	if len(st.cmds) != 4 {
		t.Fatalf("expected 4 commands, got %d", len(st.cmds))
	}
}

// --- error branches ---

func TestSealErrorBranches(t *testing.T) {
	wantErr := errors.New("io fail")
	sel := []PCRSelection{{Hash: uint16(common.AlgSHA256), PCRs: []int{16}}}

	t.Run("CreateStoragePrimary transport", func(t *testing.T) {
		if _, err := New(&fakeTransport{err: wantErr}).CreateStoragePrimary(); !errors.Is(err, wantErr) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("CreateStoragePrimary short handle", func(t *testing.T) {
		ft := &fakeTransport{rsp: sessResp([]byte{0x00})}
		if _, err := New(ft).CreateStoragePrimary(); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("Create transport", func(t *testing.T) {
		if _, _, err := New(&fakeTransport{err: wantErr}).Create(1, nil, nil); !errors.Is(err, wantErr) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("Create short parameterSize", func(t *testing.T) {
		ft := &fakeTransport{rsp: sessResp([]byte{0x00})}
		if _, _, err := New(ft).Create(1, nil, nil); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("Create short private", func(t *testing.T) {
		// parameterSize present, but the TPM2B_PRIVATE is truncated.
		rp := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x05} // size says 5, no bytes
		ft := &fakeTransport{rsp: sessResp(rp)}
		if _, _, err := New(ft).Create(1, nil, nil); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("Create short public", func(t *testing.T) {
		var rp []byte
		rp = common.PutU32(rp, 0)
		rp = append(rp, common.MarshalTPM2B([]byte{0x01})...) // valid private
		rp = append(rp, 0x00, 0x05)                           // public size 5, no bytes
		ft := &fakeTransport{rsp: sessResp(rp)}
		if _, _, err := New(ft).Create(1, nil, nil); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("Load transport", func(t *testing.T) {
		if _, err := New(&fakeTransport{err: wantErr}).Load(1, nil, nil); !errors.Is(err, wantErr) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("Load short handle", func(t *testing.T) {
		ft := &fakeTransport{rsp: sessResp([]byte{0x00})}
		if _, err := New(ft).Load(1, nil, nil); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("StartAuthSession transport", func(t *testing.T) {
		if _, _, err := New(&fakeTransport{err: wantErr}).StartAuthSession(nil); !errors.Is(err, wantErr) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("StartAuthSession short handle", func(t *testing.T) {
		ft := &fakeTransport{rsp: okResp([]byte{0x00})}
		if _, _, err := New(ft).StartAuthSession(nil); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("StartAuthSession short nonceTPM", func(t *testing.T) {
		// handle present (4 bytes) but the TPM2B_NONCE is truncated.
		rp := []byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x05}
		ft := &fakeTransport{rsp: okResp(rp)}
		if _, _, err := New(ft).StartAuthSession(nil); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("PolicyPCR transport", func(t *testing.T) {
		if err := New(&fakeTransport{err: wantErr}).PolicyPCR(1, sel); !errors.Is(err, wantErr) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("PolicyGetDigest transport", func(t *testing.T) {
		if _, err := New(&fakeTransport{err: wantErr}).PolicyGetDigest(1); !errors.Is(err, wantErr) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("PolicyGetDigest short digest", func(t *testing.T) {
		ft := &fakeTransport{rsp: okResp([]byte{0x00})}
		if _, err := New(ft).PolicyGetDigest(1); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("Unseal transport", func(t *testing.T) {
		if _, err := New(&fakeTransport{err: wantErr}).Unseal(1, 2); !errors.Is(err, wantErr) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("Unseal short parameterSize", func(t *testing.T) {
		ft := &fakeTransport{rsp: sessResp([]byte{0x00})}
		if _, err := New(ft).Unseal(1, 2); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("Unseal short data", func(t *testing.T) {
		rp := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x05} // parameterSize + bad TPM2B
		ft := &fakeTransport{rsp: sessResp(rp)}
		if _, err := New(ft).Unseal(1, 2); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
}

// TestSealToPCRError drives SealToPCR's Create-error branch.
func TestSealToPCRError(t *testing.T) {
	sel := []PCRSelection{{Hash: uint16(common.AlgSHA256), PCRs: []int{16}}}
	if _, _, _, err := New(&fakeTransport{err: errors.New("x")}).
		SealToPCR(1, nil, sel, [][]byte{{0x00}}); err == nil {
		t.Fatalf("expected error")
	}
}

// TestUnsealWithPCRErrors drives each early-return branch of UnsealWithPCR.
func TestUnsealWithPCRErrors(t *testing.T) {
	sel := []PCRSelection{{Hash: uint16(common.AlgSHA256), PCRs: []int{16}}}
	nonce := bytes.Repeat([]byte{0x5A}, 32)

	loadRsp := sessResp([]byte{0x80, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	var sasParams []byte
	sasParams = common.PutU32(sasParams, 0x03000000)
	sasParams = append(sasParams, common.MarshalTPM2B(bytes.Repeat([]byte{0x01}, 32))...)
	sasRsp := okResp(sasParams)
	polRsp := okResp(nil)

	t.Run("Load fails", func(t *testing.T) {
		st := &scriptedTransport{rsps: [][]byte{nil}, errs: []error{errors.New("load")}}
		if _, err := New(st).UnsealWithPCR(1, nil, nil, sel, nonce); err == nil {
			t.Fatalf("expected error")
		}
	})
	t.Run("StartAuthSession fails", func(t *testing.T) {
		st := &scriptedTransport{rsps: [][]byte{loadRsp, nil}, errs: []error{nil, errors.New("sas")}}
		if _, err := New(st).UnsealWithPCR(1, nil, nil, sel, nonce); err == nil {
			t.Fatalf("expected error")
		}
	})
	t.Run("PolicyPCR fails", func(t *testing.T) {
		st := &scriptedTransport{rsps: [][]byte{loadRsp, sasRsp, nil}, errs: []error{nil, nil, errors.New("pol")}}
		if _, err := New(st).UnsealWithPCR(1, nil, nil, sel, nonce); err == nil {
			t.Fatalf("expected error")
		}
	})
	t.Run("Unseal fails", func(t *testing.T) {
		st := &scriptedTransport{
			rsps: [][]byte{loadRsp, sasRsp, polRsp, nil},
			errs: []error{nil, nil, nil, errors.New("unseal")},
		}
		if _, err := New(st).UnsealWithPCR(1, nil, nil, sel, nonce); err == nil {
			t.Fatalf("expected error")
		}
	})
}
