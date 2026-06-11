// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/tpm2 authors. All rights reserved.

package tpm2

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/go-tpm2/common"
)

// seqTransport returns canned responses in order, recording every command it
// is sent. It drives multi-command flows (ActivateAKWithEK issues
// StartAuthSession -> PolicySecret -> ActivateCredential).
type seqTransport struct {
	cmds  [][]byte // recorded commands, in order
	rsps  [][]byte // canned responses, consumed in order
	err   error    // if non-nil, returned once at errAt
	errAt int
	i     int
}

func (s *seqTransport) Send(cmd []byte) ([]byte, error) {
	s.cmds = append(s.cmds, append([]byte(nil), cmd...))
	if s.err != nil && s.i == s.errAt {
		s.i++
		return nil, s.err
	}
	r := s.rsps[s.i]
	s.i++
	return r, nil
}

// --- PolicySecret request bytes (hand-derived) ---

func TestPolicySecretRequestBytes(t *testing.T) {
	// Response (TagSessions): parameterSize || TPM2B_TIMEOUT || TPMT_TK_AUTH.
	rp := concat(
		[]byte{0x00, 0x00, 0x00, 0x00}, // parameterSize
		[]byte{0x00, 0x00},             // timeout: empty TPM2B
		// TPMT_TK_AUTH: tag(u16) hierarchy(u32) digest(TPM2B empty)
		[]byte{0x80, 0x23, 0x40, 0x00, 0x00, 0x0B, 0x00, 0x00},
	)
	ft := &fakeTransport{rsp: sessOK(rp)}
	tpm := New(ft)

	if err := tpm.PolicySecret(RHEndorsement, 0x03000000); err != nil {
		t.Fatalf("PolicySecret: %v", err)
	}

	// Hand-derived param area:
	//   handle area: authHandle = 4000000B || policySession = 03000000
	//   auth area:   authorizationSize 00000009 || RS_PW session
	//   params: nonceTPM 0000 || cpHashA 0000 || policyRef 0000 || expiration 00000000
	var params []byte
	params = append(params, 0x40, 0x00, 0x00, 0x0B)             // RH_ENDORSEMENT
	params = append(params, 0x03, 0x00, 0x00, 0x00)             // policySession
	params = append(params, 0x00, 0x00, 0x00, 0x09)             // authorizationSize
	params = append(params, rsPWAuth()...)                      // RS_PW
	params = append(params, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // nonceTPM,cpHashA,policyRef
	params = append(params, 0x00, 0x00, 0x00, 0x00)             // expiration

	want := common.BuildCommand(uint16(common.TagSessions), uint32(ccPolicySecret), params)
	if !bytes.Equal(ft.gotCmd, want) {
		t.Fatalf("PolicySecret request bytes\n got %x\nwant %x", ft.gotCmd, want)
	}
}

func TestPolicySecretError(t *testing.T) {
	ft := &fakeTransport{err: errors.New("transport down")}
	tpm := New(ft)
	if err := tpm.PolicySecret(RHEndorsement, 0x03000000); err == nil {
		t.Fatalf("expected transport error")
	}
}

// --- marshalAuthArea: dual session layout ---

func TestMarshalAuthAreaDual(t *testing.T) {
	a := []byte{0xAA, 0xAA}
	b := []byte{0xBB}
	got := marshalAuthArea(a, b)
	// authorizationSize covers len(a)+len(b) = 3, then a||b.
	want := []byte{0x00, 0x00, 0x00, 0x03, 0xAA, 0xAA, 0xBB}
	if !bytes.Equal(got, want) {
		t.Fatalf("marshalAuthArea\n got %x\nwant %x", got, want)
	}
}

// --- ActivateCredential request bytes (dual handle + dual auth area) ---

func TestActivateCredentialRequestBytes(t *testing.T) {
	// Response (TagSessions): parameterSize || TPM2B_DIGEST certInfo.
	certInfo := bytes.Repeat([]byte{0xCC}, 32)
	rp := concat([]byte{0x00, 0x00, 0x00, 0x00}, common.MarshalTPM2B(certInfo))
	ft := &fakeTransport{rsp: sessOK(rp)}
	tpm := New(ft)

	ak := uint32(0x80000001)
	ek := uint32(0x80000002)
	session := uint32(0x03000000)
	blob := common.MarshalTPM2B(bytes.Repeat([]byte{0x11}, 70))   // a TPM2B_ID_OBJECT
	secret := common.MarshalTPM2B(bytes.Repeat([]byte{0x22}, 68)) // a TPM2B_ENCRYPTED_SECRET

	got, err := tpm.ActivateCredential(ak, ek, session, blob, secret)
	if err != nil {
		t.Fatalf("ActivateCredential: %v", err)
	}
	if !bytes.Equal(got, certInfo) {
		t.Fatalf("certInfo = %x, want %x", got, certInfo)
	}

	// Hand-derived:
	//   handle area: AK 80000001 || EK 80000002
	//   auth area:   authorizationSize (= 9 + 9 = 18 = 0x12) ||
	//                AK RS_PW (9) || EK policy-session (9)
	//   params:      blob (already TPM2B) || secret (already TPM2B)
	ekPolicyAuth := concat(
		[]byte{0x03, 0x00, 0x00, 0x00}, // policy session handle
		[]byte{0x00, 0x00},             // nonce empty
		[]byte{0x01},                   // continueSession
		[]byte{0x00, 0x00},             // hmac empty
	)
	var params []byte
	params = append(params, 0x80, 0x00, 0x00, 0x01) // AK
	params = append(params, 0x80, 0x00, 0x00, 0x02) // EK
	params = append(params, 0x00, 0x00, 0x00, 0x12) // authorizationSize = 18
	params = append(params, rsPWAuth()...)          // AK RS_PW (handle #1)
	params = append(params, ekPolicyAuth...)        // EK policy (handle #2)
	params = append(params, blob...)
	params = append(params, secret...)

	want := common.BuildCommand(uint16(common.TagSessions), uint32(ccActivateCredential), params)
	if !bytes.Equal(ft.gotCmd, want) {
		t.Fatalf("ActivateCredential request bytes\n got %x\nwant %x", ft.gotCmd, want)
	}
}

func TestActivateCredentialTransportError(t *testing.T) {
	ft := &fakeTransport{err: errors.New("down")}
	tpm := New(ft)
	if _, err := tpm.ActivateCredential(1, 2, 3, []byte{0x00, 0x00}, []byte{0x00, 0x00}); err == nil {
		t.Fatalf("expected transport error")
	}
}

func TestActivateCredentialShortParamSize(t *testing.T) {
	// Response with fewer than 4 bytes: parameterSize parse fails.
	ft := &fakeTransport{rsp: sessOK([]byte{0x00})}
	tpm := New(ft)
	if _, err := tpm.ActivateCredential(1, 2, 3, []byte{0x00, 0x00}, []byte{0x00, 0x00}); err != common.ErrShortBuffer {
		t.Fatalf("err = %v, want ErrShortBuffer", err)
	}
}

func TestActivateCredentialShortCertInfo(t *testing.T) {
	// parameterSize present but the TPM2B_DIGEST is truncated.
	ft := &fakeTransport{rsp: sessOK([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x01})}
	tpm := New(ft)
	if _, err := tpm.ActivateCredential(1, 2, 3, []byte{0x00, 0x00}, []byte{0x00, 0x00}); err == nil {
		t.Fatalf("expected short-buffer error on certInfo")
	}
}

// --- ActivateAKWithEK: full off-TPM make + 3-command flow ---

// ekKeyPair builds an in-test EK key pair and the EKPublic / TPMT_PUBLIC for
// it, plus a recover-side private key. The TPMT_PUBLIC mirrors the EK L-2
// template with the real point in unique.
func ekTPMTPublic(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ek keygen: %v", err)
	}
	x := leftPad(priv.X.Bytes(), 32)
	y := leftPad(priv.Y.Bytes(), 32)
	// Minimal TPMT_PUBLIC the ECC-point parser accepts: type, nameAlg, attrs,
	// authPolicy(empty), sym NULL, scheme NULL, curve P256, kdf NULL, unique.
	var p []byte
	p = common.PutU16(p, AlgECC)
	p = common.PutU16(p, algSHA256)
	p = common.PutU32(p, ekObjectAttributes)
	p = common.PutU16(p, 0)           // authPolicy empty (keep parse simple)
	p = common.PutU16(p, algNull)     // symmetric NULL
	p = common.PutU16(p, algNull)     // scheme NULL
	p = common.PutU16(p, ECCNistP256) // curve
	p = common.PutU16(p, algNull)     // kdf NULL
	p = append(p, common.MarshalTPM2B(x)...)
	p = append(p, common.MarshalTPM2B(y)...)
	return priv, p
}

func TestActivateAKWithEKFlow(t *testing.T) {
	ekPriv, ekPub := ekTPMTPublic(t)

	// AK public area (a signing-key TPMT_PUBLIC); its Name is what gets bound.
	akPub := marshalAKPublicArea()
	akName, err := ObjectName(akPub)
	if err != nil {
		t.Fatalf("ObjectName: %v", err)
	}

	credential := []byte("GO-TPM2-CRED-CHALLENGE-32bytes!!")
	ak := uint32(0x80000001)
	ek := uint32(0x80000002)
	session := uint32(0x03000000)
	nonce := bytes.Repeat([]byte{0x5A}, 32)

	// Canned responses: StartAuthSession (handle||nonceTPM), PolicySecret,
	// ActivateCredential (parameterSize||TPM2B_DIGEST certInfo). We do not have
	// the TPM's private EK here, so we cannot produce a genuine recovered
	// value; we assert the certInfo the (faked) TPM "returns" is plumbed back,
	// and separately verify the off-TPM crypto with the live swtpm harness.
	startResp := sessRespStart(session, bytes.Repeat([]byte{0x01}, 32))
	policyResp := sessOK(concat([]byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00},
		[]byte{0x80, 0x23, 0x40, 0x00, 0x00, 0x0B, 0x00, 0x00}))
	echoed := bytes.Repeat([]byte{0xAB}, 32)
	actResp := sessOK(concat([]byte{0x00, 0x00, 0x00, 0x00}, common.MarshalTPM2B(echoed)))

	st := &seqTransport{rsps: [][]byte{startResp, policyResp, actResp}}
	tpm := New(st)

	got, err := tpm.ActivateAKWithEK(ak, ek, akPub, ekPub, credential, nonce)
	if err != nil {
		t.Fatalf("ActivateAKWithEK: %v", err)
	}
	if !bytes.Equal(got, echoed) {
		t.Fatalf("recovered %x, want echoed %x", got, echoed)
	}

	// Three commands issued, in order.
	if len(st.cmds) != 3 {
		t.Fatalf("issued %d commands, want 3", len(st.cmds))
	}
	// The 3rd command (ActivateCredential) must carry the AK Name binding:
	// recompute MakeCredential off-TPM and confirm the on-wire blob/secret
	// decrypt back to the credential under ekPriv. Extract params from cmd[2].
	_, _, p3, err := common.ParseResponse(reframeAsResp(st.cmds[2]))
	if err != nil {
		t.Fatalf("reparse activate cmd: %v", err)
	}
	// Skip handle area (8 = two u32 handles), then the auth area whose size is
	// read from its leading authorizationSize (u32), to reach the params.
	authSize, ok := common.GetU32(p3, 8)
	if !ok {
		t.Fatalf("read authorizationSize")
	}
	off := 8 + 4 + int(authSize)
	// The on-wire params are the complete TPM2B_ID_OBJECT and
	// TPM2B_ENCRYPTED_SECRET (already wrapped) — the MakeCredentialResult
	// shape recoverCredential consumes. Split them at the first TPM2B end.
	_, rest, err := common.UnmarshalTPM2B(p3[off:])
	if err != nil {
		t.Fatalf("on-wire credentialBlob: %v", err)
	}
	blobWire := p3[off : len(p3)-len(rest)]
	secretWire := append([]byte(nil), rest...)
	rec := recoverCredential(t, ekPriv, akName,
		MakeCredentialResult{CredentialBlob: blobWire, Secret: secretWire})
	if !bytes.Equal(rec, credential) {
		t.Fatalf("on-wire blob did not bind credential: recovered %x", rec)
	}
}

// Error-branch coverage for ActivateAKWithEK.

func TestActivateAKWithEKBadAKPublic(t *testing.T) {
	_, ekPub := ekTPMTPublic(t)
	tpm := New(&seqTransport{})
	if _, err := tpm.ActivateAKWithEK(1, 2, []byte{0x00}, ekPub, []byte("x"), nil); err == nil {
		t.Fatalf("expected ObjectName error for short AK public")
	}
}

func TestActivateAKWithEKBadEKPublic(t *testing.T) {
	akPub := marshalAKPublicArea()
	tpm := New(&seqTransport{})
	// EK public area too short to parse the ECC point.
	if _, err := tpm.ActivateAKWithEK(1, 2, akPub, []byte{0x00, 0x23, 0x00, 0x0B}, []byte("x"), nil); err == nil {
		t.Fatalf("expected EK point parse error")
	}
}

func TestActivateAKWithEKBadEKPoint(t *testing.T) {
	akPub := marshalAKPublicArea()
	// Valid TPMT_PUBLIC shape but an off-curve point -> MakeCredential rejects.
	var p []byte
	p = common.PutU16(p, AlgECC)
	p = common.PutU16(p, algSHA256)
	p = common.PutU32(p, ekObjectAttributes)
	p = common.PutU16(p, 0)
	p = common.PutU16(p, algNull)
	p = common.PutU16(p, algNull)
	p = common.PutU16(p, ECCNistP256)
	p = common.PutU16(p, algNull)
	p = append(p, common.MarshalTPM2B([]byte{0x01})...) // x
	p = append(p, common.MarshalTPM2B([]byte{0x02})...) // y
	tpm := New(&seqTransport{})
	if _, err := tpm.ActivateAKWithEK(1, 2, akPub, p, []byte("x"), nil); err != ErrEKPointNotOnCurve {
		t.Fatalf("err = %v, want ErrEKPointNotOnCurve", err)
	}
}

func TestActivateAKWithEKStartSessionError(t *testing.T) {
	_, ekPub := ekTPMTPublic(t)
	akPub := marshalAKPublicArea()
	st := &seqTransport{rsps: [][]byte{nil}, err: errors.New("start down"), errAt: 0}
	tpm := New(st)
	if _, err := tpm.ActivateAKWithEK(1, 2, akPub, ekPub, []byte("x"), make([]byte, 32)); err == nil {
		t.Fatalf("expected StartAuthSession error")
	}
}

func TestActivateAKWithEKPolicySecretError(t *testing.T) {
	_, ekPub := ekTPMTPublic(t)
	akPub := marshalAKPublicArea()
	startResp := sessRespStart(0x03000000, bytes.Repeat([]byte{0x01}, 32))
	st := &seqTransport{rsps: [][]byte{startResp, nil}, err: errors.New("policy down"), errAt: 1}
	tpm := New(st)
	if _, err := tpm.ActivateAKWithEK(1, 2, akPub, ekPub, []byte("x"), make([]byte, 32)); err == nil {
		t.Fatalf("expected PolicySecret error")
	}
}

func TestActivateAKWithEKActivateError(t *testing.T) {
	_, ekPub := ekTPMTPublic(t)
	akPub := marshalAKPublicArea()
	startResp := sessRespStart(0x03000000, bytes.Repeat([]byte{0x01}, 32))
	policyResp := sessOK(concat([]byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00},
		[]byte{0x80, 0x23, 0x40, 0x00, 0x00, 0x0B, 0x00, 0x00}))
	st := &seqTransport{rsps: [][]byte{startResp, policyResp, nil}, err: errors.New("act down"), errAt: 2}
	tpm := New(st)
	if _, err := tpm.ActivateAKWithEK(1, 2, akPub, ekPub, []byte("x"), make([]byte, 32)); err == nil {
		t.Fatalf("expected ActivateCredential error")
	}
}

// --- small test helpers ---

// sessRespStart builds a StartAuthSession success response:
// sessionHandle || TPM2B_NONCE nonceTPM, under TagSessions? No: the harness's
// StartAuthSession is TagNoSessions, but execute only checks the rc, so a
// TagSessions/NoSessions wrapper is interchangeable for the parse here. We use
// NoSessions to mirror the real reply tag.
func sessRespStart(handle uint32, nonceTPM []byte) []byte {
	params := common.PutU32(nil, handle)
	params = append(params, common.MarshalTPM2B(nonceTPM)...)
	return noSessOK(params)
}

// marshalAKPublicArea returns the AK's TPMT_PUBLIC bytes (the content of the
// TPM2B_PUBLIC) by stripping the 2-byte size prefix marshalECCAKPublic emits.
func marshalAKPublicArea() []byte {
	full := marshalECCAKPublic() // TPM2B_PUBLIC
	inner, _, err := common.UnmarshalTPM2B(full)
	if err != nil {
		panic(err)
	}
	return append([]byte(nil), inner...)
}

// reframeAsResp wraps a recorded COMMAND buffer so common.ParseResponse can
// re-read it: a command and a response share the [tag|size|code|params] shape,
// so the recorded command parses as a "response" whose params are the command
// body. Used only to re-extract the command body in tests.
func reframeAsResp(cmd []byte) []byte { return cmd }
