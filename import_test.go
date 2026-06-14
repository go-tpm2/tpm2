// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/tpm2 authors. All rights reserved.

package tpm2

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
	"testing"

	"github.com/go-tpm2/common"
)

// recoverDuplicate reverses WrapToPCR the way a TPM holding the SRK private key
// does during TPM2_Import: ECDH to Z, KDFe seed (label "DUPLICATE"), KDFa
// symKey + HMACkey, verify the outer HMAC over (encSensitive || objectName),
// AES-CFB-decrypt the sensitive area, and unwrap TPMT_SENSITIVE down to the
// sealed payload. It is the in-test ORACLE that makes the round trip
// self-consistent without a TPM; the live swtpm is the independent oracle.
func recoverDuplicate(t *testing.T, srkPriv *ecdsa.PrivateKey, res WrapToPCRResult) []byte {
	t.Helper()
	curve := elliptic.P256()

	objectName, err := ObjectName(res.ObjectPublic)
	if err != nil {
		t.Fatalf("ObjectName: %v", err)
	}

	// inSymSeed = TPM2B_ENCRYPTED_SECRET( TPMS_ECC_POINT{x,y} ).
	point, _, err := common.UnmarshalTPM2B(res.InSymSeed)
	if err != nil {
		t.Fatalf("inSymSeed unmarshal: %v", err)
	}
	qeX, rest, err := common.UnmarshalTPM2B(point)
	if err != nil {
		t.Fatalf("point.x: %v", err)
	}
	qeY, _, err := common.UnmarshalTPM2B(rest)
	if err != nil {
		t.Fatalf("point.y: %v", err)
	}

	// Z = x-coord of srkPriv.D * Qe.
	zx, _ := curve.ScalarMult(new(big.Int).SetBytes(qeX), new(big.Int).SetBytes(qeY), srkPriv.D.Bytes())
	z := leftPad(zx.Bytes(), 32)

	srkXfix := leftPad(srkPriv.X.Bytes(), 32)
	seed := KDFe(z, labelDuplicate, leftPad(qeX, 32), srkXfix, 256)
	symKey := KDFa(seed, labelStorage, objectName, nil, 128)
	hmacKey := KDFa(seed, labelIntegrity, nil, nil, 256)

	// duplicate = TPM2B( TPM2B(outerHMAC) || encSensitive ).
	dup, _, err := common.UnmarshalTPM2B(res.Duplicate)
	if err != nil {
		t.Fatalf("duplicate outer: %v", err)
	}
	outerHMAC, encSensitive, err := common.UnmarshalTPM2B(dup)
	if err != nil {
		t.Fatalf("outerHMAC: %v", err)
	}

	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(encSensitive)
	mac.Write(objectName)
	if !hmac.Equal(outerHMAC, mac.Sum(nil)) {
		t.Fatalf("outer HMAC mismatch (wrap crypto wrong)")
	}

	block, _ := aes.NewCipher(symKey)
	iv := make([]byte, block.BlockSize())
	plain := make([]byte, len(encSensitive))
	cipher.NewCFBDecrypter(block, iv).XORKeyStream(plain, encSensitive)

	// plain = TPM2B(TPMT_SENSITIVE). TPMT_SENSITIVE =
	//   sensitiveType(u16) authValue(TPM2B) seedValue(TPM2B) sensitive(TPM2B).
	sens, _, err := common.UnmarshalTPM2B(plain)
	if err != nil {
		t.Fatalf("sensitive TPM2B: %v", err)
	}
	if st, _ := common.GetU16(sens, 0); st != algKeyedHash {
		t.Fatalf("sensitiveType = %#x, want keyedhash", st)
	}
	_, after, err := common.UnmarshalTPM2B(sens[2:]) // authValue
	if err != nil {
		t.Fatalf("authValue: %v", err)
	}
	_, after2, err := common.UnmarshalTPM2B(after) // seedValue
	if err != nil {
		t.Fatalf("seedValue: %v", err)
	}
	payload, _, err := common.UnmarshalTPM2B(after2) // sensitive data
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	return payload
}

func testSRK(t *testing.T) (*ecdsa.PrivateKey, ECCPublic) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("srk keygen: %v", err)
	}
	return priv, ECCPublic{X: leftPad(priv.X.Bytes(), 32), Y: leftPad(priv.Y.Bytes(), 32)}
}

func testSel() ([]PCRSelection, [][]byte) {
	sel := []PCRSelection{{Hash: uint16(common.AlgSHA256), PCRs: []int{16}}}
	pcrVal := bytes.Repeat([]byte{0xAA}, 32)
	return sel, [][]byte{pcrVal}
}

// TestWrapToPCRRoundTrip is the self-consistent off-TPM proof: WrapToPCR then
// recoverDuplicate (a TPM's inverse) returns the EXACT original secret, and the
// object's authPolicy equals the PolicyPCRDigest for the chosen PCRs.
func TestWrapToPCRRoundTrip(t *testing.T) {
	srkPriv, srkPub := testSRK(t)
	sel, vals := testSel()
	secret := []byte("GO-TPM2-IMPORTED-SECRET")

	res, err := WrapToPCR(srkPub, secret, sel, vals, rand.Reader)
	if err != nil {
		t.Fatalf("WrapToPCR: %v", err)
	}
	if got := recoverDuplicate(t, srkPriv, res); !bytes.Equal(got, secret) {
		t.Fatalf("recovered %q != original %q", got, secret)
	}

	// authPolicy in the object public must equal PolicyPCRDigest(sel, vals).
	want := PolicyPCRDigest(sel, vals)
	// TPMT_PUBLIC: type(2) nameAlg(2) attrs(4) then authPolicy TPM2B.
	authPolicy, _, err := common.UnmarshalTPM2B(res.ObjectPublic[8:])
	if err != nil {
		t.Fatalf("authPolicy parse: %v", err)
	}
	if !bytes.Equal(authPolicy, want) {
		t.Fatalf("authPolicy %x != PolicyPCRDigest %x", authPolicy, want)
	}
}

// TestWrapToPCRKeyedHashBinding pins the keyedhash public/sensitive binding the
// TPM enforces at load (CryptValidateKeys -> CryptComputeSymmetricUnique): the
// sensitive's seedValue must be exactly nameAlg-digest sized, and the public
// `unique` must equal H_nameAlg(seedValue || data). A live swtpm rejected an
// empty seedValue/unique with TPM_RC_KEY_SIZE (rc 0x3C7) during Import, so this
// test guards the regression off-TPM.
func TestWrapToPCRKeyedHashBinding(t *testing.T) {
	srkPriv, srkPub := testSRK(t)
	sel, vals := testSel()
	secret := []byte("BINDING-PROBE")

	res, err := WrapToPCR(srkPub, secret, sel, vals, rand.Reader)
	if err != nil {
		t.Fatalf("WrapToPCR: %v", err)
	}

	// Recover the sensitive's seedValue (obfuscation value) the same way the
	// TPM does, and confirm it is 32 bytes (SHA-256 digest size).
	curve := elliptic.P256()
	objectName, _ := ObjectName(res.ObjectPublic)
	point, _, _ := common.UnmarshalTPM2B(res.InSymSeed)
	qeX, restp, _ := common.UnmarshalTPM2B(point)
	qeY, _, _ := common.UnmarshalTPM2B(restp)
	zx, _ := curve.ScalarMult(new(big.Int).SetBytes(qeX), new(big.Int).SetBytes(qeY), srkPriv.D.Bytes())
	seed := KDFe(leftPad(zx.Bytes(), 32), labelDuplicate, leftPad(qeX, 32), leftPad(srkPriv.X.Bytes(), 32), 256)
	symKey := KDFa(seed, labelStorage, objectName, nil, 128)
	dup, _, _ := common.UnmarshalTPM2B(res.Duplicate)
	_, encSensitive, _ := common.UnmarshalTPM2B(dup)
	block, _ := aes.NewCipher(symKey)
	plain := make([]byte, len(encSensitive))
	cipher.NewCFBDecrypter(block, make([]byte, block.BlockSize())).XORKeyStream(plain, encSensitive)
	sens, _, _ := common.UnmarshalTPM2B(plain)
	_, afterAuth, _ := common.UnmarshalTPM2B(sens[2:]) // skip authValue
	seedValue, afterSeed, _ := common.UnmarshalTPM2B(afterAuth)
	data, _, _ := common.UnmarshalTPM2B(afterSeed)
	if len(seedValue) != sha256.Size {
		t.Fatalf("seedValue len = %d, want %d", len(seedValue), sha256.Size)
	}
	if !bytes.Equal(data, secret) {
		t.Fatalf("recovered data %q != %q", data, secret)
	}

	// unique field in the public must equal H(seedValue || data).
	// TPMT_PUBLIC: type(2) nameAlg(2) attrs(4) authPolicy(TPM2B) scheme(2)
	// unique(TPM2B). Skip past authPolicy and scheme to read unique.
	_, afterPolicy, err := common.UnmarshalTPM2B(res.ObjectPublic[8:])
	if err != nil {
		t.Fatalf("authPolicy parse: %v", err)
	}
	unique, _, err := common.UnmarshalTPM2B(afterPolicy[2:]) // skip scheme (2 bytes)
	if err != nil {
		t.Fatalf("unique parse: %v", err)
	}
	uh := sha256.New()
	uh.Write(seedValue)
	uh.Write(data)
	if !bytes.Equal(unique, uh.Sum(nil)) {
		t.Fatalf("unique %x != H(seedValue||data) %x", unique, uh.Sum(nil))
	}
}

// TestWrapToPCRWrongPCRPolicy proves the PCR binding: wrapping to one PCR value
// yields an authPolicy different from any other PCR value's digest. The TPM
// enforces this at Unseal; here it is visible in the public area.
func TestWrapToPCRWrongPCRPolicy(t *testing.T) {
	_, srkPub := testSRK(t)
	sel := []PCRSelection{{Hash: uint16(common.AlgSHA256), PCRs: []int{16}}}
	good := [][]byte{bytes.Repeat([]byte{0xAA}, 32)}
	bad := [][]byte{bytes.Repeat([]byte{0xBB}, 32)}

	res, err := WrapToPCR(srkPub, []byte("s"), sel, good, rand.Reader)
	if err != nil {
		t.Fatalf("WrapToPCR: %v", err)
	}
	authPolicy, _, _ := common.UnmarshalTPM2B(res.ObjectPublic[8:])
	if bytes.Equal(authPolicy, PolicyPCRDigest(sel, bad)) {
		t.Fatalf("authPolicy matched a DIFFERENT PCR value (binding broken)")
	}
	if !bytes.Equal(authPolicy, PolicyPCRDigest(sel, good)) {
		t.Fatalf("authPolicy does not match the wrapped-to PCR value")
	}
}

// TestWrapToPCRStructure pins the wire shapes of the three outputs.
func TestWrapToPCRStructure(t *testing.T) {
	_, srkPub := testSRK(t)
	sel, vals := testSel()
	secret := bytes.Repeat([]byte{0x5A}, 20)

	res, err := WrapToPCR(srkPub, secret, sel, vals, rand.Reader)
	if err != nil {
		t.Fatalf("WrapToPCR: %v", err)
	}

	// Duplicate: TPM2B( TPM2B(32-byte HMAC) || encSensitive ).
	dup, restd, err := common.UnmarshalTPM2B(res.Duplicate)
	if err != nil || len(restd) != 0 {
		t.Fatalf("duplicate outer TPM2B malformed: %v rest=%d", err, len(restd))
	}
	hmacVal, encSensitive, err := common.UnmarshalTPM2B(dup)
	if err != nil || len(hmacVal) != 32 {
		t.Fatalf("duplicate hmac len = %d: %v", len(hmacVal), err)
	}
	// encSensitive encrypts TPM2B(TPMT_SENSITIVE). TPMT_SENSITIVE for a 20-byte
	// payload is sensitiveType(2) + authValue(2) + seedValue(2 + 32-byte
	// obfuscation) + sensitive(2 + 20) = 60 bytes, plus its TPM2B prefix = 62.
	if len(encSensitive) != 62 {
		t.Fatalf("encSensitive len = %d, want 62", len(encSensitive))
	}

	// InSymSeed: TPM2B_ENCRYPTED_SECRET wrapping a point of two 32-byte coords.
	point, rests, err := common.UnmarshalTPM2B(res.InSymSeed)
	if err != nil || len(rests) != 0 {
		t.Fatalf("inSymSeed outer TPM2B malformed: %v rest=%d", err, len(rests))
	}
	x, rest, err := common.UnmarshalTPM2B(point)
	if err != nil || len(x) != 32 {
		t.Fatalf("point.x len = %d: %v", len(x), err)
	}
	y, rest2, err := common.UnmarshalTPM2B(rest)
	if err != nil || len(y) != 32 || len(rest2) != 0 {
		t.Fatalf("point.y len = %d rest=%d: %v", len(y), len(rest2), err)
	}
}

// TestWrapToPCRNilRNG covers the rng==nil default-to-crypto/rand branch.
func TestWrapToPCRNilRNG(t *testing.T) {
	srkPriv, srkPub := testSRK(t)
	sel, vals := testSel()
	res, err := WrapToPCR(srkPub, []byte("x"), sel, vals, nil)
	if err != nil {
		t.Fatalf("WrapToPCR(nil rng): %v", err)
	}
	if got := recoverDuplicate(t, srkPriv, res); !bytes.Equal(got, []byte("x")) {
		t.Fatalf("nil-rng round trip recovered %x", got)
	}
}

// TestWrapToPCRBadSRKPoint covers the off-curve SRK rejection.
func TestWrapToPCRBadSRKPoint(t *testing.T) {
	bad := ECCPublic{X: []byte{0x01}, Y: []byte{0x02}} // not on P-256
	sel, vals := testSel()
	_, err := WrapToPCR(bad, []byte("x"), sel, vals, rand.Reader)
	if err != ErrSRKPointNotOnCurve {
		t.Fatalf("err = %v, want ErrSRKPointNotOnCurve", err)
	}
}

// TestWrapToPCRObfuscateRNGFailure covers the seedValue (obfuscation value)
// io.ReadFull error branch — the FIRST rng draw in WrapToPCR.
func TestWrapToPCRObfuscateRNGFailure(t *testing.T) {
	_, srkPub := testSRK(t)
	sel, vals := testSel()
	if _, err := WrapToPCR(srkPub, []byte("x"), sel, vals, errReader{}); err == nil {
		t.Fatalf("expected obfuscation-value rng error from failing rng")
	}
}

// nByteReader yields n bytes (all 0xCB) across reads, then fails — enough for
// the 32-byte obfuscation value, after which the ephemeral ecdsa.GenerateKey
// draw fails, exercising WrapToPCR's keygen error branch (distinct from the
// obfuscate branch above).
type nByteReader struct{ left int }

func (r *nByteReader) Read(p []byte) (int, error) {
	if r.left <= 0 {
		return 0, errors.New("rng exhausted")
	}
	n := len(p)
	if n > r.left {
		n = r.left
	}
	for i := 0; i < n; i++ {
		p[i] = 0xCB
	}
	r.left -= n
	return n, nil
}

// TestWrapToPCRKeygenRNGFailure covers the ephemeral-keygen error branch: the
// rng satisfies the 32-byte obfuscation read, then runs dry for ecdsa keygen.
func TestWrapToPCRKeygenRNGFailure(t *testing.T) {
	_, srkPub := testSRK(t)
	sel, vals := testSel()
	if _, err := WrapToPCR(srkPub, []byte("x"), sel, vals, &nByteReader{left: 32}); err == nil {
		t.Fatalf("expected ephemeral-keygen error after obfuscation read")
	}
}

// --- Import request byte-for-byte assertion ---

func TestImportRequestBytes(t *testing.T) {
	objectPublic := []byte{0x00, 0x08, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x00} // arbitrary TPMT_PUBLIC bytes
	duplicate := common.MarshalTPM2B(bytes.Repeat([]byte{0xDD}, 10))
	inSymSeed := common.MarshalTPM2B(bytes.Repeat([]byte{0x5E}, 4))

	// Response: parameterSize || TPM2B_PRIVATE outPrivate.
	outPriv := common.MarshalTPM2B(bytes.Repeat([]byte{0x99}, 12))
	rp := common.PutU32(nil, uint32(len(outPriv)))
	rp = append(rp, outPriv...)
	ft := &fakeTransport{rsp: sessResp(rp)}
	tpm := New(ft)

	got, err := tpm.Import(0x80000001, objectPublic, duplicate, inSymSeed)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if !bytes.Equal(got, bytes.Repeat([]byte{0x99}, 12)) {
		t.Fatalf("outPrivate = %x", got)
	}

	// Hand-derive the body.
	var body []byte
	body = append(body, 0x80, 0x00, 0x00, 0x01)               // parentHandle
	body = append(body, 0x00, 0x00, 0x00, 0x09)               // authorizationSize
	body = append(body, rsPWAuth()...)                        // RS_PW session
	body = append(body, 0x00, 0x00)                           // encryptionKey: empty TPM2B_DATA
	body = append(body, common.MarshalTPM2B(objectPublic)...) // objectPublic TPM2B_PUBLIC
	body = append(body, duplicate...)                         // duplicate TPM2B_PRIVATE
	body = append(body, inSymSeed...)                         // inSymSeed TPM2B_ENCRYPTED_SECRET
	body = append(body, 0x00, 0x10)                           // symmetricAlg = TPM_ALG_NULL (no inner wrap)

	size := uint32(common.HeaderSize + len(body))
	want := []byte{0x80, 0x02}
	want = append(want, byte(size>>24), byte(size>>16), byte(size>>8), byte(size))
	want = append(want, 0x00, 0x00, 0x01, 0x56) // TPM2_Import
	want = append(want, body...)

	if !bytes.Equal(ft.gotCmd, want) {
		t.Fatalf("Import request bytes\n got %x\nwant %x", ft.gotCmd, want)
	}
}

// TestImportTransportError covers the execute-error branch.
func TestImportTransportError(t *testing.T) {
	ft := &fakeTransport{err: errors.New("io")}
	tpm := New(ft)
	if _, err := tpm.Import(1, nil, nil, nil); err == nil {
		t.Fatalf("expected transport error")
	}
}

// TestImportShortResponse covers the missing-parameterSize and short-TPM2B
// response branches.
func TestImportShortResponse(t *testing.T) {
	t.Run("no-paramSize", func(t *testing.T) {
		ft := &fakeTransport{rsp: sessResp([]byte{0x00, 0x00})} // < 4 bytes
		if _, err := New(ft).Import(1, nil, nil, nil); err != common.ErrShortBuffer {
			t.Fatalf("err = %v, want ErrShortBuffer", err)
		}
	})
	t.Run("short-private", func(t *testing.T) {
		// parameterSize present, but the TPM2B_PRIVATE size claims more than is
		// there.
		rp := []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0xFF}
		ft := &fakeTransport{rsp: sessResp(rp)}
		if _, err := New(ft).Import(1, nil, nil, nil); err == nil {
			t.Fatalf("expected short-buffer error on outPrivate")
		}
	})
}

// --- ImportAndUnseal: Import -> Load -> PolicyPCR -> Unseal sequencing ---

// scriptTransport returns a queued sequence of canned responses, one per Send,
// recording each command for inspection. It drives the multi-command
// ImportAndUnseal path without a TPM.
type scriptTransport struct {
	rsps  [][]byte
	cmds  [][]byte
	i     int
	errAt int // 1-based index at which Send returns errBoom; 0 = never
}

var errBoom = errors.New("boom")

func (s *scriptTransport) Send(cmd []byte) ([]byte, error) {
	s.cmds = append(s.cmds, append([]byte(nil), cmd...))
	s.i++
	if s.errAt == s.i {
		return nil, errBoom
	}
	if s.i-1 >= len(s.rsps) {
		return sessResp([]byte{0x00, 0x00, 0x00, 0x00}), nil
	}
	return s.rsps[s.i-1], nil
}

func TestImportAndUnsealHappyPath(t *testing.T) {
	objectPublic := []byte{0x00, 0x08, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x00}
	sel, _ := testSel()
	nonce := bytes.Repeat([]byte{0x01}, 32)
	secret := []byte("RECOVERED")

	importRsp := func() []byte {
		op := common.MarshalTPM2B(bytes.Repeat([]byte{0x77}, 8))
		return sessResp(append(common.PutU32(nil, uint32(len(op))), op...))
	}()
	loadRsp := sessResp(append(common.PutU32([]byte{0x80, 0x00, 0x00, 0x02}, 0), common.MarshalTPM2B([]byte{0x00, 0x0B})...))
	sessRsp := noSessOK(append(common.PutU32(nil, 0x03000000), common.MarshalTPM2B(bytes.Repeat([]byte{0x02}, 32))...))
	policyRsp := noSessOK(nil)
	unsealRsp := sessResp(append(common.PutU32(nil, uint32(2+len(secret))), common.MarshalTPM2B(secret)...))

	st := &scriptTransport{rsps: [][]byte{importRsp, loadRsp, sessRsp, policyRsp, unsealRsp}}
	tpm := New(st)

	got, err := tpm.ImportAndUnseal(0x80000001, objectPublic, common.MarshalTPM2B([]byte{0x01}), common.MarshalTPM2B([]byte{0x02}), sel, nonce)
	if err != nil {
		t.Fatalf("ImportAndUnseal: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("recovered %q != %q", got, secret)
	}
	if len(st.cmds) != 5 {
		t.Fatalf("issued %d commands, want 5 (Import,Load,StartAuthSession,PolicyPCR,Unseal)", len(st.cmds))
	}
	// Load's inPrivate must be the outPrivate Import returned (the 8-byte 0x77).
	wantPriv := bytes.Repeat([]byte{0x77}, 8)
	if !bytes.Contains(st.cmds[1], wantPriv) {
		t.Fatalf("Load did not carry Import's outPrivate")
	}
}

func TestImportAndUnsealErrorBranches(t *testing.T) {
	objectPublic := []byte{0x00, 0x08, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x00}
	sel, _ := testSel()
	nonce := bytes.Repeat([]byte{0x01}, 32)
	op := common.MarshalTPM2B(bytes.Repeat([]byte{0x77}, 8))
	importRsp := sessResp(append(common.PutU32(nil, uint32(len(op))), op...))
	loadRsp := sessResp(append(common.PutU32([]byte{0x80, 0x00, 0x00, 0x02}, 0), common.MarshalTPM2B([]byte{0x00, 0x0B})...))
	sessRsp := noSessOK(append(common.PutU32(nil, 0x03000000), common.MarshalTPM2B(bytes.Repeat([]byte{0x02}, 32))...))
	policyRsp := noSessOK(nil)

	cases := []struct {
		name  string
		rsps  [][]byte
		errAt int
	}{
		{"import-fails", nil, 1},
		{"load-fails", [][]byte{importRsp}, 2},
		{"startsession-fails", [][]byte{importRsp, loadRsp}, 3},
		{"policypcr-fails", [][]byte{importRsp, loadRsp, sessRsp}, 4},
		{"unseal-fails", [][]byte{importRsp, loadRsp, sessRsp, policyRsp}, 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := &scriptTransport{rsps: tc.rsps, errAt: tc.errAt}
			tpm := New(st)
			_, err := tpm.ImportAndUnseal(0x80000001, objectPublic, common.MarshalTPM2B([]byte{0x01}), common.MarshalTPM2B([]byte{0x02}), sel, nonce)
			if err == nil {
				t.Fatalf("expected error at step %d", tc.errAt)
			}
		})
	}
}

// --- CreateStoragePrimaryPub ---

func TestCreateStoragePrimaryPub(t *testing.T) {
	x := bytes.Repeat([]byte{0xAA}, 32)
	y := bytes.Repeat([]byte{0xBB}, 32)
	ft := &fakeTransport{rsp: sessResp(cannedCreatePrimaryResponse(0x80000003, x, y))}
	tpm := New(ft)

	h, pub, err := tpm.CreateStoragePrimaryPub()
	if err != nil {
		t.Fatalf("CreateStoragePrimaryPub: %v", err)
	}
	if h != 0x80000003 {
		t.Fatalf("handle = %#x, want 0x80000003", h)
	}
	if !bytes.Equal(pub.X, x) || !bytes.Equal(pub.Y, y) {
		t.Fatalf("public point mismatch: x=%x y=%x", pub.X, pub.Y)
	}
}

func TestCreateStoragePrimaryPubError(t *testing.T) {
	t.Run("transport", func(t *testing.T) {
		ft := &fakeTransport{err: errors.New("down")}
		if _, _, err := New(ft).CreateStoragePrimaryPub(); err == nil {
			t.Fatalf("expected transport error")
		}
	})
	t.Run("short", func(t *testing.T) {
		ft := &fakeTransport{rsp: sessResp([]byte{0x00, 0x00})}
		if _, _, err := New(ft).CreateStoragePrimaryPub(); err == nil {
			t.Fatalf("expected parse error")
		}
	})
}

// TestCreateStoragePrimaryStillWorks confirms the thin wrapper keeps returning
// just the handle.
func TestCreateStoragePrimaryStillWorks(t *testing.T) {
	x := bytes.Repeat([]byte{0x11}, 32)
	y := bytes.Repeat([]byte{0x22}, 32)
	ft := &fakeTransport{rsp: sessResp(cannedCreatePrimaryResponse(0x80000009, x, y))}
	h, err := New(ft).CreateStoragePrimary()
	if err != nil || h != 0x80000009 {
		t.Fatalf("CreateStoragePrimary h=%#x err=%v", h, err)
	}
}
