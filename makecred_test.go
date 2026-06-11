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

// recoverCredential reverses MakeCredential the way a TPM with the EK private
// key does: ECDH to Z, KDFe seed, KDFa symKey + HMACkey, verify the outer
// HMAC, then AES-CFB-decrypt encIdentity and unwrap the inner TPM2B. It is the
// in-test ORACLE that makes the round-trip self-consistent without a TPM.
func recoverCredential(t *testing.T, ekPriv *ecdsa.PrivateKey, akName []byte, res MakeCredentialResult) []byte {
	t.Helper()
	curve := elliptic.P256()

	// Parse secret = TPM2B_ENCRYPTED_SECRET( TPMS_ECC_POINT{x,y} ).
	point, _, err := common.UnmarshalTPM2B(res.Secret)
	if err != nil {
		t.Fatalf("secret unmarshal: %v", err)
	}
	qeX, rest, err := common.UnmarshalTPM2B(point)
	if err != nil {
		t.Fatalf("point.x: %v", err)
	}
	qeY, _, err := common.UnmarshalTPM2B(rest)
	if err != nil {
		t.Fatalf("point.y: %v", err)
	}

	// Z = x-coord of ekPriv.D * Qe.
	zx, _ := curve.ScalarMult(new(big.Int).SetBytes(qeX), new(big.Int).SetBytes(qeY), ekPriv.D.Bytes())
	z := leftPad(zx.Bytes(), 32)

	ekXfix := leftPad(ekPriv.X.Bytes(), 32)
	seed := KDFe(z, labelIdentity, leftPad(qeX, 32), ekXfix, 256)
	symKey := KDFa(seed, labelStorage, akName, nil, 128)
	hmacKey := KDFa(seed, labelIntegrity, nil, nil, 256)

	// credentialBlob = TPM2B_ID_OBJECT { TPM2B(outerHMAC) || encIdentity }.
	idObject, _, err := common.UnmarshalTPM2B(res.CredentialBlob)
	if err != nil {
		t.Fatalf("idObject: %v", err)
	}
	outerHMAC, encIdentity, err := common.UnmarshalTPM2B(idObject)
	if err != nil {
		t.Fatalf("outerHMAC: %v", err)
	}

	// Verify outer HMAC over (encIdentity || akName).
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(encIdentity)
	mac.Write(akName)
	if !hmac.Equal(outerHMAC, mac.Sum(nil)) {
		t.Fatalf("outer HMAC mismatch")
	}

	// Decrypt encIdentity and unwrap the inner TPM2B(credential).
	block, _ := aes.NewCipher(symKey)
	iv := make([]byte, block.BlockSize())
	plain := make([]byte, len(encIdentity))
	cipher.NewCFBDecrypter(block, iv).XORKeyStream(plain, encIdentity)
	cred, _, err := common.UnmarshalTPM2B(plain)
	if err != nil {
		t.Fatalf("inner credential: %v", err)
	}
	return cred
}

// TestMakeCredentialRoundTrip is the self-consistent off-TPM proof: an
// in-test EK key pair, MakeCredential, then recoverCredential (the TPM's
// inverse) must return the EXACT original credential.
func TestMakeCredentialRoundTrip(t *testing.T) {
	ekPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ek keygen: %v", err)
	}
	ekPub := EKPublic{X: leftPad(ekPriv.X.Bytes(), 32), Y: leftPad(ekPriv.Y.Bytes(), 32)}
	akName := append([]byte{0x00, 0x0B}, bytes.Repeat([]byte{0x77}, 32)...)
	cred := []byte("GO-TPM2-CRED-CHALLENGE-32bytes!!") // 32 bytes

	res, err := MakeCredential(ekPub, akName, cred, rand.Reader)
	if err != nil {
		t.Fatalf("MakeCredential: %v", err)
	}
	got := recoverCredential(t, ekPriv, akName, res)
	if !bytes.Equal(got, cred) {
		t.Fatalf("recovered %x != original %x", got, cred)
	}
}

// TestMakeCredentialWrongName proves the binding to the AK Name: recovering
// with a DIFFERENT name fails the outer-HMAC check (the negative property the
// swtpm enforces, demonstrated here off-TPM).
func TestMakeCredentialWrongName(t *testing.T) {
	ekPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ekPub := EKPublic{X: leftPad(ekPriv.X.Bytes(), 32), Y: leftPad(ekPriv.Y.Bytes(), 32)}
	rightName := append([]byte{0x00, 0x0B}, bytes.Repeat([]byte{0x01}, 32)...)
	wrongName := append([]byte{0x00, 0x0B}, bytes.Repeat([]byte{0x02}, 32)...)

	res, err := MakeCredential(ekPub, rightName, []byte("secret"), rand.Reader)
	if err != nil {
		t.Fatalf("MakeCredential: %v", err)
	}

	// Recompute with the WRONG name: the outer HMAC must not verify.
	idObject, _, _ := common.UnmarshalTPM2B(res.CredentialBlob)
	outerHMAC, encIdentity, _ := common.UnmarshalTPM2B(idObject)
	point, _, _ := common.UnmarshalTPM2B(res.Secret)
	qeX, rest, _ := common.UnmarshalTPM2B(point)
	qeY, _, _ := common.UnmarshalTPM2B(rest)
	curve := elliptic.P256()
	zx, _ := curve.ScalarMult(new(big.Int).SetBytes(qeX), new(big.Int).SetBytes(qeY), ekPriv.D.Bytes())
	seed := KDFe(leftPad(zx.Bytes(), 32), labelIdentity, leftPad(qeX, 32), leftPad(ekPriv.X.Bytes(), 32), 256)
	hmacKey := KDFa(seed, labelIntegrity, nil, nil, 256)
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(encIdentity)
	mac.Write(wrongName)
	if hmac.Equal(outerHMAC, mac.Sum(nil)) {
		t.Fatalf("outer HMAC verified under WRONG name (binding broken)")
	}
}

// TestMakeCredentialStructure pins the wire shapes of the two outputs.
func TestMakeCredentialStructure(t *testing.T) {
	ekPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ekPub := EKPublic{X: leftPad(ekPriv.X.Bytes(), 32), Y: leftPad(ekPriv.Y.Bytes(), 32)}
	akName := append([]byte{0x00, 0x0B}, bytes.Repeat([]byte{0x09}, 32)...)
	cred := bytes.Repeat([]byte{0xC0}, 32)

	res, err := MakeCredential(ekPub, akName, cred, rand.Reader)
	if err != nil {
		t.Fatalf("MakeCredential: %v", err)
	}

	// credentialBlob: outer TPM2B size must equal len(idObject), and idObject
	// = TPM2B(32-byte HMAC) || encIdentity, where encIdentity encrypts the
	// 34-byte TPM2B(credential) (2-byte size + 32-byte cred).
	idObject, restc, err := common.UnmarshalTPM2B(res.CredentialBlob)
	if err != nil || len(restc) != 0 {
		t.Fatalf("credentialBlob outer TPM2B malformed: %v rest=%d", err, len(restc))
	}
	hmacVal, encIdentity, err := common.UnmarshalTPM2B(idObject)
	if err != nil {
		t.Fatalf("idObject inner TPM2B: %v", err)
	}
	if len(hmacVal) != 32 {
		t.Fatalf("integrity HMAC len = %d, want 32", len(hmacVal))
	}
	if len(encIdentity) != 2+32 {
		t.Fatalf("encIdentity len = %d, want 34", len(encIdentity))
	}

	// secret: TPM2B_ENCRYPTED_SECRET wrapping a point of two 32-byte coords.
	point, rests, err := common.UnmarshalTPM2B(res.Secret)
	if err != nil || len(rests) != 0 {
		t.Fatalf("secret outer TPM2B malformed: %v rest=%d", err, len(rests))
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

// TestMakeCredentialNilRNG covers the rng==nil default-to-crypto/rand branch.
func TestMakeCredentialNilRNG(t *testing.T) {
	ekPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ekPub := EKPublic{X: leftPad(ekPriv.X.Bytes(), 32), Y: leftPad(ekPriv.Y.Bytes(), 32)}
	akName := append([]byte{0x00, 0x0B}, bytes.Repeat([]byte{0x05}, 32)...)
	res, err := MakeCredential(ekPub, akName, []byte("x"), nil)
	if err != nil {
		t.Fatalf("MakeCredential(nil rng): %v", err)
	}
	if got := recoverCredential(t, ekPriv, akName, res); !bytes.Equal(got, []byte("x")) {
		t.Fatalf("nil-rng round trip recovered %x", got)
	}
}

// TestMakeCredentialBadEKPoint covers the off-curve EK rejection.
func TestMakeCredentialBadEKPoint(t *testing.T) {
	bad := EKPublic{X: []byte{0x01}, Y: []byte{0x02}} // not on P-256
	_, err := MakeCredential(bad, []byte{0x00, 0x0B}, []byte("x"), rand.Reader)
	if err != ErrEKPointNotOnCurve {
		t.Fatalf("err = %v, want ErrEKPointNotOnCurve", err)
	}
}

// errReader fails every read, to drive the ephemeral-keygen error branch.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("rng failure") }

// TestMakeCredentialRNGFailure covers the GenerateKey error branch.
func TestMakeCredentialRNGFailure(t *testing.T) {
	ekPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ekPub := EKPublic{X: leftPad(ekPriv.X.Bytes(), 32), Y: leftPad(ekPriv.Y.Bytes(), 32)}
	if _, err := MakeCredential(ekPub, []byte{0x00, 0x0B}, []byte("x"), errReader{}); err == nil {
		t.Fatalf("expected keygen error from failing rng")
	}
}

// TestLeftPad covers the >n (truncate), <n (pad), and ==n branches.
func TestLeftPad(t *testing.T) {
	if got := leftPad([]byte{0x01, 0x02, 0x03}, 2); !bytes.Equal(got, []byte{0x02, 0x03}) {
		t.Fatalf("truncate = %x", got)
	}
	if got := leftPad([]byte{0x09}, 3); !bytes.Equal(got, []byte{0x00, 0x00, 0x09}) {
		t.Fatalf("pad = %x", got)
	}
	if got := leftPad([]byte{0x01, 0x02}, 2); !bytes.Equal(got, []byte{0x01, 0x02}) {
		t.Fatalf("exact = %x", got)
	}
}
