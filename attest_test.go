// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/tpm2 authors. All rights reserved.

package tpm2

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/go-tpm2/common"
)

// sessResp is resp with TagSessions and RCSuccess (CreatePrimary/Quote are
// TagSessions commands, and a real TPM tags their responses likewise).
func sessResp(params []byte) []byte {
	return resp(uint16(common.TagSessions), uint32(common.RCSuccess), params)
}

// --- CreatePrimary request byte-for-byte assertion ---

func TestCreatePrimaryRequestBytes(t *testing.T) {
	// A minimal but well-formed response so the call returns without error;
	// the request assertion is the point of this test.
	ft := &fakeTransport{rsp: sessResp(cannedCreatePrimaryResponse(
		0x80000000,
		bytes.Repeat([]byte{0xAA}, 32),
		bytes.Repeat([]byte{0xBB}, 32),
	))}
	tpm := New(ft)
	if _, _, err := tpm.CreatePrimary(); err != nil {
		t.Fatalf("CreatePrimary: %v", err)
	}

	// Hand-derive the parameter area.
	//
	// Handle area:
	//   primaryHandle = 40 00 00 01  (TPM_RH_OWNER)
	// Auth area:
	//   authorizationSize = 00 00 00 09
	//   TPMS_AUTH_COMMAND:
	//     sessionHandle = 40 00 00 09 (TPM_RS_PW)
	//     nonce         = 00 00       (empty)
	//     attributes    = 01          (continueSession)
	//     hmac          = 00 00       (empty)
	// TPM2B_SENSITIVE_CREATE:
	//   size = 00 04
	//   userAuth = 00 00, data = 00 00
	// TPM2B_PUBLIC:
	//   size = 00 18 (24 bytes of TPMT_PUBLIC: 2+2+4+2 + 2+2+2+2+2 + 2+2)
	//   type            = 00 23 (ECC)
	//   nameAlg         = 00 0B (SHA256)
	//   objectAttributes= 00 05 00 72
	//   authPolicy      = 00 00
	//   symmetric       = 00 10 (NULL)
	//   scheme          = 00 18 (ECDSA)
	//   scheme.hashAlg  = 00 0B (SHA256)
	//   curveID         = 00 03 (NIST P-256)
	//   kdf             = 00 10 (NULL)
	//   unique.x        = 00 00
	//   unique.y        = 00 00
	// outsideInfo  = 00 00
	// creationPCR  = 00 00 00 00
	var body []byte
	body = append(body, 0x40, 0x00, 0x00, 0x01) // primaryHandle = RH_OWNER
	body = append(body, 0x00, 0x00, 0x00, 0x09) // authorizationSize
	body = append(body, 0x40, 0x00, 0x00, 0x09) // TPM_RS_PW
	body = append(body, 0x00, 0x00)             // nonce empty
	body = append(body, 0x01)                   // continueSession
	body = append(body, 0x00, 0x00)             // hmac empty
	body = append(body, 0x00, 0x04)             // TPM2B_SENSITIVE_CREATE size
	body = append(body, 0x00, 0x00)             // userAuth empty
	body = append(body, 0x00, 0x00)             // data empty
	body = append(body, 0x00, 0x18)             // TPM2B_PUBLIC size = 24
	body = append(body, 0x00, 0x23)             // type ECC
	body = append(body, 0x00, 0x0B)             // nameAlg SHA256
	body = append(body, 0x00, 0x05, 0x00, 0x72) // objectAttributes
	body = append(body, 0x00, 0x00)             // authPolicy empty
	body = append(body, 0x00, 0x10)             // symmetric NULL
	body = append(body, 0x00, 0x18)             // scheme ECDSA
	body = append(body, 0x00, 0x0B)             // hashAlg SHA256
	body = append(body, 0x00, 0x03)             // curveID NIST P-256
	body = append(body, 0x00, 0x10)             // kdf NULL
	body = append(body, 0x00, 0x00)             // unique.x empty
	body = append(body, 0x00, 0x00)             // unique.y empty
	body = append(body, 0x00, 0x00)             // outsideInfo empty
	body = append(body, 0x00, 0x00, 0x00, 0x00) // creationPCR count 0

	// commandSize = 10 header + len(body).
	size := uint32(common.HeaderSize + len(body))
	want := []byte{0x80, 0x02}
	want = append(want, byte(size>>24), byte(size>>16), byte(size>>8), byte(size))
	want = append(want, 0x00, 0x00, 0x01, 0x31) // TPM2_CreatePrimary
	want = append(want, body...)

	if !bytes.Equal(ft.gotCmd, want) {
		t.Fatalf("CreatePrimary request bytes\n got %x\nwant %x", ft.gotCmd, want)
	}
}

// cannedCreatePrimaryResponse builds a realistic TPM2_CreatePrimary response
// param area: parameterSize, TPM2B_PUBLIC (TPMT_PUBLIC with the given ECC
// point), then a creationData/creationHash/ticket/name tail (consumed but not
// parsed by the code under test).
func cannedCreatePrimaryResponse(handle uint32, x, y []byte) []byte {
	// Inner TPMT_PUBLIC mirroring marshalECCAKPublic but with a populated
	// unique point.
	var pub []byte
	pub = common.PutU16(pub, AlgECC)
	pub = common.PutU16(pub, algSHA256)
	pub = common.PutU32(pub, akObjectAttributes)
	pub = common.PutU16(pub, 0) // authPolicy
	pub = common.PutU16(pub, algNull)
	pub = common.PutU16(pub, AlgECDSA)
	pub = common.PutU16(pub, algSHA256)
	pub = common.PutU16(pub, ECCNistP256)
	pub = common.PutU16(pub, algNull)
	pub = append(pub, common.MarshalTPM2B(x)...)
	pub = append(pub, common.MarshalTPM2B(y)...)

	var rp []byte
	rp = common.PutU32(rp, handle)             // objectHandle (handle area)
	tail := []byte{0xDE, 0xAD}                 // arbitrary trailing creation bytes
	pubB := common.MarshalTPM2B(pub)           // TPM2B_PUBLIC
	paramSize := uint32(len(pubB) + len(tail)) // everything after parameterSize
	rp = common.PutU32(rp, paramSize)          // parameterSize
	rp = append(rp, pubB...)                   // outPublic
	rp = append(rp, tail...)                   // creationData/hash/ticket/name (opaque)
	return rp
}

func TestCreatePrimaryResponseParse(t *testing.T) {
	x := bytes.Repeat([]byte{0x11}, 32)
	y := bytes.Repeat([]byte{0x22}, 32)
	ft := &fakeTransport{rsp: sessResp(cannedCreatePrimaryResponse(0x80000001, x, y))}
	tpm := New(ft)
	h, pub, err := tpm.CreatePrimary()
	if err != nil {
		t.Fatalf("CreatePrimary: %v", err)
	}
	if h != 0x80000001 {
		t.Fatalf("handle = %#x, want 0x80000001", h)
	}
	if !bytes.Equal(pub.X, x) || !bytes.Equal(pub.Y, y) {
		t.Fatalf("pub = (%x,%x), want (%x,%x)", pub.X, pub.Y, x, y)
	}
}

// --- Quote request byte-for-byte assertion ---

func TestQuoteRequestBytes(t *testing.T) {
	nonce := []byte{0xCA, 0xFE, 0xBA, 0xBE}
	sel := []PCRSelection{{Hash: uint16(common.AlgSHA256), PCRs: []int{16}}}

	// Canned response so the call returns; bytes assertion is the point.
	attest := buildQuoteAttest(nonce, sel, bytes.Repeat([]byte{0x33}, 32))
	ft := &fakeTransport{rsp: sessResp(cannedQuoteResponse(attest,
		bytes.Repeat([]byte{0x01}, 32), bytes.Repeat([]byte{0x02}, 32)))}
	tpm := New(ft)
	if _, _, err := tpm.Quote(0x80000001, nonce, sel); err != nil {
		t.Fatalf("Quote: %v", err)
	}

	// Hand-derived body:
	//   keyHandle         = 80 00 00 01
	//   authorizationSize = 00 00 00 09
	//   TPM_RS_PW         = 40 00 00 09
	//   nonce empty       = 00 00
	//   continueSession   = 01
	//   hmac empty        = 00 00
	//   qualifyingData    = 00 04 CA FE BA BE
	//   inScheme (NULL)   = 00 10
	//   pcrSelect         = 00 00 00 01 | 00 0B | 03 | 01 00 00
	//     PCR 16 -> octet 2 bit 0 -> bitmap 00 00 01
	var body []byte
	body = append(body, 0x80, 0x00, 0x00, 0x01)             // keyHandle
	body = append(body, 0x00, 0x00, 0x00, 0x09)             // authorizationSize
	body = append(body, 0x40, 0x00, 0x00, 0x09)             // TPM_RS_PW
	body = append(body, 0x00, 0x00)                         // nonce empty
	body = append(body, 0x01)                               // continueSession
	body = append(body, 0x00, 0x00)                         // hmac empty
	body = append(body, 0x00, 0x04, 0xCA, 0xFE, 0xBA, 0xBE) // TPM2B_DATA nonce
	body = append(body, 0x00, 0x10)                         // inScheme NULL
	body = append(body, 0x00, 0x00, 0x00, 0x01)             // selection count
	body = append(body, 0x00, 0x0B)                         // sha256
	body = append(body, 0x03)                               // sizeofSelect
	body = append(body, 0x00, 0x00, 0x01)                   // bitmap PCR16

	size := uint32(common.HeaderSize + len(body))
	want := []byte{0x80, 0x02}
	want = append(want, byte(size>>24), byte(size>>16), byte(size>>8), byte(size))
	want = append(want, 0x00, 0x00, 0x01, 0x58) // TPM2_Quote
	want = append(want, body...)

	if !bytes.Equal(ft.gotCmd, want) {
		t.Fatalf("Quote request bytes\n got %x\nwant %x", ft.gotCmd, want)
	}
}

// buildQuoteAttest assembles a TPMS_ATTEST of type TPM_ST_ATTEST_QUOTE with
// the given extraData nonce, pcr selection, and pcrDigest. It mirrors the
// exact byte layout ParseAttest decodes.
func buildQuoteAttest(nonce []byte, sel []PCRSelection, pcrDigest []byte) []byte {
	var a []byte
	a = common.PutU32(a, attestMagic)
	a = common.PutU16(a, stAttestQuote)
	a = append(a, common.MarshalTPM2B([]byte{0xAB, 0xCD})...) // qualifiedSigner TPM2B_NAME
	a = append(a, common.MarshalTPM2B(nonce)...)              // extraData TPM2B_DATA
	// clockInfo: clock u64, resetCount u32, restartCount u32, safe u8 = 17 bytes.
	a = common.PutU64(a, 0x0102030405060708)
	a = common.PutU32(a, 0x00000001)
	a = common.PutU32(a, 0x00000002)
	a = common.PutU8(a, 0x01)
	a = common.PutU64(a, 0xAABBCCDDEEFF0011) // firmwareVersion
	// attested = TPMS_QUOTE_INFO.
	a = append(a, marshalPCRSelectionList(sel)...)
	a = append(a, common.MarshalTPM2B(pcrDigest)...)
	return a
}

// cannedQuoteResponse builds a TPM2_Quote response param area: parameterSize,
// TPM2B_ATTEST, TPMT_SIGNATURE (ECDSA: sigAlg, hash, R TPM2B, S TPM2B).
func cannedQuoteResponse(attest, r, s []byte) []byte {
	var sig []byte
	sig = common.PutU16(sig, AlgECDSA)  // sigAlg
	sig = common.PutU16(sig, algSHA256) // hash
	sig = append(sig, common.MarshalTPM2B(r)...)
	sig = append(sig, common.MarshalTPM2B(s)...)

	attestB := common.MarshalTPM2B(attest)
	var rp []byte
	rp = common.PutU32(rp, uint32(len(attestB)+len(sig))) // parameterSize
	rp = append(rp, attestB...)
	rp = append(rp, sig...)
	return rp
}

func TestQuoteResponseParse(t *testing.T) {
	nonce := []byte{0x01, 0x02}
	sel := []PCRSelection{{Hash: uint16(common.AlgSHA256), PCRs: []int{16}}}
	pcrDigest := bytes.Repeat([]byte{0x44}, 32)
	attest := buildQuoteAttest(nonce, sel, pcrDigest)
	r := bytes.Repeat([]byte{0x0A}, 32)
	s := bytes.Repeat([]byte{0x0B}, 32)
	ft := &fakeTransport{rsp: sessResp(cannedQuoteResponse(attest, r, s))}
	tpm := New(ft)
	quoted, sig, err := tpm.Quote(0x80000001, nonce, sel)
	if err != nil {
		t.Fatalf("Quote: %v", err)
	}
	if !bytes.Equal(quoted, attest) {
		t.Fatalf("quoted\n got %x\nwant %x", quoted, attest)
	}
	if !bytes.Equal(sig.R, r) || !bytes.Equal(sig.S, s) {
		t.Fatalf("sig = (%x,%x)", sig.R, sig.S)
	}
}

// --- VerifyQuote with a real ECDSA key ---

// signAttest signs an attest blob with a P-256 key, returning the AKPublic and
// the (r,s) signature the way the TPM would.
func signAttest(t *testing.T, key *ecdsa.PrivateKey, attest []byte) (AKPublic, ECDSASignature) {
	t.Helper()
	digest := sha256.Sum256(attest)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("ecdsa.Sign: %v", err)
	}
	return AKPublic{
			X: key.PublicKey.X.Bytes(),
			Y: key.PublicKey.Y.Bytes(),
		}, ECDSASignature{
			R: r.Bytes(),
			S: s.Bytes(),
		}
}

func TestVerifyQuoteRoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	nonce := []byte{0x11, 0x22, 0x33}
	sel := []PCRSelection{{Hash: uint16(common.AlgSHA256), PCRs: []int{16}}}

	// Two PCR values; the quoted digest is SHA256(pcr0 || pcr1).
	pcr0 := bytes.Repeat([]byte{0x77}, 32)
	pcr1 := bytes.Repeat([]byte{0x88}, 32)
	h := sha256.New()
	h.Write(pcr0)
	h.Write(pcr1)
	pcrDigest := h.Sum(nil)

	attest := buildQuoteAttest(nonce, sel, pcrDigest)
	pub, sig := signAttest(t, key, attest)

	info, err := VerifyQuote(pub, attest, sig, [][]byte{pcr0, pcr1})
	if err != nil {
		t.Fatalf("VerifyQuote: %v", err)
	}
	if !bytes.Equal(info.ExtraData, nonce) {
		t.Fatalf("extraData = %x, want %x", info.ExtraData, nonce)
	}
	if !bytes.Equal(info.Quote.PCRDigest, pcrDigest) {
		t.Fatalf("pcrDigest = %x, want %x", info.Quote.PCRDigest, pcrDigest)
	}
	if len(info.Quote.PCRSelect) != 1 || info.Quote.PCRSelect[0].Hash != uint16(common.AlgSHA256) {
		t.Fatalf("pcrSelect = %+v", info.Quote.PCRSelect)
	}
}

func TestVerifyQuoteTamperedSignature(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sel := []PCRSelection{{Hash: uint16(common.AlgSHA256), PCRs: []int{16}}}
	pcr := bytes.Repeat([]byte{0x01}, 32)
	pcrDigest := sha256.Sum256(pcr)
	attest := buildQuoteAttest([]byte{0x01}, sel, pcrDigest[:])
	pub, sig := signAttest(t, key, attest)

	// Flip a byte of S: the signature must no longer verify.
	sig.S = append([]byte(nil), sig.S...)
	sig.S[len(sig.S)-1] ^= 0xFF
	if _, err := VerifyQuote(pub, attest, sig, [][]byte{pcr}); !errors.Is(err, ErrSigInvalid) {
		t.Fatalf("VerifyQuote err = %v, want ErrSigInvalid", err)
	}
}

func TestVerifyQuoteWrongKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sel := []PCRSelection{{Hash: uint16(common.AlgSHA256), PCRs: []int{16}}}
	pcr := bytes.Repeat([]byte{0x01}, 32)
	pcrDigest := sha256.Sum256(pcr)
	attest := buildQuoteAttest([]byte{0x01}, sel, pcrDigest[:])
	_, sig := signAttest(t, key, attest)
	// Verify with the OTHER key's public part.
	wrongPub := AKPublic{X: other.PublicKey.X.Bytes(), Y: other.PublicKey.Y.Bytes()}
	if _, err := VerifyQuote(wrongPub, attest, sig, [][]byte{pcr}); !errors.Is(err, ErrSigInvalid) {
		t.Fatalf("VerifyQuote err = %v, want ErrSigInvalid", err)
	}
}

func TestVerifyQuotePCRDigestMismatch(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sel := []PCRSelection{{Hash: uint16(common.AlgSHA256), PCRs: []int{16}}}
	pcr := bytes.Repeat([]byte{0x01}, 32)
	// The attest commits to a digest of the real PCR...
	pcrDigest := sha256.Sum256(pcr)
	attest := buildQuoteAttest([]byte{0x01}, sel, pcrDigest[:])
	pub, sig := signAttest(t, key, attest)
	// ...but we pass a DIFFERENT expected PCR value, so the recomputed digest
	// differs and the check fails (after the signature verifies).
	wrong := bytes.Repeat([]byte{0x02}, 32)
	if _, err := VerifyQuote(pub, attest, sig, [][]byte{wrong}); !errors.Is(err, ErrPCRDigestMismatch) {
		t.Fatalf("VerifyQuote err = %v, want ErrPCRDigestMismatch", err)
	}
}

// --- ParseAttest error branches ---

func TestParseAttestErrors(t *testing.T) {
	good := buildQuoteAttest([]byte{0x01}, []PCRSelection{{Hash: uint16(common.AlgSHA256), PCRs: []int{16}}}, bytes.Repeat([]byte{0x44}, 32))

	t.Run("short magic", func(t *testing.T) {
		if _, err := ParseAttest([]byte{0x00, 0x00}); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("bad magic", func(t *testing.T) {
		b := append([]byte(nil), good...)
		b[0] = 0x00 // corrupt TPM_GENERATED_VALUE
		if _, err := ParseAttest(b); !errors.Is(err, ErrBadMagic) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("short type", func(t *testing.T) {
		// magic present (4 bytes) but no type u16.
		b := common.PutU32(nil, attestMagic)
		if _, err := ParseAttest(b); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("not quote", func(t *testing.T) {
		b := append([]byte(nil), good...)
		b[4], b[5] = 0x80, 0x17 // TPM_ST_ATTEST_CERTIFY, not QUOTE
		if _, err := ParseAttest(b); !errors.Is(err, ErrNotQuote) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("short qualifiedSigner", func(t *testing.T) {
		// magic + type, then a truncated TPM2B_NAME.
		b := common.PutU32(nil, attestMagic)
		b = common.PutU16(b, stAttestQuote)
		b = append(b, 0x00) // 1 byte: too short for a u16 size
		if _, err := ParseAttest(b); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("short extraData", func(t *testing.T) {
		b := common.PutU32(nil, attestMagic)
		b = common.PutU16(b, stAttestQuote)
		b = append(b, common.MarshalTPM2B([]byte{0xAB})...) // qualifiedSigner
		b = append(b, 0x00)                                 // truncated extraData size
		if _, err := ParseAttest(b); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("short clockInfo/firmware", func(t *testing.T) {
		b := common.PutU32(nil, attestMagic)
		b = common.PutU16(b, stAttestQuote)
		b = append(b, common.MarshalTPM2B([]byte{0xAB})...) // qualifiedSigner
		b = append(b, common.MarshalTPM2B([]byte{0x01})...) // extraData
		b = append(b, bytes.Repeat([]byte{0x00}, 24)...)    // 24 < 25 required
		if _, err := ParseAttest(b); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("short pcrSelect", func(t *testing.T) {
		b := common.PutU32(nil, attestMagic)
		b = common.PutU16(b, stAttestQuote)
		b = append(b, common.MarshalTPM2B([]byte{0xAB})...)
		b = append(b, common.MarshalTPM2B([]byte{0x01})...)
		b = append(b, bytes.Repeat([]byte{0x00}, 25)...) // clockInfo+firmware
		b = append(b, 0x00, 0x00)                        // truncated selection count
		if _, err := ParseAttest(b); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("short pcrDigest", func(t *testing.T) {
		b := common.PutU32(nil, attestMagic)
		b = common.PutU16(b, stAttestQuote)
		b = append(b, common.MarshalTPM2B([]byte{0xAB})...)
		b = append(b, common.MarshalTPM2B([]byte{0x01})...)
		b = append(b, bytes.Repeat([]byte{0x00}, 25)...)
		b = append(b, 0x00, 0x00, 0x00, 0x00) // empty selection list
		b = append(b, 0x00)                   // truncated digest size
		if _, err := ParseAttest(b); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestVerifyQuoteParseError(t *testing.T) {
	// A non-attest blob makes VerifyQuote fail in ParseAttest before any
	// crypto.
	if _, err := VerifyQuote(AKPublic{}, []byte{0x00}, ECDSASignature{}, nil); !errors.Is(err, common.ErrShortBuffer) {
		t.Fatalf("err = %v, want ErrShortBuffer", err)
	}
}

// --- CreatePrimary / Quote execute + parse error branches ---

func TestCreatePrimaryExecuteError(t *testing.T) {
	ft := &fakeTransport{err: errors.New("io")}
	if _, _, err := New(ft).CreatePrimary(); err == nil {
		t.Fatal("want error")
	}
}

func TestCreatePrimaryResponseErrors(t *testing.T) {
	t.Run("short handle", func(t *testing.T) {
		ft := &fakeTransport{rsp: sessResp([]byte{0x00, 0x00})}
		if _, _, err := New(ft).CreatePrimary(); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("short parameterSize", func(t *testing.T) {
		ft := &fakeTransport{rsp: sessResp([]byte{0x80, 0x00, 0x00, 0x01, 0x00})}
		if _, _, err := New(ft).CreatePrimary(); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("short outPublic", func(t *testing.T) {
		// handle + parameterSize present, but the TPM2B_PUBLIC size says 32
		// with no bytes following.
		rp := []byte{
			0x80, 0x00, 0x00, 0x01, // handle
			0x00, 0x00, 0x00, 0x02, // parameterSize
			0x00, 0x20, // TPM2B_PUBLIC size = 32, but nothing follows
		}
		ft := &fakeTransport{rsp: sessResp(rp)}
		if _, _, err := New(ft).CreatePrimary(); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("malformed inner TPMT_PUBLIC", func(t *testing.T) {
		// A well-formed TPM2B_PUBLIC wrapper (size matches), but the inner
		// TPMT_PUBLIC is too short to parse: drives the parseTPMTPublicECCPoint
		// error path inside parseCreatePrimaryResponse.
		inner := []byte{0x00, 0x23} // only a type field, nothing else
		var rp []byte
		rp = common.PutU32(rp, 0x80000002) // handle
		pubB := common.MarshalTPM2B(inner)
		rp = common.PutU32(rp, uint32(len(pubB))) // parameterSize
		rp = append(rp, pubB...)
		ft := &fakeTransport{rsp: sessResp(rp)}
		if _, _, err := New(ft).CreatePrimary(); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
}

// TestVerifyQuotePCRDigestLengthMismatch drives the length-mismatch branch of
// bytesEqual: the signed attest commits to a 16-byte pcrDigest, but the
// recomputed SHA-256 over the expected PCRs is 32 bytes, so the lengths differ
// before any byte comparison.
func TestVerifyQuotePCRDigestLengthMismatch(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sel := []PCRSelection{{Hash: uint16(common.AlgSHA256), PCRs: []int{16}}}
	pcr := bytes.Repeat([]byte{0x01}, 32)
	shortDigest := bytes.Repeat([]byte{0x44}, 16) // 16 != SHA-256's 32 bytes
	attest := buildQuoteAttest([]byte{0x01}, sel, shortDigest)
	pub, sig := signAttest(t, key, attest)
	if _, err := VerifyQuote(pub, attest, sig, [][]byte{pcr}); !errors.Is(err, ErrPCRDigestMismatch) {
		t.Fatalf("VerifyQuote err = %v, want ErrPCRDigestMismatch", err)
	}
}

func TestQuoteExecuteError(t *testing.T) {
	ft := &fakeTransport{err: errors.New("io")}
	if _, _, err := New(ft).Quote(0, nil, nil); err == nil {
		t.Fatal("want error")
	}
}

func TestQuoteResponseErrors(t *testing.T) {
	t.Run("short parameterSize", func(t *testing.T) {
		ft := &fakeTransport{rsp: sessResp([]byte{0x00, 0x00})}
		if _, _, err := New(ft).Quote(0, nil, nil); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("short attest", func(t *testing.T) {
		rp := []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x10} // paramSize, then TPM2B size 16 with no data
		ft := &fakeTransport{rsp: sessResp(rp)}
		if _, _, err := New(ft).Quote(0, nil, nil); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("short sigAlg", func(t *testing.T) {
		// paramSize, empty TPM2B_ATTEST, then nothing for sigAlg.
		rp := []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00}
		ft := &fakeTransport{rsp: sessResp(rp)}
		if _, _, err := New(ft).Quote(0, nil, nil); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("wrong sigAlg", func(t *testing.T) {
		// paramSize, empty attest, sigAlg = RSASSA (0x0014) != ECDSA.
		rp := []byte{0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x14}
		ft := &fakeTransport{rsp: sessResp(rp)}
		if _, _, err := New(ft).Quote(0, nil, nil); !errors.Is(err, ErrUnexpectedSigAlg) {
			t.Fatalf("err = %v, want ErrUnexpectedSigAlg", err)
		}
	})
	t.Run("short hash", func(t *testing.T) {
		// paramSize, empty attest, sigAlg=ECDSA, then no hash u16.
		rp := []byte{0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x18}
		ft := &fakeTransport{rsp: sessResp(rp)}
		if _, _, err := New(ft).Quote(0, nil, nil); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("short R", func(t *testing.T) {
		// sigAlg=ECDSA, hash=SHA256, then truncated R TPM2B.
		rp := []byte{0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x18, 0x00, 0x0B, 0x00}
		ft := &fakeTransport{rsp: sessResp(rp)}
		if _, _, err := New(ft).Quote(0, nil, nil); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("short S", func(t *testing.T) {
		// sigAlg, hash, R (empty TPM2B), then truncated S.
		rp := []byte{0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x18, 0x00, 0x0B, 0x00, 0x00, 0x00}
		ft := &fakeTransport{rsp: sessResp(rp)}
		if _, _, err := New(ft).Quote(0, nil, nil); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
}

// --- parseTPMTPublicECCPoint extra branches (symmetric != NULL, scheme NULL,
// kdf != NULL, truncations) reached directly. ---

func TestParseTPMTPublicECCPointBranches(t *testing.T) {
	// Helper to build a TPMT_PUBLIC with explicit parameter algorithms.
	build := func(sym, scheme, kdf uint16, withSchemeHash, withKDFHash bool, x, y []byte) []byte {
		var b []byte
		b = common.PutU16(b, AlgECC)
		b = common.PutU16(b, algSHA256)
		b = common.PutU32(b, akObjectAttributes)
		b = common.PutU16(b, 0) // authPolicy
		b = common.PutU16(b, sym)
		if sym != algNull {
			b = common.PutU16(b, 0x0006) // keyBits (AES-ish)
			b = common.PutU16(b, 0x0043) // mode (CFB)
		}
		b = common.PutU16(b, scheme)
		if withSchemeHash {
			b = common.PutU16(b, algSHA256)
		}
		b = common.PutU16(b, ECCNistP256) // curveID
		b = common.PutU16(b, kdf)
		if withKDFHash {
			b = common.PutU16(b, algSHA256)
		}
		b = append(b, common.MarshalTPM2B(x)...)
		b = append(b, common.MarshalTPM2B(y)...)
		return b
	}

	x := bytes.Repeat([]byte{0xA1}, 32)
	y := bytes.Repeat([]byte{0xB2}, 32)

	t.Run("symmetric and kdf set", func(t *testing.T) {
		b := build(0x0006 /*AES*/, AlgECDSA, 0x0011 /*KDF1_SP800_56A*/, true, true, x, y)
		pub, err := parseTPMTPublicECCPoint(b)
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if !bytes.Equal(pub.X, x) || !bytes.Equal(pub.Y, y) {
			t.Fatalf("point = (%x,%x)", pub.X, pub.Y)
		}
	})

	t.Run("scheme NULL no hash", func(t *testing.T) {
		b := build(algNull, algNull, algNull, false, false, x, y)
		if _, err := parseTPMTPublicECCPoint(b); err != nil {
			t.Fatalf("err = %v", err)
		}
	})

	// Truncation branches.
	full := build(algNull, AlgECDSA, algNull, true, false, x, y)
	for _, n := range []int{1, 3, 7, 8} {
		t.Run("trunc prefix", func(t *testing.T) {
			if _, err := parseTPMTPublicECCPoint(full[:n]); !errors.Is(err, common.ErrShortBuffer) {
				t.Fatalf("n=%d err = %v", n, err)
			}
		})
	}

	t.Run("trunc symmetric algorithm", func(t *testing.T) {
		// Valid 8-byte prefix + empty authPolicy, then nothing: the GetU16
		// of the symmetric algorithm itself fails.
		var b []byte
		b = common.PutU16(b, AlgECC)
		b = common.PutU16(b, algSHA256)
		b = common.PutU32(b, akObjectAttributes)
		b = common.PutU16(b, 0) // authPolicy empty; no symmetric follows
		if _, err := parseTPMTPublicECCPoint(b); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("trunc unique x", func(t *testing.T) {
		// Full prefix through kdf, then a truncated unique-x TPM2B.
		var b []byte
		b = common.PutU16(b, AlgECC)
		b = common.PutU16(b, algSHA256)
		b = common.PutU32(b, akObjectAttributes)
		b = common.PutU16(b, 0)
		b = common.PutU16(b, algNull)
		b = common.PutU16(b, algNull)
		b = common.PutU16(b, ECCNistP256)
		b = common.PutU16(b, algNull)
		b = append(b, 0x00) // x size truncated
		if _, err := parseTPMTPublicECCPoint(b); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("trunc symmetric keyBits", func(t *testing.T) {
		// sym != NULL but truncated right after the symmetric algorithm.
		var b []byte
		b = common.PutU16(b, AlgECC)
		b = common.PutU16(b, algSHA256)
		b = common.PutU32(b, akObjectAttributes)
		b = common.PutU16(b, 0)      // authPolicy
		b = common.PutU16(b, 0x0006) // symmetric AES, no keyBits follows
		if _, err := parseTPMTPublicECCPoint(b); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("trunc symmetric mode", func(t *testing.T) {
		var b []byte
		b = common.PutU16(b, AlgECC)
		b = common.PutU16(b, algSHA256)
		b = common.PutU32(b, akObjectAttributes)
		b = common.PutU16(b, 0)
		b = common.PutU16(b, 0x0006)
		b = common.PutU16(b, 0x0006) // keyBits, no mode follows
		if _, err := parseTPMTPublicECCPoint(b); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("trunc scheme", func(t *testing.T) {
		var b []byte
		b = common.PutU16(b, AlgECC)
		b = common.PutU16(b, algSHA256)
		b = common.PutU32(b, akObjectAttributes)
		b = common.PutU16(b, 0)
		b = common.PutU16(b, algNull) // symmetric NULL, no scheme follows
		if _, err := parseTPMTPublicECCPoint(b); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("trunc scheme hash", func(t *testing.T) {
		var b []byte
		b = common.PutU16(b, AlgECC)
		b = common.PutU16(b, algSHA256)
		b = common.PutU32(b, akObjectAttributes)
		b = common.PutU16(b, 0)
		b = common.PutU16(b, algNull)
		b = common.PutU16(b, AlgECDSA) // scheme set, no hash follows
		if _, err := parseTPMTPublicECCPoint(b); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("trunc curveID", func(t *testing.T) {
		var b []byte
		b = common.PutU16(b, AlgECC)
		b = common.PutU16(b, algSHA256)
		b = common.PutU32(b, akObjectAttributes)
		b = common.PutU16(b, 0)
		b = common.PutU16(b, algNull)
		b = common.PutU16(b, algNull) // scheme NULL, no curveID follows
		if _, err := parseTPMTPublicECCPoint(b); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("trunc kdf", func(t *testing.T) {
		var b []byte
		b = common.PutU16(b, AlgECC)
		b = common.PutU16(b, algSHA256)
		b = common.PutU32(b, akObjectAttributes)
		b = common.PutU16(b, 0)
		b = common.PutU16(b, algNull)
		b = common.PutU16(b, algNull)
		b = common.PutU16(b, ECCNistP256) // curveID, no kdf follows
		if _, err := parseTPMTPublicECCPoint(b); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("trunc kdf hash", func(t *testing.T) {
		var b []byte
		b = common.PutU16(b, AlgECC)
		b = common.PutU16(b, algSHA256)
		b = common.PutU32(b, akObjectAttributes)
		b = common.PutU16(b, 0)
		b = common.PutU16(b, algNull)
		b = common.PutU16(b, algNull)
		b = common.PutU16(b, ECCNistP256)
		b = common.PutU16(b, 0x0011) // kdf set, no hash follows
		if _, err := parseTPMTPublicECCPoint(b); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("trunc authPolicy", func(t *testing.T) {
		var b []byte
		b = common.PutU16(b, AlgECC)
		b = common.PutU16(b, algSHA256)
		b = common.PutU32(b, akObjectAttributes)
		b = append(b, 0x00) // authPolicy TPM2B size truncated
		if _, err := parseTPMTPublicECCPoint(b); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("trunc unique y", func(t *testing.T) {
		// Full prefix through curveID/kdf, valid x, truncated y.
		var b []byte
		b = common.PutU16(b, AlgECC)
		b = common.PutU16(b, algSHA256)
		b = common.PutU32(b, akObjectAttributes)
		b = common.PutU16(b, 0)
		b = common.PutU16(b, algNull)
		b = common.PutU16(b, algNull)
		b = common.PutU16(b, ECCNistP256)
		b = common.PutU16(b, algNull)
		b = append(b, common.MarshalTPM2B(x)...)
		b = append(b, 0x00) // y size truncated
		if _, err := parseTPMTPublicECCPoint(b); !errors.Is(err, common.ErrShortBuffer) {
			t.Fatalf("err = %v", err)
		}
	})
}
