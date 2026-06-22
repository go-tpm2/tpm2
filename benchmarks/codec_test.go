// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/tpm2 authors. All rights reserved.

package benchmarks

// Pure marshal/unmarshal micro-benchmarks: NO TPM, NO swtpm. This is the layer
// where Go-library performance actually differs — encoding a command's
// parameter area and decoding a response's parameter area in a tight loop.
//
// go-tpm2 (github.com/go-tpm2/common) marshals with a hand-rolled big-endian
// append-based codec. github.com/google/go-tpm marshals/unmarshals by
// REFLECTION over tagged structs (Marshal / Unmarshal generics). The two are
// compared on equivalent work.
//
// SCOPE NOTE (honest): go-tpm's public command API does not expose a "build the
// full command buffer" function — MarshalCommand emits the cpHash preimage
// (commandCode || handle-NAMES || params), and the tag/size framing plus the
// 4-byte-handle area are assembled inside its unexported dispatch path. So for
// a like-for-like PARAMETER-area comparison we use go-tpm's generic
// Marshal/Unmarshal over the parameter structs. The full end-to-end marshal+
// parse cost of each library is measured separately by the round-trip
// benchmark (roundtrip_test.go), which drives each library's real send path
// against the same swtpm.
//
// A parity test first asserts the two libraries produce byte-equal parameter
// areas for the same logical command, so the ns/op figures compare equivalent
// output, not different output.

import (
	"bytes"
	"testing"

	"github.com/go-tpm2/common"
	legacy "github.com/google/go-tpm/tpm2"
)

// --- representative payloads ---

var (
	sampleDigest = mustBytes(32, 0xAB)
	sampleNonce  = mustBytes(32, 0xCD)
)

func mustBytes(n int, fill byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = fill
	}
	return b
}

// ===========================================================================
// Correctness: our marshaled parameter area must match go-tpm's.
// ===========================================================================

// TestGetCapabilityParamParity builds the TPM2_GetCapability PARAMETER area
// both ways (TPM_CAP, property, propertyCount — three UINT32) and asserts they
// are byte-identical.
func TestGetCapabilityParamParity(t *testing.T) {
	const (
		capTPMProperties = 0x00000006
		ptManufacturer   = 0x00000105
	)
	// go-tpm2: the parameter area as commands.go builds it.
	ours := common.PutU32(nil, capTPMProperties)
	ours = common.PutU32(ours, ptManufacturer)
	ours = common.PutU32(ours, 1)

	// go-tpm: MarshalCommand emits commandCode(4) || params (GetCapability has
	// no handles), so the parameter area is its output minus the leading cc.
	full, err := legacy.MarshalCommand(legacy.GetCapability{
		Capability:    legacy.TPMCap(capTPMProperties),
		Property:      ptManufacturer,
		PropertyCount: 1,
	})
	if err != nil {
		t.Fatalf("go-tpm MarshalCommand: %v", err)
	}
	theirs := full[4:]
	if !bytes.Equal(ours, theirs) {
		t.Fatalf("GetCapability param mismatch:\n ours:   %x\n go-tpm: %x", ours, theirs)
	}
}

// TestGetRandomParamParity does the same for TPM2_GetRandom (a single u16).
func TestGetRandomParamParity(t *testing.T) {
	const n = 32
	ours := common.PutU16(nil, n)
	full, err := legacy.MarshalCommand(legacy.GetRandom{BytesRequested: n})
	if err != nil {
		t.Fatalf("go-tpm MarshalCommand: %v", err)
	}
	theirs := full[4:] // strip the leading commandCode
	if !bytes.Equal(ours, theirs) {
		t.Fatalf("GetRandom param mismatch:\n ours:   %x\n go-tpm: %x", ours, theirs)
	}
}

// TestDigestValuesParity asserts the TPML_DIGEST_VALUES parameter of
// TPM2_PCR_Extend (count || {hashAlg, digest}) marshals identically.
func TestDigestValuesParity(t *testing.T) {
	ours := common.PutU32(nil, 1)
	ours = common.PutU16(ours, uint16(common.AlgSHA256))
	ours = append(ours, sampleDigest...)

	theirs := legacy.Marshal(legacy.TPMLDigestValues{
		Digests: []legacy.TPMTHA{{HashAlg: legacy.TPMAlgSHA256, Digest: sampleDigest}},
	})
	if !bytes.Equal(ours, theirs) {
		t.Fatalf("TPML_DIGEST_VALUES mismatch:\n ours:   %x\n go-tpm: %x", ours, theirs)
	}
}

// ===========================================================================
// Benchmarks: marshal a command's parameter area (ours vs go-tpm).
// ===========================================================================

func marshalGetCapabilityParamsOurs() []byte {
	params := common.PutU32(nil, 0x00000006)
	params = common.PutU32(params, 0x00000105)
	return common.PutU32(params, 1)
}

func BenchmarkMarshalGetCapability_Ours(b *testing.B) {
	b.ReportAllocs()
	var sink []byte
	for i := 0; i < b.N; i++ {
		sink = marshalGetCapabilityParamsOurs()
	}
	_ = sink
}

func BenchmarkMarshalGetCapability_GoTPM(b *testing.B) {
	b.ReportAllocs()
	cmd := legacy.GetCapability{Capability: legacy.TPMCap(0x06), Property: 0x105, PropertyCount: 1}
	var sink []byte
	for i := 0; i < b.N; i++ {
		sink, _ = legacy.MarshalCommand(cmd)
	}
	_ = sink
}

// PCR_Extend's parameter area is a TPML_DIGEST_VALUES (the heaviest "real"
// parameter in the starter set).
func marshalDigestValuesOurs(digest []byte) []byte {
	body := common.PutU32(nil, 1)
	body = common.PutU16(body, uint16(common.AlgSHA256))
	return append(body, digest...)
}

func BenchmarkMarshalDigestValues_Ours(b *testing.B) {
	b.ReportAllocs()
	var sink []byte
	for i := 0; i < b.N; i++ {
		sink = marshalDigestValuesOurs(sampleDigest)
	}
	_ = sink
}

func BenchmarkMarshalDigestValues_GoTPM(b *testing.B) {
	b.ReportAllocs()
	dv := legacy.TPMLDigestValues{
		Digests: []legacy.TPMTHA{{HashAlg: legacy.TPMAlgSHA256, Digest: sampleDigest}},
	}
	var sink []byte
	for i := 0; i < b.N; i++ {
		sink = legacy.Marshal(dv)
	}
	_ = sink
}

// ===========================================================================
// Benchmarks: parse a response parameter area (ours vs go-tpm).
// ===========================================================================

// A canned TPM2_GetRandom response PARAMETER area: a TPM2B_DIGEST of 32 bytes.
var getRandomParams = common.MarshalTPM2B(sampleNonce)

// And the full response buffer (header + params) for our ParseResponse path.
var getRandomResponse = func() []byte {
	size := uint32(common.HeaderSize + len(getRandomParams))
	out := common.PutU16(nil, uint16(common.TagNoSessions))
	out = common.PutU32(out, size)
	out = common.PutU32(out, uint32(common.RCSuccess))
	return append(out, getRandomParams...)
}()

// goTPMResponseBytes is the response in the shape go-tpm's UnmarshalResponse
// consumes: responseCode(u32, SUCCESS) || commandCode(u32, GetRandom) || params.
var goTPMResponseBytes = func() []byte {
	out := common.PutU32(nil, 0)         // responseCode = SUCCESS
	out = common.PutU32(out, 0x0000017B) // commandCode = TPM_CC_GetRandom
	return append(out, getRandomParams...)
}()

func parseGetRandomOurs(rsp []byte) ([]byte, error) {
	_, _, rp, err := common.ParseResponse(rsp)
	if err != nil {
		return nil, err
	}
	val, _, err := common.UnmarshalTPM2B(rp)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(val))
	copy(out, val)
	return out, nil
}

func TestParseGetRandomParity(t *testing.T) {
	got, err := parseGetRandomOurs(getRandomResponse)
	if err != nil {
		t.Fatalf("ours parse: %v", err)
	}
	if !bytes.Equal(got, sampleNonce) {
		t.Fatalf("ours decoded %x, want %x", got, sampleNonce)
	}
	// go-tpm: UnmarshalResponse expects responseCode(4) || commandCode(4) ||
	// params. Build that preamble (rc=SUCCESS, cc=GetRandom) over the param area.
	rsp, err := legacy.UnmarshalResponse[legacy.GetRandomResponse](goTPMResponseBytes)
	if err != nil {
		t.Fatalf("go-tpm UnmarshalResponse: %v", err)
	}
	if !bytes.Equal(rsp.RandomBytes.Buffer, sampleNonce) {
		t.Fatalf("go-tpm decoded %x, want %x", rsp.RandomBytes.Buffer, sampleNonce)
	}
}

func BenchmarkParseGetRandom_Ours(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := parseGetRandomOurs(getRandomResponse); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseGetRandom_GoTPM(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := legacy.UnmarshalResponse[legacy.GetRandomResponse](goTPMResponseBytes); err != nil {
			b.Fatal(err)
		}
	}
}
