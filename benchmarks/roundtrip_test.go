// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/tpm2 authors. All rights reserved.

package benchmarks

// End-to-end round-trip benchmarks against a REAL swtpm, driven by both
// libraries over the IDENTICAL Send([]byte)->[]byte transport (swtpmTCP, which
// satisfies both go-tpm2's common.Transport and google/go-tpm's transport.TPM).
//
// HONEST framing: a TPM command's latency is dominated by the swtpm/TPM itself,
// not the Go library. Both libraries marshal a few hundred bytes (tens of ns,
// per codec_test.go), then block on a TCP round-trip to swtpm which runs the
// command (microseconds to milliseconds). So these numbers are EXPECTED to be
// ~equal between the two libraries; the point is to CONFIRM go-tpm2 adds no
// significant transport overhead over go-tpm, not to claim a win. Any
// difference here is swtpm scheduling noise, not library cost.
//
// swtpm runs in TCP "MS simulator" mode (verified working on Darwin); no QEMU
// needed. If swtpm is not installed the round-trip benchmarks skip.

import (
	"testing"

	"github.com/go-tpm2/tpm2"
	legacy "github.com/google/go-tpm/tpm2"
)

// Ports for the two harnesses (separate so they can coexist if run together).
const (
	oursCmdPort  = 2421
	oursPlatPort = 2422
	gtCmdPort    = 2431
	gtPlatPort   = 2432
)

// startupCLEAR issues TPM2_Startup(CLEAR) so the TPM is operational. swtpm is
// launched with --flags startup-clear, so this is redundant and tolerated, but
// issuing it makes the harness robust if that flag is ever dropped.
func startupOurs(b *testing.B, t *tpm2.TPM) {
	if err := t.Startup(uint16(0x0000)); err != nil {
		// TPM_RC_INITIALIZE (already started) is fine.
		b.Logf("Startup(CLEAR): %v (tolerated if already initialized)", err)
	}
}

// ---------------------------------------------------------------------------
// GetRandom round-trip (no auth, smallest command).
// ---------------------------------------------------------------------------

func BenchmarkRoundTripGetRandom_Ours(b *testing.B) {
	h := startSWTPM(b, oursCmdPort, oursPlatPort)
	t := tpm2.New(h.transport())
	startupOurs(b, t)
	// warm up
	if _, err := t.GetRandom(32); err != nil {
		b.Fatalf("warmup GetRandom: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := t.GetRandom(32); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRoundTripGetRandom_GoTPM(b *testing.B) {
	h := startSWTPM(b, gtCmdPort, gtPlatPort)
	tp := h.transport()
	// Startup via go-tpm.
	if _, err := (legacy.Startup{StartupType: legacy.TPMSUClear}).Execute(tp); err != nil {
		b.Logf("go-tpm Startup: %v (tolerated)", err)
	}
	cmd := legacy.GetRandom{BytesRequested: 32}
	if _, err := cmd.Execute(tp); err != nil {
		b.Fatalf("warmup GetRandom: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cmd.Execute(tp); err != nil {
			b.Fatal(err)
		}
	}
}

// ---------------------------------------------------------------------------
// GetCapability round-trip (TPM_PT_MANUFACTURER).
// ---------------------------------------------------------------------------

func BenchmarkRoundTripGetCapability_Ours(b *testing.B) {
	h := startSWTPM(b, oursCmdPort, oursPlatPort)
	t := tpm2.New(h.transport())
	startupOurs(b, t)
	if _, err := t.GetManufacturer(); err != nil {
		b.Fatalf("warmup GetManufacturer: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := t.GetCapability(0x06, 0x105, 1); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRoundTripGetCapability_GoTPM(b *testing.B) {
	h := startSWTPM(b, gtCmdPort, gtPlatPort)
	tp := h.transport()
	if _, err := (legacy.Startup{StartupType: legacy.TPMSUClear}).Execute(tp); err != nil {
		b.Logf("go-tpm Startup: %v (tolerated)", err)
	}
	cmd := legacy.GetCapability{
		Capability:    legacy.TPMCapTPMProperties,
		Property:      0x105,
		PropertyCount: 1,
	}
	if _, err := cmd.Execute(tp); err != nil {
		b.Fatalf("warmup GetCapability: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cmd.Execute(tp); err != nil {
			b.Fatal(err)
		}
	}
}

// ---------------------------------------------------------------------------
// PCR_Extend round-trip (carries an auth area — the heaviest starter command).
// ---------------------------------------------------------------------------

func BenchmarkRoundTripPCRExtend_Ours(b *testing.B) {
	h := startSWTPM(b, oursCmdPort, oursPlatPort)
	t := tpm2.New(h.transport())
	startupOurs(b, t)
	if err := t.PCRExtend(16, uint16(0x000B), sampleDigest); err != nil {
		b.Fatalf("warmup PCRExtend: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := t.PCRExtend(16, uint16(0x000B), sampleDigest); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRoundTripPCRExtend_GoTPM(b *testing.B) {
	h := startSWTPM(b, gtCmdPort, gtPlatPort)
	tp := h.transport()
	if _, err := (legacy.Startup{StartupType: legacy.TPMSUClear}).Execute(tp); err != nil {
		b.Logf("go-tpm Startup: %v (tolerated)", err)
	}
	cmd := legacy.PCRExtend{
		PCRHandle: legacy.AuthHandle{
			Handle: legacy.TPMHandle(16),
			Auth:   legacy.PasswordAuth(nil),
		},
		Digests: legacy.TPMLDigestValues{
			Digests: []legacy.TPMTHA{{HashAlg: legacy.TPMAlgSHA256, Digest: sampleDigest}},
		},
	}
	if _, err := cmd.Execute(tp); err != nil {
		b.Fatalf("warmup PCRExtend: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cmd.Execute(tp); err != nil {
			b.Fatal(err)
		}
	}
}
