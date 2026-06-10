// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/tpm2 authors. All rights reserved.

// Package tpm2 is the transport-agnostic, pure-Go TPM 2.0 command API. It
// sits one layer above github.com/go-tpm2/common: common owns the
// big-endian wire codec and the Transport contract, and this package turns
// that codec into typed TPM 2.0 commands.
//
// A TPM value wraps a common.Transport. Each command method marshals its
// parameters (with common.BuildCommand and the appropriate TPM_ST tag and
// TPM_CC code), hands the buffer to Transport.Send, parses the reply with
// common.ParseResponse, checks the response code, and unmarshals the
// response parameters. A non-success response code is surfaced as a typed
// *TPMError carrying both the raw rc and the command code it came from.
//
// All multi-byte fields are encoded big-endian, as the TPM 2.0 wire format
// mandates (TCG "TPM 2.0 Part 1: Architecture", "Data Marshaling").
//
// This is the starter set required by the first measured-boot milestone:
// Startup, Shutdown, SelfTest, GetRandom, GetCapability, PCR_Read and
// PCR_Extend. Each method cites the relevant clause of TCG "TPM 2.0 Part 3:
// Commands" (with structure shapes from "Part 2: Structures").
//
// Conventions: pure Go, CGO_ENABLED=0, no architecture-specific assembly,
// BSD-3-Clause on every file, 100% statement coverage, and GOWORK=off (the
// module is not part of any workspace).
package tpm2
