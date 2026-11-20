// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/tpm2 authors. All rights reserved.

package tpm2

import "github.com/go-tpm2/common"

// This file names a TPM by its Endorsement Key. The EK of the L-2 template is
// derived from the endorsement primary seed (EPS) alone, so the same TPM
// always yields the same public point and two TPMs yield different ones, with
// the probability of a 256-bit collision. TCG "EK Credential Profile for TPM
// Family 2.0", "Template L-2" (the unique field is the only free part of the
// template); "TPM 2.0 Part 1: Architecture", "Primary Seeds" and "Names".
//
// What the name proves, and what it does not: it names the TPM whose seed made
// the key. It does NOT prove the TPM answering now is that one: whoever
// controls a software TPM, or sits on the wire to a TPM, can present any EK
// public. Proof of possession of the EK private key is TPM2_ActivateCredential
// (ActivateAKWithEK).

// FlushContext runs TPM2_FlushContext, releasing a transient object or a
// session. The kernel resource manager flushes what a connection loaded when
// it closes; a raw TPM stream (a software TPM, a hardware TPM without a
// resource manager) keeps the handle loaded until it is flushed, and has room
// for only a few (TPM_PT_HR_TRANSIENT_MIN is 3).
//
// Wire: TagNoSessions, CC 0x00000165, parameter TPMI_DH_CONTEXT flushHandle
// (u32). TCG "TPM 2.0 Part 3: Commands", clause "TPM2_FlushContext".
func (tpm *TPM) FlushContext(handle uint32) error {
	_, err := tpm.execute(common.TagNoSessions, ccFlushContext, common.PutU32(nil, handle))
	return err
}

// ccFlushContext is TPM_CC_FlushContext (common v0.1.0 predates it). TCG "TPM
// 2.0 Part 2: Structures", clause "TPM_CC (Command Codes)".
const ccFlushContext common.TPM_CC = 0x00000165

// ErrEKPoint is returned when the point the TPM reports for the EK does not
// fit the NIST P-256 curve's 32-byte coordinates: a TPM answer that is not an
// EK of the template asked for.
const ErrEKPoint = common.Error("tpm2: the EK public point is not a P-256 point (coordinates over 32 bytes)")

// EKName is the Name of the EK with public point pub: the TPM's own name for
// the key (nameAlg || SHA-256 of the TPMT_PUBLIC with that point), 34 bytes.
// It is computed, not read, so it can be pinned and compared without the TPM.
func EKName(pub EKPublic) ([]byte, error) {
	if len(pub.X) > 32 || len(pub.Y) > 32 {
		return nil, ErrEKPoint
	}
	return ObjectName(ekPublicArea(pub.X, pub.Y))
}

// EKIdentity creates the EK transiently, returns its Name and flushes the key:
// nothing is left loaded and nothing is made persistent. It is the identity of
// THIS TPM (see the note at the top of this file for what that proves). It
// needs an empty endorsement authValue, the default, like CreateEK.
func (tpm *TPM) EKIdentity() ([]byte, error) {
	h, pub, err := tpm.CreateEK()
	if err != nil {
		return nil, err
	}
	name, nerr := EKName(pub)
	if ferr := tpm.FlushContext(h); nerr == nil {
		nerr = ferr
	}
	return name, nerr
}
