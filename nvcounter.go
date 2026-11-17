// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/tpm2 authors. All rights reserved.

package tpm2

import (
	"errors"

	"github.com/go-tpm2/common"
)

// This file adds NV counters: TPM2_NV_Increment, and the password-authorized
// forms of NV_DefineSpace, NV_UndefineSpace and NV_Read that an index with its
// own authValue needs. TCG "TPM 2.0 Library Part 3: Commands", rev 1.83
// (opened): clause 31.3 "TPM2_NV_DefineSpace" (pp. 378-379), clause 31.7
// "TPM2_NV_Write" (p. 391: NV_Write on a TPM_NT_COUNTER index is
// TPM_RC_ATTRIBUTES), clause 31.8 "TPM2_NV_Increment" (pp. 394-395).

// ccNVIncrement is TPM_CC_NV_Increment. TCG "TPM 2.0 Part 2: Structures", rev
// 1.83, Table 12 (p. 34, opened), and TestSwtpmCounter against a software TPM.
const ccNVIncrement common.TPM_CC = 0x00000134

// More TPMA_NV bits (TPMA_NV is a UINT32; TCG "TPM 2.0 Part 2: Structures",
// clause "TPMA_NV"; the layout is exercised against a software TPM by
// TestSwtpmCounter).
const (
	// NVTypeCounter is TPM_NT_COUNTER (1) in the TPM_NT field, bits 7:4.
	NVTypeCounter uint32 = 1 << 4
	// NVWritten (bit 29): set by the TPM once the index has been written (for
	// a counter: incremented) at least once.
	NVWritten uint32 = 1 << 29

	// CounterAttributes is the TPMA_NV of a rollback counter: a TPM_NT_COUNTER
	// index, incremented and read under its own authValue (AUTHWRITE,
	// AUTHREAD). Deliberately NOT set:
	//
	//   - ORDERLY: after a non-orderly shutdown the TPM advances such a counter
	//     by MAX_ORDERLY_COUNT (clause 31.8.1, note 2);
	//   - OWNERWRITE: the owner could then increment without the authValue;
	//   - POLICY_DELETE: Part 3 clause 31.3.1 (p. 378) allows it only when
	//     the index is defined with Platform Authorization, which user space
	//     does not hold. The owner can therefore delete the index (and
	//     TPM2_Clear removes it, note 4). That is a denial of service, not a
	//     rollback: a redefined counter starts above every earlier count on
	//     the TPM (Part 3 p. 376), so a bound value recorded earlier never
	//     matches it again.
	CounterAttributes = NVTypeCounter | NVAuthWrite | NVAuthRead
)

// CounterSize is the data size of a TPM_NT_COUNTER index: a UINT64 (clause
// 31.3.1: dataSize shall be eight).
const CounterSize = 8

// ErrCounterSize is returned when NV_Read of a counter does not return exactly
// CounterSize bytes.
var ErrCounterSize = errors.New("tpm2: NV counter value is not 8 bytes")

// marshalAuth renders the TPMS_AUTH_COMMAND of a cleartext-password session
// carrying authValue in the hmac field. TCG "TPM 2.0 Part 1: Architecture",
// "Password Authorizations".
func marshalAuth(authValue []byte) []byte {
	out := common.PutU32(nil, TPM_RS_PW)
	out = common.PutU16(out, 0) // nonce: empty
	out = common.PutU8(out, sessionContinue)
	return append(out, common.MarshalTPM2B(authValue)...)
}

// NVDefineSpaceAuth is NVDefineSpace with passwords: ownerAuth authorizes the
// definition under TPM_RH_OWNER, and indexAuth becomes the new index's
// authValue (TPM2B_AUTH inSensitive). Both may be empty. The authValue may be
// no longer than the digest of the index's nameAlg (clause 31.3.1, p. 379).
func (tpm *TPM) NVDefineSpaceAuth(ownerAuth, indexAuth []byte, pub NVPublic) error {
	body := common.PutU32(nil, RHOwner)
	auth := marshalAuth(ownerAuth)
	body = common.PutU32(body, uint32(len(auth)))
	body = append(body, auth...)
	body = append(body, common.MarshalTPM2B(indexAuth)...)
	body = append(body, marshalNVPublic(pub)...)
	_, err := tpm.execute(common.TagSessions, ccNVDefineSpace, body)
	return err
}

// NVDefineCounter defines the rollback counter index nvIndex: a
// TPM_NT_COUNTER of CounterSize bytes, named by SHA-256, with
// CounterAttributes and no authPolicy. ownerAuth authorizes it, indexAuth is
// the counter's authValue. It returns the index's Name as the TPM computed it
// (NV_ReadPublic), which a caller pins: an index redefined as another type or
// with other attributes has a different Name. The new counter is not yet
// written; the first increment does that.
func (tpm *TPM) NVDefineCounter(ownerAuth, indexAuth []byte, nvIndex uint32) ([]byte, error) {
	err := tpm.NVDefineSpaceAuth(ownerAuth, indexAuth, NVPublic{
		Index:      nvIndex,
		NameAlg:    algSHA256,
		Attributes: CounterAttributes,
		DataSize:   CounterSize,
	})
	if err != nil {
		return nil, err
	}
	_, name, err := tpm.NVReadPublic(nvIndex)
	return name, err
}

// NVUndefineSpaceAuth is NVUndefineSpace with the owner's password.
func (tpm *TPM) NVUndefineSpaceAuth(ownerAuth []byte, nvIndex uint32) error {
	body := common.PutU32(nil, RHOwner)
	body = common.PutU32(body, nvIndex)
	auth := marshalAuth(ownerAuth)
	body = common.PutU32(body, uint32(len(auth)))
	body = append(body, auth...)
	_, err := tpm.execute(common.TagSessions, ccNVUndefineSpace, body)
	return err
}

// NVIncrementAuth runs TPM2_NV_Increment (Part 3 clause 31.8). authHandle is
// the handle the authorization comes from, TPM_RH_OWNER or nvIndex itself,
// and auth its password.
//
//	handle area: authHandle (u32) || nvIndex (u32)
//	auth   area: authorizationSize (u32) || TPMS_AUTH_COMMAND (RS_PW, auth)
//	(no parameters, no response parameters)
//
// A counter that was never written is written by this call (TPMA_NV_WRITTEN
// becomes SET). Do not define the index with TPMA_NV_ORDERLY: after a
// non-orderly shutdown the TPM advances such a counter by MAX_ORDERLY_COUNT
// (clause 31.8.1, note 2).
func (tpm *TPM) NVIncrementAuth(authHandle uint32, auth []byte, nvIndex uint32) error {
	body := common.PutU32(nil, authHandle)
	body = common.PutU32(body, nvIndex)
	a := marshalAuth(auth)
	body = common.PutU32(body, uint32(len(a)))
	body = append(body, a...)
	_, err := tpm.execute(common.TagSessions, ccNVIncrement, body)
	return err
}

// NVIncrement is NVIncrementAuth under TPM_RH_OWNER with an empty password,
// the twin of NVWrite: it needs an index defined with OWNERWRITE.
func (tpm *TPM) NVIncrement(nvIndex uint32) error {
	return tpm.NVIncrementAuth(RHOwner, nil, nvIndex)
}

// NVReadAuth is NVRead with a chosen authorization handle and password: for
// an index with AUTHREAD, authHandle is nvIndex itself.
func (tpm *TPM) NVReadAuth(authHandle uint32, auth []byte, nvIndex uint32, size, offset uint16) ([]byte, error) {
	body := common.PutU32(nil, authHandle)
	body = common.PutU32(body, nvIndex)
	a := marshalAuth(auth)
	body = common.PutU32(body, uint32(len(a)))
	body = append(body, a...)
	body = common.PutU16(body, size)
	body = common.PutU16(body, offset)
	rp, err := tpm.execute(common.TagSessions, ccNVRead, body)
	if err != nil {
		return nil, err
	}
	return parseNVReadResponse(rp)
}

// parseNVReadResponse decodes parameterSize || TPM2B_MAX_NV_BUFFER.
func parseNVReadResponse(rp []byte) ([]byte, error) {
	if _, ok := common.GetU32(rp, 0); !ok {
		return nil, common.ErrShortBuffer
	}
	d, _, err := common.UnmarshalTPM2B(rp[4:])
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), d...), nil
}

// NVReadCounter reads the 64-bit value of the counter nvIndex, authorized by
// the index's own authValue (AUTHREAD). A counter never incremented is
// TPM_RC_NV_UNINITIALIZED.
func (tpm *TPM) NVReadCounter(auth []byte, nvIndex uint32) (uint64, error) {
	d, err := tpm.NVReadAuth(nvIndex, auth, nvIndex, CounterSize, 0)
	if err != nil {
		return 0, err
	}
	return counterValue(d)
}

// counterValue decodes the big-endian UINT64 of a counter.
func counterValue(d []byte) (uint64, error) {
	if len(d) != CounterSize {
		return 0, ErrCounterSize
	}
	var v uint64
	for _, b := range d {
		v = v<<8 | uint64(b)
	}
	return v, nil
}
