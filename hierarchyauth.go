// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/tpm2 authors. All rights reserved.

package tpm2

import "github.com/go-tpm2/common"

// RHLockout is TPM_RH_LOCKOUT, the lockout hierarchy handle. TCG "TPM 2.0 Part
// 2: Structures", clause "TPM_RH (Permanent Handles)".
const RHLockout uint32 = 0x4000000A

// ccHierarchyChangeAuth is TPM_CC_HierarchyChangeAuth. TCG "TPM 2.0 Part 2:
// Structures", clause "TPM_CC (Command Codes)".
const ccHierarchyChangeAuth common.TPM_CC = 0x00000129

// PTLockoutCounter is TPM_PT_LOCKOUT_COUNTER (PT_VAR + 14): failedTries, the
// count of authorization failures that count toward the dictionary-attack
// lockout. TCG "TPM 2.0 Part 2: Structures", clause "TPM_PT".
const PTLockoutCounter uint32 = 0x0000020E

// HierarchyChangeAuth runs TPM2_HierarchyChangeAuth: it sets the authValue of
// the hierarchy (RHOwner, RHEndorsement, RHLockout or the platform hierarchy)
// to newAuth, authorized by the current authValue auth (a password session).
// newAuth is a TPM2B_AUTH: at most the digest size of the largest hash the TPM
// implements. TCG "TPM 2.0 Part 3: Commands", clause "TPM2_HierarchyChangeAuth".
//
// Body (TagSessions): authHandle (u32) || authorizationSize (u32) ||
// TPMS_AUTH_COMMAND || newAuth (TPM2B_AUTH).
func (tpm *TPM) HierarchyChangeAuth(hierarchy uint32, auth, newAuth []byte) error {
	body := common.PutU32(nil, hierarchy)
	a := marshalAuth(auth)
	body = common.PutU32(body, uint32(len(a)))
	body = append(body, a...)
	body = append(body, common.MarshalTPM2B(newAuth)...)
	_, err := tpm.execute(common.TagSessions, ccHierarchyChangeAuth, body)
	return err
}
