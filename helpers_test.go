// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/tpm2 authors. All rights reserved.

package tpm2

import "github.com/go-tpm2/common"

// Shared test helpers for the NV / capability / EK suites. The fakeTransport,
// resp, and okResp helpers live in tpm2_test.go; these add response builders
// for the two response tags and small byte-assembly utilities.

// sessOK is resp with TagSessions and RCSuccess: a session-tagged success
// reply (the shape commands issued with TagSessions get back).
func sessOK(params []byte) []byte {
	return resp(uint16(common.TagSessions), uint32(common.RCSuccess), params)
}

// noSessOK is resp with TagNoSessions and RCSuccess.
func noSessOK(params []byte) []byte {
	return resp(uint16(common.TagNoSessions), uint32(common.RCSuccess), params)
}

// rsPWAuth is the on-wire TPMS_AUTH_COMMAND for the empty-auth RS_PW password
// session, the 9-byte area every owner-authorized command in these suites
// carries: sessionHandle 0x40000009 || empty nonce || continueSession ||
// empty hmac.
func rsPWAuth() []byte {
	return []byte{
		0x40, 0x00, 0x00, 0x09, // sessionHandle = TPM_RS_PW
		0x00, 0x00, // nonce: empty TPM2B
		0x01,       // sessionAttributes = continueSession
		0x00, 0x00, // hmac: empty TPM2B
	}
}

// concat joins byte slices, for assembling hand-derived expected buffers.
func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
