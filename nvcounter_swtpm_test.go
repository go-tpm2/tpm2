// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/tpm2 authors. All rights reserved.

package tpm2

// A software TPM (swtpm, TPM 2.0) in the MS-simulator TCP mode drives the NV
// counter commands end to end. The test is skipped when swtpm is not
// installed, unless TPM2_REQUIRE_SWTPM is set (CI sets it), when a missing
// swtpm is a failure: a skipped test is not a pass.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/go-tpm2/common"
)

// swtpmConn frames commands for swtpm's TCP command channel:
// [TPM_SEND_COMMAND u32 | locality u8 | len u32 | cmd], reply
// [len u32 | rsp | result u32].
type swtpmConn struct{ c net.Conn }

func (s swtpmConn) Send(cmd []byte) ([]byte, error) {
	hdr := make([]byte, 9, 9+len(cmd))
	binary.BigEndian.PutUint32(hdr, 8)
	binary.BigEndian.PutUint32(hdr[5:], uint32(len(cmd)))
	if _, err := s.c.Write(append(hdr, cmd...)); err != nil {
		return nil, err
	}
	var n [4]byte
	if _, err := io.ReadFull(s.c, n[:]); err != nil {
		return nil, err
	}
	rsp := make([]byte, binary.BigEndian.Uint32(n[:]))
	if _, err := io.ReadFull(s.c, rsp); err != nil {
		return nil, err
	}
	_, err := io.ReadFull(s.c, n[:]) // trailing result code
	return rsp, err
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func dialRetry(t *testing.T, port int) net.Conn {
	t.Helper()
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		if c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			return c
		}
	}
	t.Fatalf("swtpm did not listen on %d", port)
	return nil
}

// startSwtpm launches a fresh swtpm and returns a TPM on its command channel.
func startSwtpm(t *testing.T) *TPM {
	t.Helper()
	bin, err := exec.LookPath("swtpm")
	if err != nil {
		if os.Getenv("TPM2_REQUIRE_SWTPM") != "" {
			t.Fatal("swtpm not installed and TPM2_REQUIRE_SWTPM is set")
		}
		t.Skip("swtpm not installed")
	}
	cmdPort, platPort := freePort(t), freePort(t)
	cmd := exec.Command(bin, "socket", "--tpm2", "--tpmstate", "dir="+t.TempDir(),
		"--server", fmt.Sprintf("type=tcp,port=%d", cmdPort),
		"--ctrl", fmt.Sprintf("type=tcp,port=%d", platPort),
		"--flags", "startup-clear", "--log", "level=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	plat := dialRetry(t, platPort)
	t.Cleanup(func() { plat.Close() })
	for _, c := range []uint32{1, 11} { // TPM_SIGNAL_POWER_ON, TPM_SIGNAL_NV_ON
		var b, r [4]byte
		binary.BigEndian.PutUint32(b[:], c)
		if _, err := plat.Write(b[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(plat, r[:]); err != nil {
			t.Fatal(err)
		}
	}
	conn := dialRetry(t, cmdPort)
	t.Cleanup(func() { conn.Close() })
	tpm := New(swtpmConn{conn})
	// startup-clear already started it; a second Startup is TPM_RC_INITIALIZE.
	_ = tpm.Startup(uint16(common.SUClear))
	return tpm
}

func rcOf(err error) uint32 {
	var te *TPMError
	if errors.As(err, &te) {
		return te.RC
	}
	return 0
}

func TestSwtpmCounter(t *testing.T) {
	tpm := startSwtpm(t)
	const idx, idx2 uint32 = 0x01500010, 0x01500011
	auth := []byte("index-secret")

	// A wrong owner password is refused (the owner auth of swtpm is empty).
	if _, err := tpm.NVDefineCounter([]byte("not the owner"), auth, idx); err == nil {
		t.Fatal("define accepted a wrong owner password")
	}
	name, err := tpm.NVDefineCounter(nil, auth, idx)
	if err != nil {
		t.Fatalf("NVDefineCounter: %v", err)
	}
	pub, name2, err := tpm.NVReadPublic(idx)
	if err != nil {
		t.Fatal(err)
	}
	if string(name) != string(name2) || len(name) != 34 || name[0] != 0 || name[1] != 0x0B {
		t.Fatalf("name %x vs %x", name, name2)
	}
	if pub.Attributes&^NVWritten != CounterAttributes || pub.DataSize != 8 || len(pub.AuthPolicy) != 0 {
		t.Fatalf("public area %+v", pub)
	}

	// Not yet written: reading is refused.
	if _, err := tpm.NVReadCounter(auth, idx); err == nil {
		t.Fatal("read of an unwritten counter")
	}
	// Wrong index password: refused, the counter does not move.
	if err := tpm.NVIncrementAuth(idx, []byte("wrong"), idx); err == nil {
		t.Fatal("increment with a wrong authValue")
	}
	// The owner is not the holder of the authValue.
	if err := tpm.NVIncrement(idx); err == nil {
		t.Fatal("owner incremented an AUTHWRITE-only counter")
	}
	if err := tpm.NVIncrementAuth(idx, auth, idx); err != nil {
		t.Fatalf("NVIncrementAuth: %v", err)
	}
	c0, err := tpm.NVReadCounter(auth, idx)
	if err != nil {
		t.Fatal(err)
	}
	for i := uint64(1); i <= 3; i++ {
		if err := tpm.NVIncrementAuth(idx, auth, idx); err != nil {
			t.Fatal(err)
		}
		if c, err := tpm.NVReadCounter(auth, idx); err != nil || c != c0+i {
			t.Fatalf("after %d increments: %d (%v), want %d", i, c, err, c0+i)
		}
	}
	if pub, _, _ := tpm.NVReadPublic(idx); pub.Attributes&NVWritten == 0 {
		t.Fatal("WRITTEN not set after an increment")
	}
	// Part 3 clause 31.7: NV_Write on a counter is TPM_RC_ATTRIBUTES.
	if err := tpm.NVWrite(idx, make([]byte, 8), 0); err == nil {
		t.Fatal("NV_Write on a counter")
	}
	// A second, live counter is independent of the first.
	if _, err := tpm.NVDefineCounter(nil, nil, idx2); err != nil {
		t.Fatal(err)
	}
	if err := tpm.NVIncrementAuth(idx2, nil, idx2); err != nil {
		t.Fatal(err)
	}
	c2, err := tpm.NVReadCounter(nil, idx2)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("first counter: first value %d, then %d; second counter: first value %d", c0, c0+3, c2)
	// Deleting and redefining the counter cannot lower it: the same Name
	// (same type, attributes, policy), a value above the bound recorded.
	if err := tpm.NVUndefineSpaceAuth([]byte("not the owner"), idx); err == nil {
		t.Fatal("undefine accepted a wrong owner password")
	}
	if err := tpm.NVUndefineSpaceAuth(nil, idx); err != nil {
		t.Fatal(err)
	}
	again, err := tpm.NVDefineCounter(nil, auth, idx)
	if err != nil || string(again) != string(name) {
		t.Fatalf("redefined name %x (%v), want %x", again, err, name)
	}
	if err := tpm.NVIncrementAuth(idx, auth, idx); err != nil {
		t.Fatal(err)
	}
	if c, err := tpm.NVReadCounter(auth, idx); err != nil || c <= c0+3 {
		t.Fatalf("redefined counter %d (%v), want above %d", c, err, c0+3)
	}
}
