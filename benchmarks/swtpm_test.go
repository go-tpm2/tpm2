// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/tpm2 authors. All rights reserved.

package benchmarks

// Shared swtpm harness for the round-trip benchmarks. It launches a real
// swtpm (software TPM 2.0) in the de-facto "MS simulator" TCP mode — a command
// channel on :2321 and a platform channel on :2322 — which both go-tpm2 and
// google/go-tpm can drive over the IDENTICAL byte-level Send([]byte)->[]byte
// transport. Driving one swtpm over one transport is what makes the round-trip
// comparison fair: any latency difference is purely the Go marshal/parse on
// each side, because the wire bytes and the TPM behind them are the same.
//
// On Darwin swtpm's TCP server mode works directly (verified: ports 2321/2322
// LISTEN), so unlike the QEMU/CRB validate harness (which needs --ctrl unixio)
// this needs no virtualization. End-to-end latency here is swtpm-bound; see
// BENCHMARKS.md.

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// swtpmTCP is a minimal client for swtpm's MS-simulator TCP command protocol:
// each command is framed [ TCP_SEND_COMMAND:u32 | locality:u8 | len:u32 |
// cmd... ] and the reply is [ len:u32 | rsp... | code:u32 ]. It satisfies the
// common.Transport contract (Send) AND google/go-tpm's transport.TPM contract,
// so the same instance drives both libraries.
type swtpmTCP struct {
	conn net.Conn
}

const (
	tcpSendCommand uint32 = 8 // TPM_SEND_COMMAND
	platPowerOn    uint32 = 1
	platNVOn       uint32 = 11
)

// Send transmits one fully-marshaled TPM command and returns the full response
// buffer (header + parameters), suitable for ParseResponse. This is the exact
// signature of common.Transport.Send and of go-tpm's transport.TPM.Send.
func (s *swtpmTCP) Send(cmd []byte) ([]byte, error) {
	var hdr [9]byte
	binary.BigEndian.PutUint32(hdr[0:], tcpSendCommand)
	hdr[4] = 0 // locality 0
	binary.BigEndian.PutUint32(hdr[5:], uint32(len(cmd)))
	if _, err := s.conn.Write(hdr[:]); err != nil {
		return nil, err
	}
	if _, err := s.conn.Write(cmd); err != nil {
		return nil, err
	}
	var lenBuf [4]byte
	if _, err := readFull(s.conn, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	rsp := make([]byte, int(n))
	if _, err := readFull(s.conn, rsp); err != nil {
		return nil, err
	}
	var codeBuf [4]byte // trailing TCP result code
	if _, err := readFull(s.conn, codeBuf[:]); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (s *swtpmTCP) Close() error { return s.conn.Close() }

func readFull(c net.Conn, b []byte) (int, error) {
	got := 0
	for got < len(b) {
		n, err := c.Read(b[got:])
		if err != nil {
			return got, err
		}
		got += n
	}
	return got, nil
}

// swtpmHarness is a launched swtpm plus its command/platform connections.
type swtpmHarness struct {
	cmd      *exec.Cmd
	cmdConn  net.Conn
	platConn net.Conn
	stateDir string
}

// startSWTPM launches swtpm in TCP mode, powers it on, and returns a harness.
// It skips (not fails) the benchmark when swtpm is not installed, so the
// pure-CPU benchmarks in the same module still run on a machine without swtpm.
func startSWTPM(tb testing.TB, cmdPort, platPort int) *swtpmHarness {
	tb.Helper()
	bin, err := exec.LookPath("swtpm")
	if err != nil {
		tb.Skip("swtpm not installed; skipping round-trip benchmark")
	}
	stateDir, err := os.MkdirTemp("", "swtpm-bench-")
	if err != nil {
		tb.Fatalf("mkdtemp: %v", err)
	}
	cmd := exec.Command(bin, "socket",
		"--tpm2",
		"--tpmstate", "dir="+filepath.Clean(stateDir),
		"--server", fmt.Sprintf("type=tcp,port=%d", cmdPort),
		"--ctrl", fmt.Sprintf("type=tcp,port=%d", platPort),
		"--flags", "startup-clear",
		"--log", "level=1",
	)
	if err := cmd.Start(); err != nil {
		os.RemoveAll(stateDir)
		tb.Fatalf("start swtpm: %v", err)
	}

	cmdConn := dialWait(tb, cmdPort)
	platConn := dialWait(tb, platPort)

	h := &swtpmHarness{cmd: cmd, cmdConn: cmdConn, platConn: platConn, stateDir: stateDir}

	// Power on the simulated platform (TPM_SEND_COMMAND needs power + NV).
	powerOn(tb, platConn)

	tb.Cleanup(func() { h.stop() })
	return h
}

func dialWait(tb testing.TB, port int) net.Conn {
	tb.Helper()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			return c
		}
		time.Sleep(50 * time.Millisecond)
	}
	tb.Fatalf("could not connect to swtpm at %s", addr)
	return nil
}

func powerOn(tb testing.TB, plat net.Conn) {
	tb.Helper()
	for _, c := range []uint32{platPowerOn, platNVOn} {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], c)
		if _, err := plat.Write(b[:]); err != nil {
			tb.Fatalf("platform command %d: %v", c, err)
		}
		var res [4]byte
		if _, err := readFull(plat, res[:]); err != nil {
			tb.Fatalf("platform result %d: %v", c, err)
		}
	}
}

func (h *swtpmHarness) transport() *swtpmTCP { return &swtpmTCP{conn: h.cmdConn} }

func (h *swtpmHarness) stop() {
	if h.cmdConn != nil {
		h.cmdConn.Close()
	}
	if h.platConn != nil {
		h.platConn.Close()
	}
	if h.cmd != nil && h.cmd.Process != nil {
		_ = h.cmd.Process.Kill()
		_, _ = h.cmd.Process.Wait()
	}
	if h.stateDir != "" {
		os.RemoveAll(h.stateDir)
	}
}
