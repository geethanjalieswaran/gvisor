// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tcp_timestamp_test

import (
	"flag"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	tb "gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	tb.RegisterFlags(flag.CommandLine)
}

func TestTimeStamp(t *testing.T) {
	dut := tb.NewDUT(t)
	defer dut.TearDown()
	listenFd, remotePort := dut.CreateListener(unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	defer dut.Close(listenFd)
	conn := tb.NewTCPIPv4(t, tb.TCP{DstPort: &remotePort}, tb.TCP{SrcPort: &remotePort})
	defer conn.Close()

	recentTSO := HandshakeWithTSO(&conn, t)
	acceptFd, _ := dut.Accept(listenFd)
	defer dut.Close(acceptFd)

	sampleData := []byte("Sample Data")
	options := make([]byte, 10)
	sentTSVal := CurrentTS()
	header.EncodeTSOption(sentTSVal, recentTSO, options)
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck), Options: options}, &tb.Payload{Bytes: sampleData})

	gotTCP, err := conn.Expect(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck)}, time.Second)
	if err != nil {
		t.Fatalf("expected an ACK but got none: %s", err)
	}

	parsedOpts := header.ParseTCPOptions(gotTCP.Options)
	if !parsedOpts.TS {
		t.Fatalf("expected TS option in response")
	}
	if parsedOpts.TSVal < recentTSO {
		t.Fatalf("TSval should grow monotonically")
	}
	if parsedOpts.TSEcr != sentTSVal {
		t.Fatalf("TSecr should match our sent TSVal")
	}
	recentTSO = parsedOpts.TSVal
	lastAckNum := gotTCP.AckNum

	badTSVal := sentTSVal - 100
	header.EncodeTSOption(badTSVal, recentTSO, options)
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck), Options: options}, &tb.Payload{Bytes: sampleData})

	gotTCP, err = conn.Expect(tb.TCP{AckNum: lastAckNum, Flags: tb.Uint8(header.TCPFlagAck)}, time.Second)
	if err != nil {
		t.Fatalf("expected an ACK with last ack number but got none: %s", err)
	}
	parsedOpts = header.ParseTCPOptions(gotTCP.Options)
	if !parsedOpts.TS {
		t.Fatalf("expected TS option in response")
	}
	if parsedOpts.TSVal < recentTSO {
		t.Fatalf("TSval should grow monotonically")
	}
	if parsedOpts.TSEcr != sentTSVal {
		t.Fatalf("TSecr should match our sent TSVal")
	}
}

func CurrentTS() uint32 {
	now := time.Now()
	return uint32(now.Unix()*1000 + int64(now.Nanosecond()/1e6))
}

// HandshakeWithTSO performs handshake and returns the most recent TSVal
// sent by DUT.
func HandshakeWithTSO(conn *tb.TCPIPv4, t *testing.T) uint32 {
	// Send the SYN.
	options := make([]byte, 10)
	header.EncodeTSOption(CurrentTS(), 0, options)
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagSyn), Options: options})

	// Wait for the SYN-ACK.
	synAck, err := conn.Expect(tb.TCP{Flags: tb.Uint8(header.TCPFlagSyn | header.TCPFlagAck)}, time.Second)
	if synAck == nil {
		t.Fatalf("didn't get synack during handshake: %s", err)
	}
	parsedOpts := header.ParseSynOptions(synAck.Options, true)
	if !parsedOpts.TS {
		t.Fatalf("expected TSOpt from DUT")
	}

	header.EncodeTSOption(CurrentTS(), parsedOpts.TSVal, options)
	// Send an ACK.
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck), Options: options})
	return parsedOpts.TSVal
}
