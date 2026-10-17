// Copyright 2018-2020 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package uacp

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fakeACKServer accepts one connection, reads the HEL and replies with ack.
// The HEL is delivered on the returned channel.
func fakeACKServer(t *testing.T, ack *Acknowledge) (string, <-chan *Hello) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	hels := make(chan *Hello, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))

		var hdr [hdrlen]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return
		}
		body := make([]byte, binary.LittleEndian.Uint32(hdr[4:])-hdrlen)
		if _, err := io.ReadFull(c, body); err != nil {
			return
		}
		hel := new(Hello)
		if _, err := hel.Decode(body); err != nil {
			return
		}
		hels <- hel

		b, err := ack.Encode()
		if err != nil {
			return
		}
		msg := make([]byte, hdrlen, hdrlen+len(b))
		copy(msg, "ACKF")
		binary.LittleEndian.PutUint32(msg[4:], uint32(hdrlen+len(b)))
		if _, err := c.Write(append(msg, b...)); err != nil {
			return
		}
		// keep the connection open until the client closes it
		io.Copy(io.Discard, c)
	}()
	return "opc.tcp://" + ln.Addr().String(), hels
}

func TestClientHandshakeIgnoresHugeServerLimits(t *testing.T) {
	ep, hels := fakeACKServer(t, &Acknowledge{
		ReceiveBufSize: 0xF0000000,
		SendBufSize:    0xF0000000,
		MaxMessageSize: 0xF0000000,
		MaxChunkCount:  0xF0000000,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, ep)
	require.NoError(t, err)
	defer c.Close()

	hel := <-hels
	require.Equal(t, uint32(DefaultReceiveBufSize), hel.ReceiveBufSize)

	// Our receive side keeps our own limits.
	require.Equal(t, uint32(DefaultReceiveBufSize), c.ReceiveBufSize())
	require.Equal(t, uint32(DefaultMaxMessageSize), c.MaxMessageSize())
	require.Equal(t, uint32(DefaultMaxChunkCount), c.MaxChunkCount())

	// Our send side is limited by our own buffer, too.
	require.Equal(t, uint32(DefaultSendBufSize), c.SendBufSize())
	require.Equal(t, uint32(DefaultMaxMessageSize), c.SendMaxMessageSize())
	require.Equal(t, uint32(DefaultMaxChunkCount), c.SendMaxChunkCount())

	// The default client ACK must not have been modified.
	require.Equal(t, uint32(DefaultReceiveBufSize), DefaultClientACK.ReceiveBufSize)
	require.Equal(t, uint32(0), DefaultClientACK.MaxMessageSize)
}

func TestClientHandshakeServerLowersLimits(t *testing.T) {
	ep, _ := fakeACKServer(t, &Acknowledge{
		ReceiveBufSize: 8192,
		SendBufSize:    16384,
		MaxMessageSize: 64 * KB,
		MaxChunkCount:  4,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, ep)
	require.NoError(t, err)
	defer c.Close()

	// The server's SendBufferSize lowers our receive buffer, but its
	// message limits do not change what we accept.
	require.Equal(t, uint32(16384), c.ReceiveBufSize())
	require.Equal(t, uint32(DefaultMaxMessageSize), c.MaxMessageSize())
	require.Equal(t, uint32(DefaultMaxChunkCount), c.MaxChunkCount())

	// Our chunks and messages must fit the server's limits.
	require.Equal(t, uint32(8192), c.SendBufSize())
	require.Equal(t, uint32(64*KB), c.SendMaxMessageSize())
	require.Equal(t, uint32(4), c.SendMaxChunkCount())
}

func TestClientHandshakeRejectsUndersizedACK(t *testing.T) {
	tests := []struct {
		name string
		ack  *Acknowledge
	}{
		{"receive buffer", &Acknowledge{ReceiveBufSize: 8191, SendBufSize: 0xffff}},
		{"send buffer", &Acknowledge{ReceiveBufSize: 0xffff, SendBufSize: 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep, _ := fakeACKServer(t, tt.ack)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, err := Dial(ctx, ep)
			if c != nil {
				c.Close()
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid ACK")
		})
	}
}

// TestNegotiateNeverExceedsHello checks that a hostile ACK cannot grow the
// buffers beyond what the client announced in its HEL.
func TestNegotiateNeverExceedsHello(t *testing.T) {
	c := &Conn{ack: DefaultClientACK}
	hel := &Hello{
		ReceiveBufSize: DefaultReceiveBufSize,
		SendBufSize:    DefaultSendBufSize,
	}
	err := c.negotiate(hel, &Acknowledge{
		ReceiveBufSize: 0xF0000000,
		SendBufSize:    0xF0000000,
	})
	require.NoError(t, err)
	require.LessOrEqual(t, c.ReceiveBufSize(), hel.ReceiveBufSize)
	require.LessOrEqual(t, c.SendBufSize(), hel.SendBufSize)
}
