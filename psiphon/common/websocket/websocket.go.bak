/*
 * Copyright (c) 2026, Psiphon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

// Package websocket implements a minimal, dependency-free RFC 6455
// WebSocket client handshake, server handshake (upgrade), and binary
// frame codec sufficient to carry an OSSH byte stream.
//
// This is intentionally NOT a general-purpose WebSocket library: no
// text frames, no fragmentation across application Write() calls, no
// extensions/compression, minimal ping/pong/close handling. It exists
// solely to let UNFRONTED-WS-OSSH / UNFRONTED-WSS-OSSH / FRONTED-WS-OSSH /
// FRONTED-WSS-OSSH tunnel raw OSSH bytes inside WebSocket binary frames,
// the same way MeekConn tunnels OSSH bytes inside HTTP request/response
// bodies.
//
// NOTE: this is reference code written for integration into
// psiphon-tunnel-core. It has not been fuzz-tested or run against a
// hostile peer; before relying on it in production, add the same kind
// of test coverage that meekConn_test.go / meek_test.go have, and
// consider bounds/DoS review of readFrame (frame size limits, slow-loris
// on the handshake read, etc.)
package websocket

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA

	// maxFramePayload bounds how much we put in a single outbound frame.
	// Larger writes are split across multiple frames.
	maxFramePayload = 16384

	// maxReadFrame bounds the size of a single inbound frame we're willing
	// to buffer, as a basic defense against a malicious/broken peer
	// claiming an enormous payload length.
	maxReadFrame = 1 << 20 // 1 MiB

	websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
)

// Conn wraps an already-established net.Conn (raw TCP, or already
// TLS-wrapped for the WSS variants) and speaks binary WebSocket framing
// over it. It implements net.Conn so it can be used as a drop-in OSSH
// transport wherever psiphon.MeekConn / psiphon.TLSTunnelConn are used
// today.
type Conn struct {
	net.Conn
	isClient bool
	br       *bufio.Reader
	readBuf  []byte
}

// newConn constructs a Conn around an underlying connection and an
// optional bufio.Reader that may already have buffered bytes read past
// the HTTP handshake response/request (br may be nil).
func newConn(underlying net.Conn, isClient bool, br *bufio.Reader) *Conn {
	if br == nil {
		br = bufio.NewReaderSize(underlying, maxFramePayload)
	}
	return &Conn{
		Conn:     underlying,
		isClient: isClient,
		br:       br,
	}
}

// ClientHandshake performs the WebSocket opening handshake as a client,
// over conn, which must already be dialed (and, for WSS, already
// TLS-wrapped) to the peer. hostHeader is the Host header value to send
// -- for FRONTED-WS(S)-OSSH this is the true origin server's identity,
// while conn was actually dialed to a CDN edge address, mirroring how
// MeekConn separates DialAddress from the Host header / SNI used for
// fronting. resourcePath is the HTTP request path (servers should accept
// a fixed, shared-secret-derived path rather than "/", to avoid trivial
// fingerprinting -- see server-side Upgrade for the matching check).
func ClientHandshake(conn net.Conn, hostHeader string, resourcePath string) (*Conn, error) {

	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, fmt.Errorf("websocket: rand key: %w", err)
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)

	request := "GET " + resourcePath + " HTTP/1.1\r\n" +
		"Host: " + hostHeader + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"\r\n"

	if _, err := io.WriteString(conn, request); err != nil {
		return nil, fmt.Errorf("websocket: write request: %w", err)
	}

	br := bufio.NewReaderSize(conn, maxFramePayload)

	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		return nil, fmt.Errorf("websocket: read response: %w", err)
	}
	// Drain and discard any (unexpected) response body without holding
	// the connection.
	_, _ = io.CopyN(io.Discard, resp.Body, 0)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("websocket: unexpected status %d", resp.StatusCode)
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		return nil, errors.New("websocket: missing/invalid Upgrade header")
	}
	if !strings.EqualFold(resp.Header.Get("Connection"), "upgrade") {
		return nil, errors.New("websocket: missing/invalid Connection header")
	}
	if resp.Header.Get("Sec-WebSocket-Accept") != acceptKey(key) {
		return nil, errors.New("websocket: Sec-WebSocket-Accept mismatch")
	}

	return newConn(conn, true, carryOverBuffer(br, conn)), nil
}

// Upgrade performs the WebSocket opening handshake as a server, given the
// inbound HTTP request. requiredPath, if non-empty, restricts upgrades to
// that exact request path (recommended: derive this from a per-server or
// per-deployment secret rather than hard-coding "/", so that scanning for
// a bare Upgrade: websocket response doesn't immediately fingerprint the
// server as running this protocol).
func Upgrade(w http.ResponseWriter, r *http.Request, requiredPath string) (*Conn, error) {

	if requiredPath != "" && r.URL.Path != requiredPath {
		return nil, errors.New("websocket: path mismatch")
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return nil, errors.New("websocket: not an upgrade request")
	}
	if !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		return nil, errors.New("websocket: missing Connection: Upgrade")
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, errors.New("websocket: missing Sec-WebSocket-Key")
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("websocket: ResponseWriter does not support hijacking")
	}
	conn, brw, err := hijacker.Hijack()
	if err != nil {
		return nil, fmt.Errorf("websocket: hijack: %w", err)
	}

	response := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + acceptKey(key) + "\r\n" +
		"\r\n"

	if _, err := brw.WriteString(response); err != nil {
		conn.Close()
		return nil, fmt.Errorf("websocket: write response: %w", err)
	}
	if err := brw.Flush(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("websocket: flush response: %w", err)
	}

	return newConn(conn, false, carryOverBuffer(brw.Reader, conn)), nil
}

// carryOverBuffer returns a bufio.Reader that first yields any bytes
// already buffered in br (which may include the start of the first
// WebSocket frame, read speculatively while parsing HTTP headers) and
// then continues reading from underlying.
func carryOverBuffer(br *bufio.Reader, underlying net.Conn) *bufio.Reader {
	if br == nil || br.Buffered() == 0 {
		return bufio.NewReaderSize(underlying, maxFramePayload)
	}
	buffered := make([]byte, br.Buffered())
	_, _ = io.ReadFull(br, buffered)
	return bufio.NewReaderSize(io.MultiReader(bytes.NewReader(buffered), underlying), maxFramePayload)
}

func acceptKey(key string) string {
	h := sha1.New()
	h.Write([]byte(key))
	h.Write([]byte(websocketGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// DerivePath deterministically derives an HTTP request path from a
// pre-shared secret. Both the client (from ServerEntry.MeekObfuscatedKey)
// and the server (from Config.MeekObfuscatedKey) already possess this
// same secret today, for the existing MEEK protocols -- reusing it here
// means UNFRONTED/FRONTED-WS(S)-OSSH gets a non-default, non-guessable
// upgrade path with zero additional configuration required.
func DerivePath(secret string) string {
	h := sha256.Sum256([]byte("psiphon-ws-ossh-path|" + secret))
	return "/" + hex.EncodeToString(h[:])[:24]
}

// Read implements net.Conn / io.Reader, returning payload bytes from
// binary frames. Ping frames are answered with Pong and skipped; Close
// frames surface as io.EOF.
func (c *Conn) Read(p []byte) (int, error) {
	for len(c.readBuf) == 0 {
		payload, opcode, err := c.readFrame()
		if err != nil {
			return 0, err
		}
		switch opcode {
		case opBinary, opContinuation, opText:
			c.readBuf = payload
		case opPing:
			if err := c.writeFrame(opPong, payload); err != nil {
				return 0, err
			}
		case opPong:
			// ignore
		case opClose:
			_ = c.writeFrame(opClose, nil)
			return 0, io.EOF
		default:
			return 0, fmt.Errorf("websocket: unsupported opcode %d", opcode)
		}
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

// Write implements net.Conn / io.Writer, sending payload bytes as one or
// more binary frames.
func (c *Conn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxFramePayload {
			chunk = chunk[:maxFramePayload]
		}
		if err := c.writeFrame(opBinary, chunk); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

// Close sends a best-effort Close frame, then closes the underlying
// connection.
func (c *Conn) Close() error {
	_ = c.writeFrame(opClose, nil)
	return c.Conn.Close()
}

func (c *Conn) readFrame() ([]byte, byte, error) {

	header := make([]byte, 2)
	if _, err := io.ReadFull(c.br, header); err != nil {
		return nil, 0, err
	}

	opcode := header[0] & 0x0F
	masked := header[1]&0x80 != 0
	payloadLen := int64(header[1] & 0x7F)

	switch payloadLen {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(c.br, ext); err != nil {
			return nil, 0, err
		}
		payloadLen = int64(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(c.br, ext); err != nil {
			return nil, 0, err
		}
		payloadLen = int64(binary.BigEndian.Uint64(ext))
	}

	if payloadLen < 0 || payloadLen > maxReadFrame {
		return nil, 0, fmt.Errorf("websocket: frame too large (%d bytes)", payloadLen)
	}

	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(c.br, maskKey[:]); err != nil {
			return nil, 0, err
		}
	}

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(c.br, payload); err != nil {
		return nil, 0, err
	}

	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}

	return payload, opcode, nil
}

func (c *Conn) writeFrame(opcode byte, payload []byte) error {

	finOp := byte(0x80) | opcode

	maskBit := byte(0)
	if c.isClient {
		maskBit = 0x80
	}

	var header []byte
	switch {
	case len(payload) < 126:
		header = []byte{finOp, maskBit | byte(len(payload))}
	case len(payload) <= 0xFFFF:
		header = make([]byte, 4)
		header[0] = finOp
		header[1] = maskBit | 126
		binary.BigEndian.PutUint16(header[2:], uint16(len(payload)))
	default:
		header = make([]byte, 10)
		header[0] = finOp
		header[1] = maskBit | 127
		binary.BigEndian.PutUint64(header[2:], uint64(len(payload)))
	}

	buf := make([]byte, 0, len(header)+4+len(payload))
	buf = append(buf, header...)

	if c.isClient {
		// RFC 6455 requires client-to-server frames to be masked.
		var maskKey [4]byte
		if _, err := rand.Read(maskKey[:]); err != nil {
			return fmt.Errorf("websocket: rand mask: %w", err)
		}
		buf = append(buf, maskKey[:]...)
		masked := make([]byte, len(payload))
		for i, b := range payload {
			masked[i] = b ^ maskKey[i%4]
		}
		buf = append(buf, masked...)
	} else {
		buf = append(buf, payload...)
	}

	_, err := c.Conn.Write(buf)
	return err
}
