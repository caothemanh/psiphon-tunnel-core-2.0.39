#!/usr/bin/env python3
"""
Patch script: adds optional SOCKS5 UDP ASSOCIATE support to
psiphon-tunnel-core, bridged to the existing server-side udpgw
interception feature. No server changes required.

Usage (same pattern as your other CI patch steps):

    cd go/src/github.com/Psiphon-Labs/psiphon-tunnel-core
    python3 patch_socks_udp_associate.py

Files touched:
  - psiphon/config.go       (adds EnableSocksUDPAssociate bool field)
  - psiphon/controller.go   (routes to the UDP-associate-capable proxy
                              when EnableSocksUDPAssociate is true)
  - psiphon/socksUdpAssociate.go  (new file, written from scratch)

After patching, set EnableSocksUDPAssociate: true in your client config
JSON to enable it. Requires the server to have
UDPInterceptUdpgwServerAddress configured (e.g. "127.0.0.1:7300").
"""

import sys

# ---------------------------------------------------------------------
# 1. psiphon/config.go — add the new field
# ---------------------------------------------------------------------

config_path = "psiphon/config.go"
content = open(config_path).read()

old = (
    '\t// DisableLocalSocksProxy disables running the local SOCKS proxy.\n'
    '\tDisableLocalSocksProxy bool `json:",omitempty"`'
)
new = (
    '\t// DisableLocalSocksProxy disables running the local SOCKS proxy.\n'
    '\tDisableLocalSocksProxy bool `json:",omitempty"`\n'
    '\n'
    '\t// EnableSocksUDPAssociate causes the local SOCKS proxy to use an\n'
    '\t// alternate listener that supports the SOCKS5 UDP ASSOCIATE command\n'
    '\t// (RFC 1928), in addition to CONNECT. UDP datagrams are bridged to\n'
    '\t// the Psiphon server\'s udpgw interception feature over the existing\n'
    '\t// tunnel. Requires the server to have UDPInterceptUdpgwServerAddress\n'
    '\t// configured. Has no effect if DisableLocalSocksProxy is set.\n'
    '\tEnableSocksUDPAssociate bool `json:",omitempty"`'
)

if old in content:
    content = content.replace(old, new)
    open(config_path, "w").write(content)
    print("Patched config.go successfully")
else:
    print("config.go pattern not found!")
    idx = content.find("DisableLocalSocksProxy")
    print(repr(content[idx - 10:idx + 200]))
    sys.exit(1)

# ---------------------------------------------------------------------
# 2. psiphon/controller.go — route to the new proxy when enabled
# ---------------------------------------------------------------------

controller_path = "psiphon/controller.go"
content = open(controller_path).read()

old = (
    '\t\tif !controller.config.DisableLocalSocksProxy {\n'
    '\t\t\tsocksProxy, err := NewSocksProxy(controller.config, controller, listenIP)\n'
    '\t\t\tif err != nil {\n'
    '\t\t\t\tNoticeError("error initializing local SOCKS proxy: %v", errors.Trace(err))\n'
    '\t\t\t\treturn\n'
    '\t\t\t}\n'
    '\t\t\tdefer socksProxy.Close()\n'
    '\t\t}'
)
new = (
    '\t\tif !controller.config.DisableLocalSocksProxy {\n'
    '\t\t\tif controller.config.EnableSocksUDPAssociate {\n'
    '\t\t\t\tsocksProxy, err := NewUDPAssociateSocksProxy(controller.config, controller, listenIP)\n'
    '\t\t\t\tif err != nil {\n'
    '\t\t\t\t\tNoticeError("error initializing local SOCKS proxy: %v", errors.Trace(err))\n'
    '\t\t\t\t\treturn\n'
    '\t\t\t\t}\n'
    '\t\t\t\tdefer socksProxy.Close()\n'
    '\t\t\t} else {\n'
    '\t\t\t\tsocksProxy, err := NewSocksProxy(controller.config, controller, listenIP)\n'
    '\t\t\t\tif err != nil {\n'
    '\t\t\t\t\tNoticeError("error initializing local SOCKS proxy: %v", errors.Trace(err))\n'
    '\t\t\t\t\treturn\n'
    '\t\t\t\t}\n'
    '\t\t\t\tdefer socksProxy.Close()\n'
    '\t\t\t}\n'
    '\t\t}'
)

if old in content:
    content = content.replace(old, new)
    open(controller_path, "w").write(content)
    print("Patched controller.go successfully")
else:
    print("controller.go pattern not found!")
    idx = content.find("NewSocksProxy(controller.config")
    print(repr(content[idx - 200:idx + 200]))
    sys.exit(1)

# ---------------------------------------------------------------------
# 3. psiphon/socksUdpAssociate.go — new file
# ---------------------------------------------------------------------

new_file_path = "psiphon/socksUdpAssociate.go"
new_file_content = r'''/*
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

// This file adds optional SOCKS5 UDP ASSOCIATE (RFC 1928) support to the
// local SOCKS proxy. This is NOT part of upstream psiphon-tunnel-core.
//
// Background: the vendored goptlib SOCKS server only implements the
// CONNECT command; UDP ASSOCIATE requests are rejected with
// SocksRepCommandNotSupported. Some downstream consumers (e.g. an app
// that re-shares its Psiphon connection to other devices over a local
// SOCKS5 proxy) need UDP ASSOCIATE to relay real-time UDP traffic such
// as WebRTC/RTP for voice/video calls.
//
// This file implements a minimal, self-contained SOCKS5 handshake
// (greeting + no-auth + command) that supports both CONNECT (proxied to
// the existing tunneler.Dial path, mirroring socksConnectionHandler) and
// UDP ASSOCIATE. UDP ASSOCIATE datagrams are bridged to the Psiphon
// server's existing "udpgw" interception feature: the client dials a
// plain SSH port-forward channel to config.UDPInterceptUdpgwServerAddress
// equivalent -- from the client's perspective this is simply
// tunneler.Dial("127.0.0.1:7300", ...) -- and the server-side
// handleUdpgwChannel (see psiphon/server/udp.go) transparently relays
// real UDP packets. No server-side or protocol changes are required;
// this is purely a client-side bridge between the SOCKS5 UDP ASSOCIATE
// wire format and the existing udpgw wire format.
//
// Enable by setting Config.EnableSocksUDPAssociate = true. When false
// (the default), behavior is completely unchanged: NewSocksProxy uses
// the original goptlib-based listener.

package psiphon

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

const (
	socks5Version = 0x05

	socks5AuthNoneRequired        = 0x00
	socks5AuthNoAcceptableMethods = 0xff

	socks5CmdConnect      = 0x01
	socks5CmdBind         = 0x02
	socks5CmdUDPAssociate = 0x03

	socks5AtypV4     = 0x01
	socks5AtypDomain = 0x03
	socks5AtypV6     = 0x04

	socks5RepSucceeded            = 0x00
	socks5RepGeneralFailure       = 0x01
	socks5RepCommandNotSupported  = 0x07
	socks5RepAddressNotSupported  = 0x08

	// The magic address the Psiphon server is configured to intercept as
	// a udpgw channel (must match server config
	// UDPInterceptUdpgwServerAddress).
	udpgwInterceptAddress = "127.0.0.1:7300"

	// udpgw wire protocol constants (must match psiphon/server/udp.go).
	udpgwFlagKeepalive = 1 << 0
	udpgwFlagRebind    = 1 << 1
	udpgwFlagDNS       = 1 << 2
	udpgwFlagIPv6      = 1 << 3

	udpgwMaxPayloadSize = 32768

	udpAssociateSessionIdleTimeout = 2 * time.Minute
)

// EnableSocksUDPAssociate, when set on Config, causes NewSocksProxy to use
// a custom SOCKS5 listener that supports both CONNECT and UDP ASSOCIATE,
// instead of the default goptlib-based CONNECT-only listener.
//
// Add this field to the Config struct in config.go:
//
//   EnableSocksUDPAssociate bool `json:",omitempty"`

// udpAssociateSocksProxy is an alternate SocksProxy implementation used
// when config.EnableSocksUDPAssociate is true.
type udpAssociateSocksProxy struct {
	config                 *Config
	tunneler               Tunneler
	listener               net.Listener
	serveWaitGroup         *sync.WaitGroup
	stopListeningBroadcast chan struct{}
	nextConnID             uint32
}

// NewUDPAssociateSocksProxy initializes a SOCKS proxy that supports both
// CONNECT and UDP ASSOCIATE. See NewSocksProxy for the standard,
// CONNECT-only proxy.
func NewUDPAssociateSocksProxy(
	config *Config,
	tunneler Tunneler,
	listenIP string) (*udpAssociateSocksProxy, error) {

	listener, portInUse, err := makeLocalProxyListener(listenIP, config.LocalSocksProxyPort)
	if err != nil {
		if portInUse {
			NoticeSocksProxyPortInUse(config.LocalSocksProxyPort)
		}
		return nil, errors.Trace(err)
	}

	proxy := &udpAssociateSocksProxy{
		config:                 config,
		tunneler:               tunneler,
		listener:                listener,
		serveWaitGroup:         new(sync.WaitGroup),
		stopListeningBroadcast: make(chan struct{}),
	}

	proxy.serveWaitGroup.Add(1)
	go proxy.serve()

	NoticeListeningSocksProxyPort(proxy.listener.Addr().(*net.TCPAddr).Port)

	return proxy, nil
}

func (proxy *udpAssociateSocksProxy) Close() {
	close(proxy.stopListeningBroadcast)
	proxy.listener.Close()
	proxy.serveWaitGroup.Wait()
}

func (proxy *udpAssociateSocksProxy) serve() {
	defer proxy.listener.Close()
	defer proxy.serveWaitGroup.Done()

	for {
		conn, err := proxy.listener.Accept()
		select {
		case <-proxy.stopListeningBroadcast:
			return
		default:
		}
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Temporary() {
				continue
			}
			proxy.tunneler.SignalComponentFailure()
			return
		}

		go func(c net.Conn) {
			defer c.Close()
			err := proxy.handleConnection(c)
			if err != nil {
				NoticeWarning("SOCKS UDP associate proxy: %s", errors.Trace(err))
			}
		}(conn)
	}
}

// handleConnection performs the SOCKS5 greeting/auth negotiation, then
// dispatches to a CONNECT or UDP ASSOCIATE handler based on the command
// byte. SOCKS4/4a is intentionally not supported by this alternate
// listener; only SOCKS5 clients requiring UDP ASSOCIATE should be pointed
// at it.
func (proxy *udpAssociateSocksProxy) handleConnection(conn net.Conn) error {

	// Greeting: VER | NMETHODS | METHODS[NMETHODS]

	header := make([]byte, 2)
	_, err := io.ReadFull(conn, header)
	if err != nil {
		return errors.Trace(err)
	}
	if header[0] != socks5Version {
		return errors.TraceNew("unsupported SOCKS version")
	}
	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	_, err = io.ReadFull(conn, methods)
	if err != nil {
		return errors.Trace(err)
	}

	foundNoAuth := false
	for _, m := range methods {
		if m == socks5AuthNoneRequired {
			foundNoAuth = true
			break
		}
	}
	if !foundNoAuth {
		conn.Write([]byte{socks5Version, socks5AuthNoAcceptableMethods})
		return errors.TraceNew("no acceptable auth method")
	}
	_, err = conn.Write([]byte{socks5Version, socks5AuthNoneRequired})
	if err != nil {
		return errors.Trace(err)
	}

	// Command: VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT

	cmdHeader := make([]byte, 4)
	_, err = io.ReadFull(conn, cmdHeader)
	if err != nil {
		return errors.Trace(err)
	}
	if cmdHeader[0] != socks5Version {
		return errors.TraceNew("unsupported SOCKS version in request")
	}
	cmd := cmdHeader[1]
	atyp := cmdHeader[3]

	targetAddr, err := readSocks5Address(conn, atyp)
	if err != nil {
		proxy.sendReply(conn, socks5RepAddressNotSupported, nil)
		return errors.Trace(err)
	}

	switch cmd {
	case socks5CmdConnect:
		return proxy.handleConnect(conn, targetAddr)
	case socks5CmdUDPAssociate:
		return proxy.handleUDPAssociate(conn)
	default:
		proxy.sendReply(conn, socks5RepCommandNotSupported, nil)
		return errors.TraceNew(fmt.Sprintf("unsupported command 0x%02x", cmd))
	}
}

func readSocks5Address(conn net.Conn, atyp byte) (string, error) {
	switch atyp {
	case socks5AtypV4:
		buf := make([]byte, 4+2)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", errors.Trace(err)
		}
		ip := net.IP(buf[0:4])
		port := binary.BigEndian.Uint16(buf[4:6])
		return net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)), nil
	case socks5AtypV6:
		buf := make([]byte, 16+2)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", errors.Trace(err)
		}
		ip := net.IP(buf[0:16])
		port := binary.BigEndian.Uint16(buf[16:18])
		return net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)), nil
	case socks5AtypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", errors.Trace(err)
		}
		nameBuf := make([]byte, int(lenBuf[0])+2)
		if _, err := io.ReadFull(conn, nameBuf); err != nil {
			return "", errors.Trace(err)
		}
		name := string(nameBuf[0 : len(nameBuf)-2])
		port := binary.BigEndian.Uint16(nameBuf[len(nameBuf)-2:])
		return net.JoinHostPort(name, fmt.Sprintf("%d", port)), nil
	default:
		return "", errors.TraceNew("unsupported address type")
	}
}

func (proxy *udpAssociateSocksProxy) sendReply(conn net.Conn, rep byte, bindAddr *net.UDPAddr) {
	reply := make([]byte, 4)
	reply[0] = socks5Version
	reply[1] = rep
	reply[2] = 0x00

	if bindAddr == nil {
		reply[3] = socks5AtypV4
		reply = append(reply, 0, 0, 0, 0, 0, 0)
	} else if ip4 := bindAddr.IP.To4(); ip4 != nil {
		reply[3] = socks5AtypV4
		reply = append(reply, ip4...)
		portBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(portBuf, uint16(bindAddr.Port))
		reply = append(reply, portBuf...)
	} else {
		reply[3] = socks5AtypV6
		reply = append(reply, bindAddr.IP.To16()...)
		portBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(portBuf, uint16(bindAddr.Port))
		reply = append(reply, portBuf...)
	}

	conn.Write(reply)
}

// handleConnect mirrors SocksProxy.socksConnectionHandler's CONNECT
// handling, so existing TCP behavior is preserved for clients that use
// this alternate listener.
func (proxy *udpAssociateSocksProxy) handleConnect(conn net.Conn, target string) error {

	remoteConn, err := proxy.tunneler.Dial(target, conn)
	if err != nil {
		proxy.sendReply(conn, socks5RepGeneralFailure, nil)
		return errors.Trace(err)
	}
	defer remoteConn.Close()

	proxy.sendReply(conn, socks5RepSucceeded, &net.UDPAddr{IP: net.IPv4zero, Port: 0})

	LocalProxyRelay(proxy.config, _SOCKS_PROXY_TYPE, conn, remoteConn)

	return nil
}

// handleUDPAssociate implements RFC 1928 UDP ASSOCIATE. It opens a local
// UDP relay socket for the requesting client, and bridges datagrams to
// the Psiphon server's udpgw channel over the existing SSH tunnel.
//
// The TCP control connection (conn) is held open for the lifetime of the
// association, per RFC 1928; closing it tears down the UDP relay.
func (proxy *udpAssociateSocksProxy) handleUDPAssociate(conn net.Conn) error {

	relaySocket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		proxy.sendReply(conn, socks5RepGeneralFailure, nil)
		return errors.Trace(err)
	}
	defer relaySocket.Close()

	// Open the udpgw channel. From the client's perspective this is an
	// ordinary tunneled TCP port forward to a magic address; the Psiphon
	// server intercepts connections to this address and speaks the udpgw
	// protocol instead of actually forwarding TCP
	// (see server/tunnelServer.go: isUdpgwChannel).
	udpgwConn, err := proxy.tunneler.Dial(udpgwInterceptAddress, conn)
	if err != nil {
		proxy.sendReply(conn, socks5RepGeneralFailure, nil)
		return errors.Trace(err)
	}
	defer udpgwConn.Close()

	localAddr := relaySocket.LocalAddr().(*net.UDPAddr)
	proxy.sendReply(conn, socks5RepSucceeded, localAddr)

	connID := uint16(atomic.AddUint32(&proxy.nextConnID, 1))

	session := &udpAssociateSession{
		relaySocket: relaySocket,
		udpgwConn:   udpgwConn,
		connID:      connID,
	}

	stopBroadcast := make(chan struct{})
	var workers sync.WaitGroup

	// Uplink: client UDP datagrams -> udpgw
	workers.Add(1)
	go func() {
		defer workers.Done()
		defer close(stopBroadcast)
		session.relayUplink()
	}()

	// Downlink: udpgw -> client UDP datagrams
	workers.Add(1)
	go func() {
		defer workers.Done()
		session.relayDownlink(stopBroadcast)
	}()

	// Detect control connection close (RFC 1928: association ends when
	// the TCP control connection is closed) by blocking on a read; the
	// client sends nothing further on this connection.
	buf := make([]byte, 1)
	conn.Read(buf)

	relaySocket.Close()
	udpgwConn.Close()
	workers.Wait()

	return nil
}

type udpAssociateSession struct {
	relaySocket *net.UDPConn
	udpgwConn   net.Conn
	connID      uint16

	clientAddrMutex sync.Mutex
	clientAddr      *net.UDPAddr
}

// relayUplink reads SOCKS5 UDP request datagrams from the client,
// translates them to udpgw messages, and writes them to the udpgw
// channel.
func (s *udpAssociateSession) relayUplink() {

	buf := make([]byte, 65535)

	for {
		n, clientAddr, err := s.relaySocket.ReadFromUDP(buf)
		if err != nil {
			return
		}

		s.clientAddrMutex.Lock()
		s.clientAddr = clientAddr
		s.clientAddrMutex.Unlock()

		// SOCKS5 UDP request: RSV(2) | FRAG(1) | ATYP(1) | DST.ADDR | DST.PORT | DATA

		if n < 4 {
			continue
		}
		if buf[2] != 0x00 {
			// Fragmentation not supported.
			continue
		}
		atyp := buf[3]

		offset := 4
		var remoteIP net.IP
		var isIPv6 bool

		switch atyp {
		case socks5AtypV4:
			if n < offset+4+2 {
				continue
			}
			remoteIP = net.IP(buf[offset : offset+4])
			offset += 4
		case socks5AtypV6:
			if n < offset+16+2 {
				continue
			}
			remoteIP = net.IP(buf[offset : offset+16])
			offset += 16
			isIPv6 = true
		case socks5AtypDomain:
			// Domain names are not forwarded through udpgw, which
			// expects a resolved IP address. Resolve locally.
			nameLen := int(buf[offset])
			offset++
			if n < offset+nameLen+2 {
				continue
			}
			name := string(buf[offset : offset+nameLen])
			offset += nameLen
			resolved, err := net.ResolveIPAddr("ip", name)
			if err != nil {
				continue
			}
			if v4 := resolved.IP.To4(); v4 != nil {
				remoteIP = v4
			} else {
				remoteIP = resolved.IP.To16()
				isIPv6 = true
			}
		default:
			continue
		}

		if n < offset+2 {
			continue
		}
		remotePort := binary.BigEndian.Uint16(buf[offset : offset+2])
		offset += 2

		payload := buf[offset:n]
		if len(payload) > udpgwMaxPayloadSize {
			continue
		}

		err = writeUdpgwMessageClient(
			s.udpgwConn, s.connID, remoteIP, isIPv6, remotePort, payload)
		if err != nil {
			return
		}
	}
}

// relayDownlink reads udpgw messages from the udpgw channel, translates
// them to SOCKS5 UDP response datagrams, and writes them to the client's
// UDP socket.
func (s *udpAssociateSession) relayDownlink(stopBroadcast chan struct{}) {

	reader := &udpgwReader{conn: s.udpgwConn}

	for {
		msg, err := reader.readMessage()
		if err != nil {
			return
		}

		select {
		case <-stopBroadcast:
			return
		default:
		}

		s.clientAddrMutex.Lock()
		clientAddr := s.clientAddr
		s.clientAddrMutex.Unlock()

		if clientAddr == nil {
			continue
		}

		// Build SOCKS5 UDP response: RSV(2) | FRAG(1) | ATYP(1) | SRC.ADDR | SRC.PORT | DATA

		var header []byte
		if msg.isIPv6 {
			header = make([]byte, 4+16+2)
			header[3] = socks5AtypV6
			copy(header[4:20], msg.remoteIP)
			binary.BigEndian.PutUint16(header[20:22], msg.remotePort)
		} else {
			header = make([]byte, 4+4+2)
			header[3] = socks5AtypV4
			copy(header[4:8], msg.remoteIP)
			binary.BigEndian.PutUint16(header[8:10], msg.remotePort)
		}

		packet := append(header, msg.payload...)

		_, err = s.relaySocket.WriteToUDP(packet, clientAddr)
		if err != nil {
			return
		}
	}
}

// --- udpgw wire protocol (client side) ---
//
// Layout (must match psiphon/server/udp.go):
//   | 2 byte size (LE) | 1 byte flags | 2 byte connID (LE) | 4 or 16 byte IP | 2 byte port (BE) | payload |
// "size" covers everything after the 2-byte size field itself.

func writeUdpgwMessageClient(
	w io.Writer, connID uint16, remoteIP net.IP, isIPv6 bool, remotePort uint16, payload []byte) error {

	var flags byte
	var addrLen int
	if isIPv6 {
		flags |= udpgwFlagIPv6
		addrLen = 16
	} else {
		flags |= 0
		addrLen = 4
	}

	preambleSize := 1 + 2 + addrLen + 2 // flags + connID + addr + port
	size := preambleSize + len(payload)

	buf := make([]byte, 2+preambleSize+len(payload))
	binary.LittleEndian.PutUint16(buf[0:2], uint16(size))
	buf[2] = flags
	binary.LittleEndian.PutUint16(buf[3:5], connID)
	copy(buf[5:5+addrLen], remoteIP)
	binary.BigEndian.PutUint16(buf[5+addrLen:5+addrLen+2], remotePort)
	copy(buf[5+addrLen+2:], payload)

	_, err := w.Write(buf)
	return errors.Trace(err)
}

type udpgwClientMessage struct {
	connID     uint16
	remoteIP   net.IP
	remotePort uint16
	isIPv6     bool
	payload    []byte
}

type udpgwReader struct {
	conn net.Conn
	buf  [2 + udpgwMaxPayloadSize + 23]byte
}

func (r *udpgwReader) readMessage() (*udpgwClientMessage, error) {
	for {
		_, err := io.ReadFull(r.conn, r.buf[0:2])
		if err != nil {
			return nil, errors.Trace(err)
		}
		size := binary.LittleEndian.Uint16(r.buf[0:2])
		if size < 3 || int(size) > len(r.buf)-2 {
			return nil, errors.TraceNew("invalid udpgw message size")
		}
		_, err = io.ReadFull(r.conn, r.buf[2:2+size])
		if err != nil {
			return nil, errors.Trace(err)
		}

		flags := r.buf[2]

		if flags&udpgwFlagKeepalive == udpgwFlagKeepalive {
			continue
		}

		connID := binary.LittleEndian.Uint16(r.buf[3:5])

		var remoteIP net.IP
		var remotePort uint16
		var packetStart, packetEnd int
		isIPv6 := flags&udpgwFlagIPv6 == udpgwFlagIPv6

		if isIPv6 {
			if size < 21 {
				return nil, errors.TraceNew("invalid udpgw message size")
			}
			remoteIP = make(net.IP, 16)
			copy(remoteIP, r.buf[5:21])
			remotePort = binary.BigEndian.Uint16(r.buf[21:23])
			packetStart = 23
			packetEnd = 23 + int(size) - 21
		} else {
			if size < 9 {
				return nil, errors.TraceNew("invalid udpgw message size")
			}
			remoteIP = make(net.IP, 4)
			copy(remoteIP, r.buf[5:9])
			remotePort = binary.BigEndian.Uint16(r.buf[9:11])
			packetStart = 11
			packetEnd = 11 + int(size) - 9
		}

		payload := make([]byte, packetEnd-packetStart)
		copy(payload, r.buf[packetStart:packetEnd])

		return &udpgwClientMessage{
			connID:     connID,
			remoteIP:   remoteIP,
			remotePort: remotePort,
			isIPv6:     isIPv6,
			payload:    payload,
		}, nil
	}
}
'''

open(new_file_path, "w").write(new_file_content)
print("Wrote " + new_file_path)

print("All patches applied successfully")
