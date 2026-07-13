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

package psiphon

import (
	"context"
	"net"

	tls "github.com/Psiphon-Labs/psiphon-tls"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/websocket"
)

// WebSocketConfig specifies the behavior of a WebSocketTunnelConn.
//
// It intentionally mirrors TLSTunnelConfig / MeekConfig field names and
// meaning where equivalent, so that dialParameters.go plumbing (fronting
// provider ID selection, replay of dial parameters, TLS profile
// randomization, etc.) can be wired up the same way it already is for
// TLS-OSSH and MEEK.
type WebSocketConfig struct {

	// Parameters is the active set of parameters.Parameters to use for the
	// dial, same as TLSTunnelConfig.TLSConfig.Parameters.
	Parameters *parameters.Parameters

	// DialAddress is the actual network address ("host:port") that is
	// dialed. For UNFRONTED-WS(S)-OSSH this is the real psiphond address.
	// For FRONTED-WS(S)-OSSH this is the CDN edge address (e.g. the
	// Cloudflare anycast/edge IP or the CDN's own hostname:443).
	DialAddress string

	// HostHeader is the HTTP Host header sent in the WebSocket opening
	// handshake. For UNFRONTED-WS(S)-OSSH this is the same as the host
	// part of DialAddress. For FRONTED-WS(S)-OSSH this is the true
	// psiphond origin's Host, which the CDN uses to route the request
	// after terminating the connection at the edge -- this is the same
	// role dialParams.MeekHostHeader / dialParams.FrontingProviderID play
	// for FRONTED-MEEK-HTTP-OSSH today.
	HostHeader string

	// SNIServerName is the TLS ServerName to send in the ClientHello for
	// the WSS variants. For fronted WSS, set this to the CDN's expected
	// fronting SNI (which may be a disjoint, innocuous-looking domain),
	// exactly as meekConn.go does for FRONTED-MEEK-HTTPS.
	SNIServerName string

	// ResourcePath is the HTTP request path used in the WebSocket
	// upgrade request. Use a fixed, non-obvious, shared-secret-derived
	// path (e.g. derived the same way MeekObfuscatedKey derives cookie
	// encryption keys) rather than "/", so that a passive prober sees a
	// 404 instead of a bare "yes, this is a WS tunnel server" response
	// on unrecognized paths.
	ResourcePath string

	// UseTLS selects WSS (true) vs WS (false).
	UseTLS bool

	// UserAgent is the HTTP User-Agent header value to send in the
	// WebSocket opening handshake. As with MeekConfig, this should be
	// left set (dialParams.UserAgent) rather than omitted: some CDN
	// edges' WAFs treat a missing User-Agent on an otherwise-valid
	// Upgrade request as anomalous and block it, independent of any
	// region-based rule.
	UserAgent string

	// SkipVerify: same meaning as TLSTunnelConfig.TLSConfig.SkipVerify.
	// Only used when UseTLS is true.
	//
	// FIX: this transport deliberately does NOT use tlsdialer/uTLS
	// browser-impersonation profiles (TLSProfile, RandomizedTLSProfileSeed,
	// FragmentClientHello, etc., as TLS-OSSH and MEEK use). Those profiles
	// bake in a specific real browser's ClientHello fingerprint (Chrome,
	// Firefox, Safari...), but this transport also needs to force ALPN
	// down to ["http/1.1"] only (see below), since it speaks a hand-rolled
	// HTTP/1.1 request directly on the TLS connection rather than going
	// through net/http. Combining "impersonate Chrome" with "but only
	// offer http/1.1 in ALPN" produces a ClientHello no real Chrome ever
	// sends (real browsers always include "h2" too) -- a self-inconsistent,
	// "broken disguise" fingerprint that is a stronger bot/automation
	// signal to CDN TLS fingerprinting (JA3/JA4) than an honest,
	// non-impersonating TLS client, and was observed to cause slow/
	// challenge/retry connection behavior specifically on this transport
	// (not on TLS-OSSH/MEEK, which don't force ALPN, and not on plain WS,
	// which has no TLS layer at all). Xray-core's VLESS+WS+TLS avoids this
	// same trap by not setting an uTLS "fingerprint" at all for this kind
	// of transport -- it dials with a plain/standard TLS stack and simply
	// strips "h2" from ALPN, which is self-consistent. This dial follows
	// that same approach: plain psiphon-tls (no uTLS), ALPN fixed to
	// ["http/1.1"] from the start.
	SkipVerify bool
}

// WebSocketTunnelConn is a network connection that tunnels net.Conn flows
// (i.e., OSSH) over a WebSocket connection, which may itself be running
// over plain TCP (WS) or TLS (WSS), and may have been dialed either
// directly to a psiphond server or, for the FRONTED variants, to a CDN
// edge that fronts for the real server.
type WebSocketTunnelConn struct {
	*websocket.Conn
}

// DialWebSocketTunnel dials the underlying transport (TCP, or TLS for the
// WSS variants) and performs the WebSocket opening handshake, returning a
// net.Conn ready to carry OSSH traffic.
//
// This is the WS/WSS-OSSH analog of DialTLSTunnel (tlsTunnelConn.go) and
// DialMeek (meekConn.go): a single dial-and-upgrade, no long-polling, no
// session/cookie state -- the WebSocket upgrade itself gives us a
// persistent full-duplex stream, so none of MeekConn's relay machinery is
// needed here.
func DialWebSocketTunnel(
	ctx context.Context,
	config *WebSocketConfig,
	dialConfig *DialConfig,
) (*WebSocketTunnelConn, error) {

	var conn net.Conn
	var err error

	if config.UseTLS {

		// Dial the raw TCP connection ourselves (instead of handing a
		// DialAddr to tlsdialer) since we're no longer using tlsdialer's
		// uTLS-based ClientHello construction for this transport -- see
		// the FIX comment on WebSocketConfig.SkipVerify above for why.
		tcpDialer := NewTCPDialer(dialConfig)
		rawConn, dialErr := tcpDialer(ctx, "tcp", config.DialAddress)
		if dialErr != nil {
			return nil, errors.Trace(dialErr)
		}

		tlsConfig := &tls.Config{
			ServerName:         config.SNIServerName,
			InsecureSkipVerify: config.SkipVerify,
			// Fixed from ["http/1.1"] only, from the start of the
			// handshake -- not patched onto a browser-impersonation
			// fingerprint after the fact. See the FIX comment above.
			NextProtos: []string{"http/1.1"},
		}

		tlsConn := tls.Client(rawConn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, errors.Trace(err)
		}
		conn = tlsConn

	} else {

		tcpDialer := NewTCPDialer(dialConfig)
		conn, err = tcpDialer(ctx, "tcp", config.DialAddress)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	resourcePath := config.ResourcePath
	if resourcePath == "" {
		resourcePath = "/"
	}

	wsConn, err := websocket.ClientHandshake(conn, config.HostHeader, resourcePath, config.UserAgent)
	if err != nil {
		conn.Close()
		return nil, errors.Trace(err)
	}

	return &WebSocketTunnelConn{Conn: wsConn}, nil
}
