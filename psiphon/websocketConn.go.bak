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

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tlsdialer"
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

	// TLSProfile, VerifyServerName, VerifyPins, SkipVerify,
	// NoDefaultTLSSessionID, RandomizedTLSProfileSeed,
	// FragmentClientHello, ClientSessionCache: same meaning as the
	// identically named tlsdialer.Config / TLSTunnelConfig fields. Only
	// used when UseTLS is true.
	TLSProfile               string
	VerifyServerName         string
	SkipVerify               bool
	NoDefaultTLSSessionID    bool
	RandomizedTLSProfileSeed *prng.Seed
	FragmentClientHello      bool
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

		tlsConfig := &tlsdialer.Config{
			Parameters:                    config.Parameters,
			Dial:                          NewTCPDialer(dialConfig),
			DialAddr:                      config.DialAddress,
			SNIServerName:                 config.SNIServerName,
			VerifyServerName:              config.VerifyServerName,
			SkipVerify:                    config.SkipVerify,
			TLSProfile:                    config.TLSProfile,
			NoDefaultTLSSessionID:         &config.NoDefaultTLSSessionID,
			RandomizedTLSProfileSeed:      config.RandomizedTLSProfileSeed,
			FragmentClientHello:           config.FragmentClientHello,
			TrustedCACertificatesFilename: dialConfig.TrustedCACertificatesFilename,
		}

		tlsDialer := tlsdialer.NewDialer(tlsConfig)

		// DialAddr is set in tlsConfig, so no address is required here.
		conn, err = tlsDialer(ctx, "tcp", "")
		if err != nil {
			return nil, errors.Trace(err)
		}

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

	wsConn, err := websocket.ClientHandshake(conn, config.HostHeader, resourcePath)
	if err != nil {
		conn.Close()
		return nil, errors.Trace(err)
	}

	return &WebSocketTunnelConn{Conn: wsConn}, nil
}
