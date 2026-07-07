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

package server

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/websocket"
)

// WebSocketServer accepts OSSH connections tunneled inside WebSocket binary
// frames, for the UNFRONTED-WS-OSSH, UNFRONTED-WSS-OSSH, FRONTED-WS-OSSH,
// and FRONTED-WSS-OSSH tunnel protocols.
//
// Unlike MeekServer, there is no long-polling, no cookie-encoded session
// state, and no turn-around timeout logic: the WebSocket upgrade itself
// gives a persistent, full-duplex net.Conn, which is handed directly to
// clientHandler exactly like a direct OSSH TCP accept would be. isFronted
// only affects logging/metrics here (see tunnelServer.go's
// additionalTransportData) -- the fronting CDN's TLS termination happens
// upstream of this listener (WS) or the CDN passes through TLS to us
// (WSS), matching how FRONTED-MEEK-HTTP-OSSH already works in this
// codebase.
type WebSocketServer struct {
	support         *SupportServices
	listener        net.Listener
	tunnelProtocol  string
	port            int
	useTLS          bool
	isFronted       bool
	resourcePath    string
	clientHandler   func(clientConn net.Conn, data *additionalTransportData)
	httpServer      *http.Server
	stopBroadcast   <-chan struct{}
	runWaitGroup    sync.WaitGroup
}

// NewWebSocketServer initializes a new WebSocket OSSH server. listener is
// a plain TCP listener (WS) or a TLS listener wrapping TCP (WSS) --
// callers should construct the TLS listener the same way
// ListenTLSTunnel/makeDirectMeekTLSConfig-style code does elsewhere in
// this package, then pass useTLS true purely for logging purposes since
// the listener itself is already doing the TLS termination.
//
// resourcePath, if non-empty, must match the path clients request in
// their WebSocket upgrade (see WebSocketConfig.ResourcePath client-side);
// requests to any other path get a plain 404, so that probing this port
// with a generic WebSocket client doesn't immediately confirm it's a
// tunnel endpoint.
func NewWebSocketServer(
	support *SupportServices,
	listener net.Listener,
	tunnelProtocol string,
	listenerPort int,
	useTLS bool,
	isFronted bool,
	resourcePath string,
	clientHandler func(clientConn net.Conn, data *additionalTransportData),
	stopBroadcast <-chan struct{},
) (*WebSocketServer, error) {

	server := &WebSocketServer{
		support:        support,
		listener:       listener,
		tunnelProtocol: tunnelProtocol,
		port:           listenerPort,
		useTLS:         useTLS,
		isFronted:      isFronted,
		resourcePath:   resourcePath,
		clientHandler:  clientHandler,
		stopBroadcast:  stopBroadcast,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", server.serveHTTP)

	server.httpServer = &http.Server{
		Handler: mux,
		// No ReadTimeout/WriteTimeout: once upgraded, the connection is a
		// long-lived tunnel. Consider adding ReadHeaderTimeout to bound
		// how long a non-upgrading client can hold the handshake open --
		// see MeekServer's use of MEEK_HTTP_CLIENT_IO_TIMEOUT for
		// precedent on picking a value.
		ReadHeaderTimeout: 30 * time.Second,
		ConnState:         server.connStateCallback,
	}

	return server, nil
}

// Run starts accepting and serving connections. It blocks until the
// listener is closed or stopBroadcast fires, mirroring
// MeekServer.Run/TunnelServer.Run's shutdown pattern.
func (server *WebSocketServer) Run() error {

	server.runWaitGroup.Add(1)
	go func() {
		defer server.runWaitGroup.Done()
		select {
		case <-server.stopBroadcast:
			server.httpServer.Close()
		}
	}()

	err := server.httpServer.Serve(server.listener)

	server.runWaitGroup.Wait()

	if err != nil && err != http.ErrServerClosed {
		return errors.Trace(err)
	}
	return nil
}

// ReloadTactics is a no-op stub kept for interface parity with
// MeekServer.ReloadTactics, in case sshServer.registerMeekServer-style
// registration/tactics-reload plumbing is extended to cover this server
// too. Wire this up for real if WS-OSSH ever needs runtime tactics
// (e.g. dynamic passthrough addresses).
func (server *WebSocketServer) ReloadTactics() error {
	return nil
}

func (server *WebSocketServer) connStateCallback(conn net.Conn, state http.ConnState) {
	// Placeholder hook -- MeekServer uses the equivalent callback
	// (httpConnStateCallback) to track open connections for graceful
	// shutdown / metrics. Wire up the same openConns bookkeeping here if
	// you need parity (see MeekServer.openConns).
}

func (server *WebSocketServer) serveHTTP(w http.ResponseWriter, r *http.Request) {

	defer handleServeHTTPPanic()

	wsConn, err := websocket.Upgrade(w, r, server.resourcePath)
	if err != nil {
		// Return a generic 404 rather than an error page that reveals
		// this is a WebSocket-capable endpoint, unless the hijack itself
		// already failed (in which case we can't write a response at
		// all).
		http.NotFound(w, r)
		return
	}

	data := &additionalTransportData{
		overrideTunnelProtocol: server.tunnelProtocol,
	}

	// Hand the upgraded connection to the same client handler used for
	// direct OSSH/TLS-OSSH accepts. From here on this behaves exactly
	// like any other OSSH transport: obfuscation, SSH handshake, and
	// port-forward relaying all happen above this layer, unmodified.
	server.clientHandler(wsConn, data)
}

// makeWebSocketTLSListener wraps a plain TCP listener in TLS, for the WSS
// variants. This intentionally reuses the same certificate-selection
// logic path as fronted/direct meek so that the WSS listener presents a
// TLS server the same way the existing MEEK-HTTPS listener does; see
// MeekServer.getWebServerCertificate / makeFrontedMeekTLSConfig /
// makeDirectMeekTLSConfig in meek.go for the certificate material this
// should share, and wire this up to call whichever of those matches your
// deployment (fronted WSS behind Cloudflare needs the same certificate
// posture as FRONTED-MEEK-HTTP-OSSH; unfronted WSS needs a
// server-presented cert like UNFRONTED-MEEK-HTTPS-OSSH does).
func makeWebSocketTLSListener(
	listener net.Listener,
	tlsConfig *tls.Config,
) net.Listener {
	return tls.NewListener(listener, tlsConfig)
}

var _ = context.Background // placeholder to keep context imported if you
// extend Run() with a context-based shutdown instead of stopBroadcast.
