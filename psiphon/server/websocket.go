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

	psiphon_tls "github.com/Psiphon-Labs/psiphon-tls"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/values"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/websocket"
)

// WebSocketServer accepts OSSH connections tunneled inside WebSocket binary
// frames, for the UNFRONTED-WS-OSSH, UNFRONTED-WSS-OSSH, FRONTED-WS-OSSH,
// and FRONTED-WSS-OSSH tunnel protocols.
//
// Unlike MeekServer, there is no long-polling, no cookie-encoded session
// state, and no turn-around timeout logic: the WebSocket upgrade itself
// gives a persistent, full-duplex net.Conn, which is handed directly to
// clientHandler exactly like a direct OSSH TCP accept would be.
//
// isFronted determines which of the two WSS TLS config paths is used when
// useTLS is set (see NewWebSocketServer); for the non-TLS protocols
// (UNFRONTED-WS-OSSH, FRONTED-WS-OSSH) it otherwise only affects
// logging/metrics (see tunnelServer.go's additionalTransportData) -- the
// fronting CDN's TLS termination with the client happens upstream of this
// listener either way, matching how FRONTED-MEEK-HTTP-OSSH already works
// in this codebase.
type WebSocketServer struct {
	support          *SupportServices
	listener         net.Listener
	tunnelProtocol   string
	port             int
	useTLS           bool
	isFronted        bool
	resourcePath     string
	stdTLSConfig     *tls.Config
	psiphonTLSConfig *psiphon_tls.Config
	clientHandler    func(clientConn net.Conn, data *additionalTransportData)
	httpServer       *http.Server
	stopBroadcast    <-chan struct{}
	runWaitGroup     sync.WaitGroup
}

// NewWebSocketServer initializes a new WebSocket OSSH server. listener is
// always a plain TCP listener; when useTLS is true, NewWebSocketServer
// builds the appropriate TLS config itself and Run wraps listener with it
// at Serve time -- exactly the same lazy-wrap pattern NewMeekServer/
// MeekServer.Run use for isMeekHTTPS, so that callers (tunnelServer.go)
// don't need two different code paths for fronted vs. direct TCP setup.
//
// For isFronted+useTLS (FRONTED-WSS-OSSH), a standard crypto/tls config is
// used, matching makeFrontedMeekTLSConfig: this is the edge-to-origin hop,
// where the CDN has already validated the client, so passthrough and
// obfuscated session tickets are not needed here. Unlike fronted meek,
// "h2" is deliberately NOT offered in NextProtos: this server's WebSocket
// upgrade relies on http.Hijacker, which net/http's HTTP/2 server does not
// support, so negotiating h2 here would break the upgrade.
//
// For !isFronted+useTLS (UNFRONTED-WSS-OSSH), psiphon-tls is used, matching
// makeDirectMeekTLSConfig, so the direct TLS handshake gets the same
// scanning/fingerprinting-resistant version/cipher-suite variance as
// UNFRONTED-MEEK-HTTPS-OSSH. Passthrough and obfuscated session tickets are
// not wired up yet -- see the TODO below.
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

	if useTLS {

		if isFronted {

			tlsConfig, err := server.makeFrontedWebSocketTLSConfig()
			if err != nil {
				return nil, errors.Trace(err)
			}
			server.stdTLSConfig = tlsConfig

		} else {

			// TODO: wire up useObfuscatedSessionTickets and a passthrough
			// address here, same as makeDirectMeekTLSConfig, once
			// TunnelProtocolPassthroughAddresses/tactics plumbing for
			// UNFRONTED-WSS-OSSH is added in tunnelServer.go/config.go.
			tlsConfig, err := server.makeDirectWebSocketTLSConfig()
			if err != nil {
				return nil, errors.Trace(err)
			}
			server.psiphonTLSConfig = tlsConfig
		}
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

	listener := server.listener
	if server.stdTLSConfig != nil {
		listener = tls.NewListener(listener, server.stdTLSConfig)
	} else if server.psiphonTLSConfig != nil {
		listener = psiphon_tls.NewListener(listener, server.psiphonTLSConfig)
	}

	server.runWaitGroup.Add(1)
	go func() {
		defer server.runWaitGroup.Done()
		select {
		case <-server.stopBroadcast:
			server.httpServer.Close()
		}
	}()

	err := server.httpServer.Serve(listener)

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

// getWebServerCertificate returns the origin's TLS certificate/key,
// reusing the same MeekServerCertificate/MeekServerPrivateKey config
// fields the meek listeners use (or generating one on the fly, same as
// MeekServer.getWebServerCertificate) -- this is the origin server's own
// cert, not protocol-specific, so sharing it across meek and WebSocket
// listeners is intentional, not a naming leftover.
func (server *WebSocketServer) getWebServerCertificate() ([]byte, []byte, error) {

	var certificate, privateKey string

	if server.support.Config.MeekServerCertificate != "" {
		certificate = server.support.Config.MeekServerCertificate
		privateKey = server.support.Config.MeekServerPrivateKey

	} else {
		var err error
		certificate, privateKey, _, err = common.GenerateWebServerCertificate(values.GetHostName())
		if err != nil {
			return nil, nil, errors.Trace(err)
		}
	}

	return []byte(certificate), []byte(privateKey), nil
}

// makeFrontedWebSocketTLSConfig creates a TLS config for the edge-to-origin
// hop of a FRONTED-WSS-OSSH listener. Mirrors
// MeekServer.makeFrontedMeekTLSConfig, including the non-ephemeral cipher
// suite preference (the WebSocket framing provides obfuscation, not
// privacy/integrity -- that's the tunneled SSH's job -- so perfect forward
// secrecy isn't a requirement here, and non-ephemeral suites cost the
// server less).
//
// Deliberately does NOT offer "h2" in NextProtos, unlike fronted meek:
// serveHTTP's websocket.Upgrade relies on http.Hijacker, which is not
// available on HTTP/2 connections in net/http's server, so negotiating h2
// here would break every fronted WSS upgrade.
func (server *WebSocketServer) makeFrontedWebSocketTLSConfig() (*tls.Config, error) {

	certificate, privateKey, err := server.getWebServerCertificate()
	if err != nil {
		return nil, errors.Trace(err)
	}

	tlsCertificate, err := tls.X509KeyPair(certificate, privateKey)
	if err != nil {
		return nil, errors.Trace(err)
	}

	minVersionCandidates := []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12}
	minVersion := minVersionCandidates[prng.Intn(len(minVersionCandidates))]

	cipherSuites := []uint16{
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCertificate},
		NextProtos:   []string{"http/1.1"},
		MinVersion:   minVersion,
		CipherSuites: cipherSuites,
	}, nil
}

// makeDirectWebSocketTLSConfig creates a TLS config for a direct
// UNFRONTED-WSS-OSSH listener. Mirrors MeekServer.makeDirectMeekTLSConfig,
// minus the obfuscated session ticket and passthrough options -- see the
// TODO in NewWebSocketServer for wiring those up.
func (server *WebSocketServer) makeDirectWebSocketTLSConfig() (*psiphon_tls.Config, error) {

	certificate, privateKey, err := server.getWebServerCertificate()
	if err != nil {
		return nil, errors.Trace(err)
	}

	tlsCertificate, err := psiphon_tls.X509KeyPair(certificate, privateKey)
	if err != nil {
		return nil, errors.Trace(err)
	}

	minVersionCandidates := []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12}
	minVersion := minVersionCandidates[prng.Intn(len(minVersionCandidates))]

	return &psiphon_tls.Config{
		Certificates: []psiphon_tls.Certificate{tlsCertificate},
		NextProtos:   []string{"http/1.1"},
		MinVersion:   minVersion,
	}, nil
}

var _ = context.Background // placeholder to keep context imported if you
// extend Run() with a context-based shutdown instead of stopBroadcast.
