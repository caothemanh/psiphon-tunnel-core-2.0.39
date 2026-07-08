#!/usr/bin/env python3
"""
Patch psiphon/server/{config,services,tunnelServer}.go to add:

1. A configurable number of concurrent devices ("sessions") per
   authorization ID (psiphonAuth token). When a token's device limit is
   reached, the server does NOT disconnect/evict any existing device --
   it simply does not grant the authorization's benefits to any
   additional session beyond the limit. Existing devices are untouched.

2. Visibility logging: every time a device is newly granted an
   authorization's slot, an Info-level log line
   ("authorization device slot granted") is written with the
   authorization ID and the client's GeoIP (country/city/ISP/ASN), so an
   operator can grep the psiphond log for a specific authorization ID
   and see the location history of whoever has used that token.

3. A manual "kick" mechanism: a hot-reloadable file
   (KickRequestsFilename) containing a JSON array of authorization IDs.
   Sending SIGUSR1 to psiphond (the existing reload signal) processes
   this file, forcibly disconnecting whichever device(s) currently hold
   each listed authorization ID, then clears the file. Useful when a
   legitimate token owner reports their token may have leaked: kicking
   frees the slot immediately without waiting for the leaker to
   disconnect on their own, and without permanently blacklisting the
   token.

Run from the repo root (all patches are idempotent -- safe to re-run):
    python3 patch_device_limits.py
"""

import sys

def patch_file(path, replacements):
    with open(path, "r") as f:
        content = f.read()
    changed = False
    for old, new in replacements:
        if new in content:
            print(f"SKIP (already applied) in {path}: {repr(old[:60])}")
            continue
        if old not in content:
            print(f"ERROR: pattern not found in {path}:")
            print(repr(old[:200]))
            sys.exit(1)
        content = content.replace(old, new)
        changed = True
    if changed:
        with open(path, "w") as f:
            f.write(content)
        print(f"Patched {path}")
    else:
        print(f"Nothing to do for {path} (already fully patched)")


# ---------------------------------------------------------------------
# config.go
# ---------------------------------------------------------------------
patch_file(
    "psiphon/server/config.go",
    [
        (
            '''\t// TrafficRulesFilename is the path of a file containing a JSON-encoded
\t// TrafficRulesSet, the traffic rules to apply to Psiphon client tunnels.
\tTrafficRulesFilename string `json:",omitempty"`
''',
            '''\t// TrafficRulesFilename is the path of a file containing a JSON-encoded
\t// TrafficRulesSet, the traffic rules to apply to Psiphon client tunnels.
\tTrafficRulesFilename string `json:",omitempty"`

\t// AuthorizationDeviceLimitsFilename is the path of a file containing a
\t// JSON-encoded map of base64-encoded authorization ID to the maximum
\t// number of concurrent client sessions ("devices") permitted for that
\t// authorization. Missing entries fall back to
\t// DEFAULT_AUTHORIZATION_DEVICE_LIMIT (1); 0 means unlimited.
\tAuthorizationDeviceLimitsFilename string `json:",omitempty"`

\t// KickRequestsFilename is the path of a file containing a JSON array
\t// of base64-encoded authorization IDs to forcibly disconnect from
\t// whichever device(s) currently hold them. Processed on reload
\t// (SIGUSR1) and then truncated back to an empty array.
\tKickRequestsFilename string `json:",omitempty"`
''',
        ),
    ],
)

# ---------------------------------------------------------------------
# services.go
# ---------------------------------------------------------------------
patch_file(
    "psiphon/server/services.go",
    [
        (
            "\tTrafficRulesSet              *TrafficRulesSet\n\tOSLConfig                    *osl.Config\n",
            "\tTrafficRulesSet              *TrafficRulesSet\n\tDeviceLimitsSet              *DeviceLimitsSet\n\tKickRequestsSet              *KickRequestsSet\n\tOSLConfig                    *osl.Config\n",
        ),
        (
            "\ttrafficRulesSet, err := NewTrafficRulesSet(config.TrafficRulesFilename)\n\tif err != nil {\n\t\treturn nil, errors.Trace(err)\n\t}\n\n\toslConfig, err := osl.NewConfig(config.OSLConfigFilename)",
            "\ttrafficRulesSet, err := NewTrafficRulesSet(config.TrafficRulesFilename)\n\tif err != nil {\n\t\treturn nil, errors.Trace(err)\n\t}\n\n\tdeviceLimitsSet, err := NewDeviceLimitsSet(config.AuthorizationDeviceLimitsFilename)\n\tif err != nil {\n\t\treturn nil, errors.Trace(err)\n\t}\n\n\toslConfig, err := osl.NewConfig(config.OSLConfigFilename)",
        ),
        (
            "\t\tPsinetDatabase:  psinetDatabase,\n\t\tGeoIPService:    geoIPService,\n\t\tDNSResolver:     dnsResolver,\n\t\tTacticsServer:   tacticsServer,\n\t\tBlocklist:       blocklist,\n\t}\n",
            "\t\tPsinetDatabase:  psinetDatabase,\n\t\tGeoIPService:    geoIPService,\n\t\tDNSResolver:     dnsResolver,\n\t\tTacticsServer:   tacticsServer,\n\t\tBlocklist:       blocklist,\n\t\tDeviceLimitsSet: deviceLimitsSet,\n\t}\n",
        ),
        (
            "\tsupport.ReplayCache = NewReplayCache(support)\n\n\tsupport.ServerTacticsParametersCache =\n\t\tNewServerTacticsParametersCache(support)\n",
            "\tsupport.ReplayCache = NewReplayCache(support)\n\n\tkickRequestsSet, err := NewKickRequestsSet(config.KickRequestsFilename, support)\n\tif err != nil {\n\t\treturn nil, errors.Trace(err)\n\t}\n\tsupport.KickRequestsSet = kickRequestsSet\n\n\tsupport.ServerTacticsParametersCache =\n\t\tNewServerTacticsParametersCache(support)\n",
        ),
        (
            "\t\t\tsupport.TacticsServer,\n\t\t\tsupport.Blocklist},\n\t\tsupport.GeoIPService.Reloaders()...)",
            "\t\t\tsupport.TacticsServer,\n\t\t\tsupport.Blocklist,\n\t\t\tsupport.DeviceLimitsSet,\n\t\t\tsupport.KickRequestsSet},\n\t\tsupport.GeoIPService.Reloaders()...)",
        ),
    ],
)

# ---------------------------------------------------------------------
# tunnelServer.go
# ---------------------------------------------------------------------
patch_file(
    "psiphon/server/tunnelServer.go",
    [
        (
            "\tauthorizationSessionIDsMutex sync.Mutex\n\tauthorizationSessionIDs      map[string]string\n",
            "\tauthorizationSessionIDsMutex sync.Mutex\n\tauthorizationSessionIDs      map[string][]string\n",
        ),
        (
            "\t\tauthorizationSessionIDs: make(map[string]string),\n",
            "\t\tauthorizationSessionIDs: make(map[string][]string),\n",
        ),
        (
            '\tsshClient.sshServer.authorizationSessionIDsMutex.Lock()\n\tfor _, authorizationID := range authorizationIDs {\n\t\tsessionID, ok := sshClient.sshServer.authorizationSessionIDs[authorizationID]\n\t\tif ok && sessionID != sshClient.sessionID {\n\n\t\t\tlogFields := LogFields{\n\t\t\t\t"duplicate_authorization_id": authorizationID,\n\t\t\t}\n\n\t\t\t// Log this using client, not peer, GeoIP data. In the case of\n\t\t\t// in-proxy tunnel protocols, the client GeoIP fields will be None\n\t\t\t// if a handshake does not complete. However, presense of a\n\t\t\t// (duplicate) authorization implies that the handshake completed.\n\n\t\t\tsshClient.getClientGeoIPData().SetClientLogFields(logFields)\n\t\t\tduplicateClientGeoIPData := sshClient.sshServer.getGeoIPSessionCache(sessionID)\n\t\t\tif duplicateClientGeoIPData != sshClient.getClientGeoIPData() {\n\t\t\t\tduplicateClientGeoIPData.SetClientLogFieldsWithPrefix("duplicate_authorization_", logFields)\n\t\t\t}\n\n\t\t\tlogIrregularTunnel(\n\t\t\t\tsshClient.sshServer.support,\n\t\t\t\t"", // tunnel protocol is not relevant to authorizations\n\t\t\t\t0,\n\t\t\t\t"", // GeoIP data is added above\n\t\t\t\terrors.TraceNew("duplicate active authorization"),\n\t\t\t\tlogFields)\n\n\t\t\t// Invoke asynchronously to avoid deadlocks.\n\t\t\t// TODO: invoke only once for each distinct sessionID?\n\t\t\tgo sshClient.sshServer.revokeClientAuthorizations(sessionID)\n\t\t}\n\t\tsshClient.sshServer.authorizationSessionIDs[authorizationID] = sshClient.sessionID\n\t}\n\tsshClient.sshServer.authorizationSessionIDsMutex.Unlock()\n\n\tif len(authorizationIDs) > 0 {\n\n\t\tsshClient.Lock()\n\n\t\t// Make the authorizedAccessTypes available for traffic rules filtering.\n\n\t\tsshClient.handshakeState.activeAuthorizationIDs = authorizationIDs\n\t\tsshClient.handshakeState.authorizedAccessTypes = authorizedAccessTypes\n\n\t\t// On exit, sshClient.runTunnel will call releaseAuthorizations, which\n\t\t// will release the authorization IDs so the client can reconnect and\n\t\t// present the same authorizations again. sshClient.runTunnel will\n\t\t// also cancel the stopTimer in case it has not yet fired.\n\t\t// Note: termination of the stopTimer goroutine is not synchronized.\n\n\t\tsshClient.releaseAuthorizations = func() {\n\t\t\tsshClient.sshServer.authorizationSessionIDsMutex.Lock()\n\t\t\tfor _, authorizationID := range authorizationIDs {\n\t\t\t\tsessionID, ok := sshClient.sshServer.authorizationSessionIDs[authorizationID]\n\t\t\t\tif ok && sessionID == sshClient.sessionID {\n\t\t\t\t\tdelete(sshClient.sshServer.authorizationSessionIDs, authorizationID)\n\t\t\t\t}\n\t\t\t}\n\t\t\tsshClient.sshServer.authorizationSessionIDsMutex.Unlock()\n\t\t}\n',
            '\tsshClient.sshServer.authorizationSessionIDsMutex.Lock()\n\tgrantedAuthorizationIDs := make([]string, 0, len(authorizationIDs))\n\tgrantedAccessTypes := make([]string, 0, len(authorizedAccessTypes))\n\tfor i, authorizationID := range authorizationIDs {\n\n\t\tsessionIDs := sshClient.sshServer.authorizationSessionIDs[authorizationID]\n\n\t\talreadyHeld := false\n\t\tfor _, sessionID := range sessionIDs {\n\t\t\tif sessionID == sshClient.sessionID {\n\t\t\t\talreadyHeld = true\n\t\t\t\tbreak\n\t\t\t}\n\t\t}\n\n\t\tlimit := sshClient.sshServer.support.DeviceLimitsSet.GetLimit(authorizationID)\n\n\t\tif !alreadyHeld && limit > 0 && len(sessionIDs) >= limit {\n\n\t\t\t// Device limit reached for this authorization: do NOT grant its\n\t\t\t// benefits to this session, and do NOT evict/disconnect any\n\t\t\t// existing device using it. The existing devices keep their\n\t\t\t// authorization untouched; this session simply falls back to\n\t\t\t// default (unauthorized) traffic rules for this authorization.\n\n\t\t\tlogFields := LogFields{\n\t\t\t\t"duplicate_authorization_id": authorizationID,\n\t\t\t\t"device_limit":               limit,\n\t\t\t}\n\n\t\t\tsshClient.getClientGeoIPData().SetClientLogFields(logFields)\n\n\t\t\tlogIrregularTunnel(\n\t\t\t\tsshClient.sshServer.support,\n\t\t\t\t"", // tunnel protocol is not relevant to authorizations\n\t\t\t\t0,\n\t\t\t\t"", // GeoIP data is added above\n\t\t\t\terrors.TraceNew("authorization device limit reached, not granted"),\n\t\t\t\tlogFields)\n\n\t\t\tcontinue\n\t\t}\n\n\t\tif !alreadyHeld {\n\t\t\tsessionIDs = append(sessionIDs, sshClient.sessionID)\n\t\t\tsshClient.sshServer.authorizationSessionIDs[authorizationID] = sessionIDs\n\n\t\t\t// Log GeoIP data for every NEW device that takes an\n\t\t\t// authorization\'s device slot. This lets the operator grep the\n\t\t\t// psiphond log for a specific authorization ID and see the\n\t\t\t// country/city/ISP/ASN of whoever has been using it over time\n\t\t\t// -- e.g. to notice a token being used from an unexpected\n\t\t\t// location, suggesting the token has leaked.\n\t\t\tlogFields := LogFields{\n\t\t\t\t"authorization_id_granted": authorizationID,\n\t\t\t\t"device_limit":             limit,\n\t\t\t\t"devices_active":           len(sessionIDs),\n\t\t\t}\n\t\t\tsshClient.getClientGeoIPData().SetClientLogFields(logFields)\n\t\t\tlog.WithTraceFields(logFields).Info("authorization device slot granted")\n\t\t}\n\n\t\tgrantedAuthorizationIDs = append(grantedAuthorizationIDs, authorizationID)\n\t\tgrantedAccessTypes = append(grantedAccessTypes, authorizedAccessTypes[i])\n\t}\n\tsshClient.sshServer.authorizationSessionIDsMutex.Unlock()\n\n\tauthorizationIDs = grantedAuthorizationIDs\n\tauthorizedAccessTypes = grantedAccessTypes\n\n\tif len(authorizationIDs) > 0 {\n\n\t\tsshClient.Lock()\n\n\t\t// Make the authorizedAccessTypes available for traffic rules filtering.\n\n\t\tsshClient.handshakeState.activeAuthorizationIDs = authorizationIDs\n\t\tsshClient.handshakeState.authorizedAccessTypes = authorizedAccessTypes\n\n\t\t// On exit, sshClient.runTunnel will call releaseAuthorizations, which\n\t\t// will release the authorization IDs so the client can reconnect and\n\t\t// present the same authorizations again. sshClient.runTunnel will\n\t\t// also cancel the stopTimer in case it has not yet fired.\n\t\t// Note: termination of the stopTimer goroutine is not synchronized.\n\n\t\tsshClient.releaseAuthorizations = func() {\n\t\t\tsshClient.sshServer.authorizationSessionIDsMutex.Lock()\n\t\t\tfor _, authorizationID := range authorizationIDs {\n\t\t\t\tsessionIDs := sshClient.sshServer.authorizationSessionIDs[authorizationID]\n\t\t\t\tfor i, sessionID := range sessionIDs {\n\t\t\t\t\tif sessionID == sshClient.sessionID {\n\t\t\t\t\t\tsessionIDs = append(sessionIDs[:i], sessionIDs[i+1:]...)\n\t\t\t\t\t\tbreak\n\t\t\t\t\t}\n\t\t\t\t}\n\t\t\t\tif len(sessionIDs) == 0 {\n\t\t\t\t\tdelete(sshClient.sshServer.authorizationSessionIDs, authorizationID)\n\t\t\t\t} else {\n\t\t\t\t\tsshClient.sshServer.authorizationSessionIDs[authorizationID] = sessionIDs\n\t\t\t\t}\n\t\t\t}\n\t\t\tsshClient.sshServer.authorizationSessionIDsMutex.Unlock()\n\t\t}\n\n',
        ),
        (
            '\tclient.setTrafficRules()\n}\n\nfunc (sshServer *sshServer) stopClients() {\n',
            "\tclient.setTrafficRules()\n}\n\n// kickAuthorizationID forcibly disconnects every client session currently\n// holding the given authorization ID. It returns the number of sessions\n// disconnected. This does not blacklist the authorization; the token\n// remains valid and its slot(s) become immediately available again to\n// whichever device next presents it (subject to the normal device limit).\nfunc (sshServer *sshServer) kickAuthorizationID(authorizationID string) int {\n\n\tsshServer.authorizationSessionIDsMutex.Lock()\n\tsessionIDs := append([]string(nil), sshServer.authorizationSessionIDs[authorizationID]...)\n\tsshServer.authorizationSessionIDsMutex.Unlock()\n\n\tkicked := 0\n\tfor _, sessionID := range sessionIDs {\n\n\t\tsshServer.clientsMutex.Lock()\n\t\tclient := sshServer.clients[sessionID]\n\t\tsshServer.clientsMutex.Unlock()\n\n\t\tif client != nil {\n\t\t\t// client.stop() closes the underlying connection, which causes\n\t\t\t// the client's normal disconnect path (including its\n\t\t\t// releaseAuthorizations closure) to run and clean up\n\t\t\t// sshServer.authorizationSessionIDs for this session on its\n\t\t\t// own -- no need to remove it here.\n\t\t\tclient.stop()\n\t\t\tkicked++\n\t\t}\n\t}\n\n\treturn kicked\n}\n\nfunc (sshServer *sshServer) stopClients() {\n",
        ),
    ],
)

print("All patches (device limits + kick) applied successfully.")
