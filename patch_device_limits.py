#!/usr/bin/env python3
"""
Patch psiphon/server/{config,services,tunnelServer}.go to add support for
a configurable number of concurrent devices ("sessions") per authorization
ID (psiphonAuth token), on top of a pristine upstream checkout.

Run from the repo root:
    python3 patch_device_limits.py
"""

import sys

def patch_file(path, replacements):
    with open(path, "r") as f:
        content = f.read()
    changed = False
    for old, new in replacements:
        if new in content:
            # Already patched (e.g. file was committed pre-modified, or
            # this script already ran once) - skip safely.
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
            '\t// TrafficRulesFilename is the path of a file containing a JSON-encoded\n'
            '\t// TrafficRulesSet, the traffic rules to apply to Psiphon client tunnels.\n'
            '\tTrafficRulesFilename string `json:",omitempty"`\n',

            '\t// TrafficRulesFilename is the path of a file containing a JSON-encoded\n'
            '\t// TrafficRulesSet, the traffic rules to apply to Psiphon client tunnels.\n'
            '\tTrafficRulesFilename string `json:",omitempty"`\n'
            '\n'
            '\t// AuthorizationDeviceLimitsFilename is the path of a file containing a\n'
            '\t// JSON-encoded map of base64-encoded authorization ID to the maximum\n'
            '\t// number of concurrent client sessions ("devices") permitted for that\n'
            '\t// authorization. Missing entries fall back to\n'
            '\t// DEFAULT_AUTHORIZATION_DEVICE_LIMIT (1); 0 means unlimited.\n'
            '\tAuthorizationDeviceLimitsFilename string `json:",omitempty"`\n'
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
            '\tTrafficRulesSet              *TrafficRulesSet\n'
            '\tOSLConfig                    *osl.Config\n',

            '\tTrafficRulesSet              *TrafficRulesSet\n'
            '\tDeviceLimitsSet              *DeviceLimitsSet\n'
            '\tOSLConfig                    *osl.Config\n'
        ),
        (
            '\ttrafficRulesSet, err := NewTrafficRulesSet(config.TrafficRulesFilename)\n'
            '\tif err != nil {\n'
            '\t\treturn nil, errors.Trace(err)\n'
            '\t}\n'
            '\n'
            '\toslConfig, err := osl.NewConfig(config.OSLConfigFilename)',

            '\ttrafficRulesSet, err := NewTrafficRulesSet(config.TrafficRulesFilename)\n'
            '\tif err != nil {\n'
            '\t\treturn nil, errors.Trace(err)\n'
            '\t}\n'
            '\n'
            '\tdeviceLimitsSet, err := NewDeviceLimitsSet(config.AuthorizationDeviceLimitsFilename)\n'
            '\tif err != nil {\n'
            '\t\treturn nil, errors.Trace(err)\n'
            '\t}\n'
            '\n'
            '\toslConfig, err := osl.NewConfig(config.OSLConfigFilename)'
        ),
        (
            '\t\tPsinetDatabase:  psinetDatabase,\n'
            '\t\tGeoIPService:    geoIPService,\n'
            '\t\tDNSResolver:     dnsResolver,\n'
            '\t\tTacticsServer:   tacticsServer,\n'
            '\t\tBlocklist:       blocklist,\n'
            '\t}\n',

            '\t\tPsinetDatabase:  psinetDatabase,\n'
            '\t\tGeoIPService:    geoIPService,\n'
            '\t\tDNSResolver:     dnsResolver,\n'
            '\t\tTacticsServer:   tacticsServer,\n'
            '\t\tBlocklist:       blocklist,\n'
            '\t\tDeviceLimitsSet: deviceLimitsSet,\n'
            '\t}\n'
        ),
        (
            '\t\t\tsupport.TacticsServer,\n'
            '\t\t\tsupport.Blocklist},\n'
            '\t\tsupport.GeoIPService.Reloaders()...)',

            '\t\t\tsupport.TacticsServer,\n'
            '\t\t\tsupport.Blocklist,\n'
            '\t\t\tsupport.DeviceLimitsSet},\n'
            '\t\tsupport.GeoIPService.Reloaders()...)'
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
            '\tauthorizationSessionIDsMutex sync.Mutex\n'
            '\tauthorizationSessionIDs      map[string]string\n',

            '\tauthorizationSessionIDsMutex sync.Mutex\n'
            '\tauthorizationSessionIDs      map[string][]string\n'
        ),
        (
            '\t\tauthorizationSessionIDs: make(map[string]string),\n',
            '\t\tauthorizationSessionIDs: make(map[string][]string),\n'
        ),
        (
            '\tsshClient.sshServer.authorizationSessionIDsMutex.Lock()\n'
            '\tfor _, authorizationID := range authorizationIDs {\n'
            '\t\tsessionID, ok := sshClient.sshServer.authorizationSessionIDs[authorizationID]\n'
            '\t\tif ok && sessionID != sshClient.sessionID {\n'
            '\n'
            '\t\t\tlogFields := LogFields{\n'
            '\t\t\t\t"duplicate_authorization_id": authorizationID,\n'
            '\t\t\t}\n'
            '\n'
            '\t\t\t// Log this using client, not peer, GeoIP data. In the case of\n'
            '\t\t\t// in-proxy tunnel protocols, the client GeoIP fields will be None\n'
            '\t\t\t// if a handshake does not complete. However, presense of a\n'
            '\t\t\t// (duplicate) authorization implies that the handshake completed.\n'
            '\n'
            '\t\t\tsshClient.getClientGeoIPData().SetClientLogFields(logFields)\n'
            '\t\t\tduplicateClientGeoIPData := sshClient.sshServer.getGeoIPSessionCache(sessionID)\n'
            '\t\t\tif duplicateClientGeoIPData != sshClient.getClientGeoIPData() {\n'
            '\t\t\t\tduplicateClientGeoIPData.SetClientLogFieldsWithPrefix("duplicate_authorization_", logFields)\n'
            '\t\t\t}\n'
            '\n'
            '\t\t\tlogIrregularTunnel(\n'
            '\t\t\t\tsshClient.sshServer.support,\n'
            '\t\t\t\t"", // tunnel protocol is not relevant to authorizations\n'
            '\t\t\t\t0,\n'
            '\t\t\t\t"", // GeoIP data is added above\n'
            '\t\t\t\terrors.TraceNew("duplicate active authorization"),\n'
            '\t\t\t\tlogFields)\n'
            '\n'
            '\t\t\t// Invoke asynchronously to avoid deadlocks.\n'
            '\t\t\t// TODO: invoke only once for each distinct sessionID?\n'
            '\t\t\tgo sshClient.sshServer.revokeClientAuthorizations(sessionID)\n'
            '\t\t}\n'
            '\t\tsshClient.sshServer.authorizationSessionIDs[authorizationID] = sshClient.sessionID\n'
            '\t}\n'
            '\tsshClient.sshServer.authorizationSessionIDsMutex.Unlock()\n',

            '\tsshClient.sshServer.authorizationSessionIDsMutex.Lock()\n'
            '\tfor _, authorizationID := range authorizationIDs {\n'
            '\n'
            '\t\tsessionIDs := sshClient.sshServer.authorizationSessionIDs[authorizationID]\n'
            '\n'
            '\t\talreadyHeld := false\n'
            '\t\tfor _, sessionID := range sessionIDs {\n'
            '\t\t\tif sessionID == sshClient.sessionID {\n'
            '\t\t\t\talreadyHeld = true\n'
            '\t\t\t\tbreak\n'
            '\t\t\t}\n'
            '\t\t}\n'
            '\n'
            '\t\tif !alreadyHeld {\n'
            '\t\t\tsessionIDs = append(sessionIDs, sshClient.sessionID)\n'
            '\n'
            '\t\t\tlimit := sshClient.sshServer.support.DeviceLimitsSet.GetLimit(authorizationID)\n'
            '\n'
            '\t\t\tif limit > 0 {\n'
            '\t\t\t\tfor len(sessionIDs) > limit {\n'
            '\n'
            '\t\t\t\t\tevictedSessionID := sessionIDs[0]\n'
            '\t\t\t\t\tsessionIDs = sessionIDs[1:]\n'
            '\n'
            '\t\t\t\t\tlogFields := LogFields{\n'
            '\t\t\t\t\t\t"duplicate_authorization_id": authorizationID,\n'
            '\t\t\t\t\t\t"device_limit":               limit,\n'
            '\t\t\t\t\t}\n'
            '\n'
            '\t\t\t\t\tsshClient.getClientGeoIPData().SetClientLogFields(logFields)\n'
            '\t\t\t\t\tevictedClientGeoIPData := sshClient.sshServer.getGeoIPSessionCache(evictedSessionID)\n'
            '\t\t\t\t\tif evictedClientGeoIPData != sshClient.getClientGeoIPData() {\n'
            '\t\t\t\t\t\tevictedClientGeoIPData.SetClientLogFieldsWithPrefix("duplicate_authorization_", logFields)\n'
            '\t\t\t\t\t}\n'
            '\n'
            '\t\t\t\t\tlogIrregularTunnel(\n'
            '\t\t\t\t\t\tsshClient.sshServer.support,\n'
            '\t\t\t\t\t\t"", // tunnel protocol is not relevant to authorizations\n'
            '\t\t\t\t\t\t0,\n'
            '\t\t\t\t\t\t"", // GeoIP data is added above\n'
            '\t\t\t\t\t\terrors.TraceNew("authorization device limit exceeded"),\n'
            '\t\t\t\t\t\tlogFields)\n'
            '\n'
            '\t\t\t\t\t// Invoke asynchronously to avoid deadlocks.\n'
            '\t\t\t\t\tgo sshClient.sshServer.revokeClientAuthorizations(evictedSessionID)\n'
            '\t\t\t\t}\n'
            '\t\t\t}\n'
            '\t\t}\n'
            '\n'
            '\t\tsshClient.sshServer.authorizationSessionIDs[authorizationID] = sessionIDs\n'
            '\t}\n'
            '\tsshClient.sshServer.authorizationSessionIDsMutex.Unlock()\n'
        ),
        (
            '\t\tsshClient.releaseAuthorizations = func() {\n'
            '\t\t\tsshClient.sshServer.authorizationSessionIDsMutex.Lock()\n'
            '\t\t\tfor _, authorizationID := range authorizationIDs {\n'
            '\t\t\t\tsessionID, ok := sshClient.sshServer.authorizationSessionIDs[authorizationID]\n'
            '\t\t\t\tif ok && sessionID == sshClient.sessionID {\n'
            '\t\t\t\t\tdelete(sshClient.sshServer.authorizationSessionIDs, authorizationID)\n'
            '\t\t\t\t}\n'
            '\t\t\t}\n'
            '\t\t\tsshClient.sshServer.authorizationSessionIDsMutex.Unlock()\n'
            '\t\t}\n',

            '\t\tsshClient.releaseAuthorizations = func() {\n'
            '\t\t\tsshClient.sshServer.authorizationSessionIDsMutex.Lock()\n'
            '\t\t\tfor _, authorizationID := range authorizationIDs {\n'
            '\t\t\t\tsessionIDs := sshClient.sshServer.authorizationSessionIDs[authorizationID]\n'
            '\t\t\t\tfor i, sessionID := range sessionIDs {\n'
            '\t\t\t\t\tif sessionID == sshClient.sessionID {\n'
            '\t\t\t\t\t\tsessionIDs = append(sessionIDs[:i], sessionIDs[i+1:]...)\n'
            '\t\t\t\t\t\tbreak\n'
            '\t\t\t\t\t}\n'
            '\t\t\t\t}\n'
            '\t\t\t\tif len(sessionIDs) == 0 {\n'
            '\t\t\t\t\tdelete(sshClient.sshServer.authorizationSessionIDs, authorizationID)\n'
            '\t\t\t\t} else {\n'
            '\t\t\t\t\tsshClient.sshServer.authorizationSessionIDs[authorizationID] = sessionIDs\n'
            '\t\t\t\t}\n'
            '\t\t\t}\n'
            '\t\t\tsshClient.sshServer.authorizationSessionIDsMutex.Unlock()\n'
            '\t\t}\n'
        ),
    ],
)

print("All device-limit patches applied successfully.")
