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
	"encoding/json"
	"os"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

// KickRequestsSet is a hot-reloadable file containing a JSON array of
// base64-encoded authorization IDs that the operator wants to
// immediately disconnect from whichever device(s) currently hold them --
// e.g. in response to a legitimate token owner reporting their token may
// have leaked.
//
// On each reload (typically triggered by sending SIGUSR1 to psiphond,
// the same signal used to reload TrafficRulesSet/DeviceLimitsSet), any
// authorization IDs listed are disconnected via sshServer.kickAuthorizationID
// and the file is truncated back to an empty array, so the same entries
// are not repeatedly reprocessed on a later, unrelated reload.
//
// This does not blocklist the authorization -- it only disconnects
// whoever currently holds it. The token remains otherwise valid: after
// being kicked, the slot is free and the next device (legitimate owner
// or otherwise) to present the token will be granted it again, subject
// to the normal device limit.
type KickRequestsSet struct {
	common.ReloadableFile

	filename string
	support  *SupportServices
}

// NewKickRequestsSet initializes a KickRequestsSet. support may have a nil
// TunnelServer at this point (it's assigned later during startup); this is
// safe because the reload callback only dereferences it at reload time,
// once the operator actually triggers a kick, by which point the server
// startup sequence has completed.
func NewKickRequestsSet(filename string, support *SupportServices) (*KickRequestsSet, error) {

	set := &KickRequestsSet{
		filename: filename,
		support:  support,
	}

	if filename == "" {
		return set, nil
	}

	set.ReloadableFile = common.NewReloadableFile(
		filename,
		true,
		func(fileContent []byte, _ time.Time) error {

			var authorizationIDs []string
			err := json.Unmarshal(fileContent, &authorizationIDs)
			if err != nil {
				return errors.Trace(err)
			}

			if len(authorizationIDs) == 0 {
				return nil
			}

			if set.support.TunnelServer == nil || set.support.TunnelServer.sshServer == nil {
				// Server not fully started yet; nothing to kick. Leave the
				// file as-is so it's retried on the next reload.
				return nil
			}

			for _, authorizationID := range authorizationIDs {
				set.support.TunnelServer.sshServer.kickAuthorizationID(authorizationID)
			}

			// Truncate so a later, unrelated reload doesn't re-kick these
			// same entries (e.g. re-kicking a legitimate reconnect).
			writeErr := os.WriteFile(filename, []byte("[]"), 0600)
			if writeErr != nil {
				return errors.Trace(writeErr)
			}

			return nil
		})

	_, err := set.Reload()
	if err != nil {
		return nil, errors.Trace(err)
	}

	return set, nil
}
