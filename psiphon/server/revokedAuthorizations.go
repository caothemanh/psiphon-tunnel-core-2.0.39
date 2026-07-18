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
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

// RevokedAuthorizationsSet is a hot-reloadable file containing a JSON
// array of base64-encoded authorization IDs (same encoding as used
// throughout this package: base64.StdEncoding.EncodeToString(auth.ID))
// that the operator has explicitly revoked.
//
// Unlike KickRequestsSet -- which only disconnects whoever currently
// holds an authorization, after which the same (still otherwise valid)
// token may be presented again and re-granted -- an authorization ID
// present in this set is treated as invalid at the point of
// verification: completeHandshake skips it entirely, as if the client
// had never presented it (same code path as a bad signature or expired
// authorization). This is what actually makes token deletion in the
// panel's "psiphonAuth & User" tab meaningful, rather than merely
// cosmetic bookkeeping.
//
// This is intentionally a *separate* mechanism from
// AccessControlVerificationKeyRing: the key ring can only invalidate
// authorizations wholesale, by rotating the signing key, which breaks
// every token issued under it, not a chosen subset. RevokedAuthorizationsSet
// allows revoking individual tokens while leaving all others (including
// ones issued from the same signing key, before or after) valid.
//
// The file is NOT truncated/modified by the reload itself (contrast with
// KickRequestsSet, which is a one-shot queue) -- entries persist across
// reloads until the operator removes them from the file (e.g. if a
// revoked note was added by mistake). The panel is responsible for
// maintaining this file's contents, matching its own tokens.log/
// authorizations.json bookkeeping.
type RevokedAuthorizationsSet struct {
	common.ReloadableFile

	Revoked map[string]bool
}

// NewRevokedAuthorizationsSet initializes a RevokedAuthorizationsSet from
// the specified file. An empty filename is valid and results in no
// authorization ever being treated as revoked.
func NewRevokedAuthorizationsSet(filename string) (*RevokedAuthorizationsSet, error) {

	set := &RevokedAuthorizationsSet{
		Revoked: make(map[string]bool),
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

			newRevoked := make(map[string]bool, len(authorizationIDs))
			for _, id := range authorizationIDs {
				newRevoked[id] = true
			}

			// Modify actual map only after unmarshal succeeds, same
			// pattern as DeviceLimitsSet.
			set.Revoked = newRevoked

			return nil
		})

	_, err := set.Reload()
	if err != nil {
		return nil, errors.Trace(err)
	}

	return set, nil
}

// IsRevoked returns true if the given base64-encoded authorization ID
// has been revoked by the operator. Safe to call on a nil set (e.g. if
// RevokedAuthorizationsFilename was never configured), always returning
// false in that case.
func (set *RevokedAuthorizationsSet) IsRevoked(authorizationID string) bool {
	if set == nil {
		return false
	}
	return set.Revoked[authorizationID]
}
