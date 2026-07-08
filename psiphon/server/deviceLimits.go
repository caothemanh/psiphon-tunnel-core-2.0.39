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

// DEFAULT_AUTHORIZATION_DEVICE_LIMIT is the number of concurrent sessions
// permitted for a verified authorization ID that has no explicit entry in
// the DeviceLimitsSet file. This preserves the original psiphond behavior
// (one active session per authorization; a second device presenting the
// same authorization causes the first to be revoked) for any authorization
// the operator hasn't explicitly configured.
const DEFAULT_AUTHORIZATION_DEVICE_LIMIT = 1

// DeviceLimitsSet maps a base64-encoded authorization ID (as computed in
// completeHandshake/base64.StdEncoding.EncodeToString(verifiedAuthorization.ID))
// to the maximum number of concurrent client sessions permitted to hold
// that authorization active at once -- i.e. the "number of devices" a
// single issued psiphonAuth token may be used from concurrently.
//
// This is intentionally kept separate from accesscontrol.Authorization
// (ID/AccessType/Expires, which is signed and shipped to the client): the
// device limit is purely a server-side, operator-adjustable policy keyed
// by the authorization's public ID, so it can be changed (or an
// authorization's limit revised) without re-issuing the token.
//
// A limit of 0 means unlimited concurrent devices for that authorization
// ID. An authorization ID with no entry falls back to
// DEFAULT_AUTHORIZATION_DEVICE_LIMIT.
type DeviceLimitsSet struct {
	common.ReloadableFile

	Limits map[string]int
}

// NewDeviceLimitsSet initializes a DeviceLimitsSet with the device limit
// data in the specified config file. An empty filename is valid and
// results in every authorization ID falling back to
// DEFAULT_AUTHORIZATION_DEVICE_LIMIT.
func NewDeviceLimitsSet(filename string) (*DeviceLimitsSet, error) {

	set := &DeviceLimitsSet{
		Limits: make(map[string]int),
	}

	if filename == "" {
		return set, nil
	}

	set.ReloadableFile = common.NewReloadableFile(
		filename,
		true,
		func(fileContent []byte, _ time.Time) error {
			var newLimits map[string]int
			err := json.Unmarshal(fileContent, &newLimits)
			if err != nil {
				return errors.Trace(err)
			}

			// Modify actual limits only after unmarshal succeeds.
			set.Limits = newLimits

			return nil
		})

	_, err := set.Reload()
	if err != nil {
		return nil, errors.Trace(err)
	}

	return set, nil
}

// GetLimit returns the configured device (concurrent session) limit for
// the given base64-encoded authorization ID, or
// DEFAULT_AUTHORIZATION_DEVICE_LIMIT if unset. 0 means unlimited.
func (set *DeviceLimitsSet) GetLimit(authorizationID string) int {
	if set == nil {
		return DEFAULT_AUTHORIZATION_DEVICE_LIMIT
	}

	limit, ok := set.Limits[authorizationID]
	if !ok {
		return DEFAULT_AUTHORIZATION_DEVICE_LIMIT
	}
	return limit
}
