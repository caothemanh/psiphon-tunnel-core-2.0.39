// psiphon-authgen: build và đặt vào $INSTALL_DIR/psiphon-authgen trên VPS.
//
// Build trong module psiphon-tunnel-core (cùng chỗ bạn build psiphond custom)
// để import đúng package accesscontrol:
//
//   go build -o psiphon-authgen ./cmd/psiphon-authgen
//
// Cách dùng (khớp với psiphon-panel.sh):
//   psiphon-authgen gen-keys <access-type> <signing-out.json> <verify-out.json>
//   psiphon-authgen issue <signing-key.json> <note/seed> <days>
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/accesscontrol"
)

func fail(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func genKeys(args []string) {
	if len(args) != 3 {
		fail("usage: gen-keys <access-type> <signing-out.json> <verify-out.json>")
	}
	accessType, signingOut, verifyOut := args[0], args[1], args[2]

	signingKey, verificationKey, err := accesscontrol.NewKeyPair(accessType)
	if err != nil {
		fail("NewKeyPair failed: %s", err)
	}

	signingJSON, err := json.MarshalIndent(signingKey, "", "  ")
	if err != nil {
		fail("marshal signing key failed: %s", err)
	}
	verifyJSON, err := json.MarshalIndent(verificationKey, "", "  ")
	if err != nil {
		fail("marshal verification key failed: %s", err)
	}

	if err := os.WriteFile(signingOut, signingJSON, 0600); err != nil {
		fail("write signing key failed: %s", err)
	}
	if err := os.WriteFile(verifyOut, verifyJSON, 0644); err != nil {
		fail("write verification key failed: %s", err)
	}
}

func issue(args []string) {
	if len(args) != 3 {
		fail("usage: issue <signing-key.json> <note/seed> <days>")
	}
	signingKeyPath, note, daysStr := args[0], args[1], args[2]

	keyBytes, err := os.ReadFile(signingKeyPath)
	if err != nil {
		fail("read signing key failed: %s", err)
	}
	var signingKey accesscontrol.SigningKey
	if err := json.Unmarshal(keyBytes, &signingKey); err != nil {
		fail("parse signing key failed: %s", err)
	}

	days, err := strconv.Atoi(daysStr)
	if err != nil {
		fail("invalid days: %s", err)
	}
	expires := time.Now().Add(time.Duration(days) * 24 * time.Hour)

	token, authID, err := accesscontrol.IssueAuthorization(&signingKey, []byte(note), expires)
	if err != nil {
		fail("IssueAuthorization failed: %s", err)
	}

	// Print token + the base64 authorization ID (same encoding psiphond
	// uses internally, base64.StdEncoding.EncodeToString(ID)) as JSON so
	// the caller can key a per-authorization device limit against it.
	out := struct {
		Token           string `json:"token"`
		AuthorizationID string `json:"authorizationId"`
	}{
		Token:           token,
		AuthorizationID: base64.StdEncoding.EncodeToString(authID),
	}
	outJSON, err := json.Marshal(out)
	if err != nil {
		fail("marshal output failed: %s", err)
	}
	fmt.Print(string(outJSON))
}

func main() {
	if len(os.Args) < 2 {
		fail("usage: psiphon-authgen <gen-keys|issue> ...")
	}
	switch os.Args[1] {
	case "gen-keys":
		genKeys(os.Args[2:])
	case "issue":
		issue(os.Args[2:])
	default:
		fail("unknown command: %s", os.Args[1])
	}
}
