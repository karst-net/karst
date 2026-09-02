// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package control_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	karstapi "github.com/netbirdio/netbird/management/internals/karst/api"
	"github.com/netbirdio/netbird/management/internals/karst/audit"
	"github.com/netbirdio/netbird/management/internals/karst/bedrock"
	"github.com/netbirdio/netbird/management/internals/karst/node"
	karstpolicy "github.com/netbirdio/netbird/management/internals/karst/policy"
	"github.com/netbirdio/netbird/management/internals/karst/relayreg"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/shared/auth"
)

// Every mutating console route, driven against the real account manager, the
// real permissions manager and the real Karst stores.
//
// # Why this is separate from the handler tests
//
// The tests in karst/api drive the same routes against one-method doubles.
// They prove the handler's own logic and they are fast, and neither of those
// is the question here. This asks whether the console's writes reach a real
// database through the real authorization middleware — the middleware that
// decides from a role in a store rather than from a struct field a test set.
//
// plans/phase-5/03-control-api.md's re-baseline names this as the remaining
// control-API work: "broader real-server authorization and mutation coverage
// for every console route".
//
// # Why it walks the router
//
// The table below is checked *against the route table* — every mutating admin
// route the router serves must appear in it. A route added later without a
// case here fails this test rather than quietly shipping unexercised, which is
// the only version of "coverage for every console route" that stays true after
// the day it is written.

const (
	consoleAccountID = "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	consoleAdminID   = "edafee4e-63fb-11ec-90d6-0242ac120003"
	// A role-`user` row in the same account, from upstream's own fixture. Using
	// it rather than minting a member through an IdP mock keeps this test about
	// authorization instead of about user creation.
	consoleMemberID = "f4f6d672-63fb-11ec-90d6-0242ac120003"
)

type consoleCase struct {
	name   string
	method string
	// path is the route template with its parameters filled in.
	path string
	body string
	// headers the console sends. Policy writes are optimiztic-concurrency
	// controlled, so If-Match is part of the request rather than optional.
	headers map[string]string
	// want is the status an administrator should get. Not always 2xx: a
	// mutation whose precondition is absent in a fresh account still proves the
	// route reached a real store and was authorized, and pretending otherwise
	// would mean seeding Bedrock ceremonies to assert a 409.
	want []int
	// template is the mux path template this case covers, for the completeness
	// check below.
	template string
}

func consoleMutations() []consoleCase {
	return []consoleCase{
		{
			name: "rename a node", method: http.MethodPatch,
			path: "/karst/v1/nodes/unknown-handle", body: `{"name":"renamed"}`,
			want: []int{http.StatusNotFound}, template: "/karst/v1/nodes/{handle}",
		},
		{
			name: "delete a node", method: http.MethodDelete,
			path: "/karst/v1/nodes/unknown-handle", body: "",
			want: []int{http.StatusNotFound}, template: "/karst/v1/nodes/{handle}",
		},
		{
			name: "write the access policy", method: http.MethodPut,
			path: "/karst/v1/policy",
			body: `{"document":"{\"acls\":[{\"action\":\"accept\",\"src\":[\"*\"],\"dst\":[\"*:*\"]}]}"}`,
			// Version 0: the account has no policy yet, and that is the write
			// the console's first-run flow makes.
			headers: map[string]string{"If-Match": `"0"`},
			want:    []int{http.StatusOK}, template: "/karst/v1/policy",
		},
		{
			name: "validate a policy document", method: http.MethodPost,
			path: "/karst/v1/policy/validate", body: `{"document":"{\"acls\":[]}"}`,
			want: []int{http.StatusOK}, template: "/karst/v1/policy/validate",
		},
		{
			name: "preview a policy change", method: http.MethodPost,
			path: "/karst/v1/policy/preview", body: `{"document":"{\"acls\":[]}"}`,
			want: []int{http.StatusOK}, template: "/karst/v1/policy/preview",
		},
		{
			name: "test a policy expectation", method: http.MethodPost,
			path: "/karst/v1/policy/test",
			body: `{"document":"{\"acls\":[]}","expectations":[]}`,
			want: []int{http.StatusOK}, template: "/karst/v1/policy/test",
		},
		{
			name: "roll a policy back", method: http.MethodPost,
			path: "/karst/v1/policy/rollback/1", body: "",
			headers: map[string]string{"If-Match": `"1"`},
			// 404 when nothing has been written yet, which is the state a
			// fresh account is in and a perfectly good answer.
			want: []int{http.StatusOK, http.StatusNotFound}, template: "/karst/v1/policy/rollback/{version}",
		},
		{
			name: "register a relay", method: http.MethodPost,
			path: "/karst/v1/relays",
			body: `{"address":"198.51.100.9:443","tls_server_name":"relay.example.test","region":"eu","identity_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB"}`,
			want: []int{http.StatusCreated, http.StatusOK}, template: "/karst/v1/relays",
		},
		{
			name: "remove a relay", method: http.MethodDelete,
			path: "/karst/v1/relays/unknown-relay", body: "",
			want: []int{http.StatusNoContent, http.StatusNotFound}, template: "/karst/v1/relays/{relayId}",
		},
		{
			name: "configure an audit sink", method: http.MethodPost,
			path: "/karst/v1/audit/sinks",
			body: `{"kind":"webhook","endpoint":"https://siem.example.test/karst"}`,
			want: []int{http.StatusCreated, http.StatusOK}, template: "/karst/v1/audit/sinks",
		},
		{
			name: "set the Bedrock mode", method: http.MethodPut,
			path: "/karst/v1/bedrock/mode", body: `{"mode":"advisory"}`,
			want: []int{http.StatusOK, http.StatusConflict}, template: "/karst/v1/bedrock/mode",
		},
		{
			name: "import a Bedrock bootstrap", method: http.MethodPost,
			path: "/karst/v1/bedrock/bootstrap/import", body: `{"payload":""}`,
			want: []int{http.StatusBadRequest}, template: "/karst/v1/bedrock/bootstrap/import",
		},
		{
			name: "export Bedrock signing requests", method: http.MethodPost,
			path: "/karst/v1/bedrock/requests/export", body: `{}`,
			// 412 until a genesis log is imported. That is the correct answer
			// for a fresh account and it is the *sibling* of the anchor export
			// below, which is how finding 66 was noticed.
			want: []int{http.StatusOK, http.StatusPreconditionFailed}, template: "/karst/v1/bedrock/requests/export",
		},
		{
			name: "import Bedrock responses", method: http.MethodPost,
			path: "/karst/v1/bedrock/responses/import", body: `{"payload":""}`,
			want: []int{http.StatusBadRequest}, template: "/karst/v1/bedrock/responses/import",
		},
		{
			name: "export an audit anchor request", method: http.MethodPost,
			path: "/karst/v1/bedrock/audit-anchor/export", body: `{}`,
			// 412, like every other missing-precondition on this surface.
			// It answered 500 before finding 66.
			want: []int{http.StatusOK, http.StatusPreconditionFailed}, template: "/karst/v1/bedrock/audit-anchor/export",
		},
	}
}

// consoleRouter wires the API the way bootstrap does: real account manager,
// real permissions manager, real Karst stores. The only fake is the clock.
func consoleRouter(t *testing.T) *mux.Router {
	t.Helper()
	am, s, _ := realAccountManager(t)

	// A private DSN per test: the shared in-memory name is process-wide, and a
	// policy row left by one test changes the version another test rolls back
	// to.
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:karstconsole%d?mode=memory&cache=shared", t.Name()[len(t.Name())-1])),
		&gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("karst db: %v", err)
	}
	for _, table := range []string{
		"karst_node_identities", "karst_device_sessions", "karst_policy_versions",
		"karst_relays", "karst_audit_entries", "karst_audit_sinks",
	} {
		_ = db.Exec("DROP TABLE IF EXISTS " + table).Error
	}

	nodes, err := node.NewStore(db)
	if err != nil {
		t.Fatalf("node store: %v", err)
	}
	auditLog, err := audit.New(db)
	if err != nil {
		t.Fatalf("audit log: %v", err)
	}
	policyStore, err := karstpolicy.NewStore(db)
	if err != nil {
		t.Fatalf("policy store: %v", err)
	}
	relayStore, err := relayreg.NewStore(db)
	if err != nil {
		t.Fatalf("relay store: %v", err)
	}
	bedrockStore, err := bedrock.NewStore(db)
	if err != nil {
		t.Fatalf("bedrock store: %v", err)
	}
	bedrockLog, err := bedrock.NewLog(db)
	if err != nil {
		t.Fatalf("bedrock log: %v", err)
	}

	router := mux.NewRouter()
	karstapi.RegisterEndpoints(nodes, am, am, auditLog, policyStore, relayStore,
		bedrockStore, bedrockLog, permissions.NewManager(s), router)
	return router
}

func consoleRequest(t *testing.T, router *mux.Router, userID string, c consoleCase) *httptest.ResponseRecorder {
	t.Helper()
	var body *strings.Reader
	if c.body == "" {
		body = strings.NewReader("")
	} else {
		body = strings.NewReader(c.body)
	}
	req := httptest.NewRequest(c.method, c.path, body)
	req.Header.Set("content-type", "application/json")
	for name, value := range c.headers {
		req.Header.Set(name, value)
	}
	req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: consoleAccountID, UserId: userID})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	return response
}

// An administrator's writes reach the real stack and are authorized by it.
func TestConsoleMutationsAreAuthorizedForAnAdministrator(t *testing.T) {
	router := consoleRouter(t)
	for _, c := range consoleMutations() {
		t.Run(c.name, func(t *testing.T) {
			response := consoleRequest(t, router, consoleAdminID, c)
			// The assertion that matters is that it is *not* a refusal. A
			// route that 403s here is one the real permissions manager
			// declines for an administrator, which is a broken console
			// whatever the handler's own tests say.
			if response.Code == http.StatusForbidden || response.Code == http.StatusUnauthorized {
				t.Fatalf("an administrator was refused: %s %s -> %d %s",
					c.method, c.path, response.Code, response.Body.String())
			}
			for _, want := range c.want {
				if response.Code == want {
					return
				}
			}
			t.Fatalf("%s %s -> %d (want one of %v) %s",
				c.method, c.path, response.Code, c.want, response.Body.String())
		})
	}
}

// The same routes, as a member of the same account. This is the half that
// needs the real permissions manager: the role comes out of the store.
func TestConsoleMutationsAreRefusedForAMember(t *testing.T) {
	router := consoleRouter(t)
	for _, c := range consoleMutations() {
		t.Run(c.name, func(t *testing.T) {
			response := consoleRequest(t, router, consoleMemberID, c)
			if response.Code != http.StatusForbidden {
				t.Fatalf("a member was not refused: %s %s -> %d %s",
					c.method, c.path, response.Code, response.Body.String())
			}
		})
	}
}

// The gate that keeps the two tests above honest as the surface grows.
func TestEveryMutatingConsoleRouteHasRealServerCoverage(t *testing.T) {
	covered := make(map[string]struct{})
	for _, c := range consoleMutations() {
		covered[c.method+" "+c.template] = struct{}{}
	}

	router := consoleRouter(t)
	var missing []string
	err := router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		template, err := route.GetPathTemplate()
		if err != nil || !strings.HasPrefix(template, "/karst/v1/") || strings.HasPrefix(template, "/karst/v1/me/") {
			return nil
		}
		methods, err := route.GetMethods()
		if err != nil {
			return nil // the subrouter prefix itself carries no methods
		}
		for _, method := range methods {
			// GET is read-only and covered by the role matrix and the
			// no-secrets scan; OPTIONS is CORS.
			if method == http.MethodGet || method == http.MethodOptions {
				continue
			}
			if _, ok := covered[method+" "+template]; !ok {
				missing = append(missing, method+" "+template)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(missing) > 0 {
		t.Fatalf("mutating console routes with no real-server coverage:\n  %s\n"+
			"Add a case to consoleMutations().", strings.Join(missing, "\n  "))
	}
}
