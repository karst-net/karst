// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

package policy_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/netbirdio/netbird/management/internals/karst/policy"
)

// PLAN.md §4.3 asks for "a large table-driven test suite". Access control is
// the component where a subtle mistake is both easy to make and invisible
// until someone exploits it, so the tests enumerate cases rather than
// exercising a few paths.

var nodes = []policy.Node{
	{Handle: "hA", User: "alice@example.com", Addresses: []string{"100.64.0.1/32"}},
	{Handle: "hB", User: "bob@example.com", Addresses: []string{"100.64.0.2/32"}},
	{Handle: "hC", User: "carol@example.com", Addresses: []string{"100.64.0.3/32"}},
	{Handle: "hProd", Tags: []string{"tag:prod"}, Addresses: []string{"100.64.0.10/32"}},
	{Handle: "hDev", Tags: []string{"tag:dev"}, Addresses: []string{"100.64.0.11/32"}},
	{Handle: "hBoth", Tags: []string{"tag:prod", "tag:dev"}, Addresses: []string{"100.64.0.12/32"}},
}

func nodeByHandle(t *testing.T, h string) policy.Node {
	t.Helper()
	for _, n := range nodes {
		if n.Handle == h {
			return n
		}
	}
	t.Fatalf("no node %q", h)
	return policy.Node{}
}

func mustParse(t *testing.T, src string) *policy.Document {
	t.Helper()
	d, err := policy.Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return d
}

func compile(t *testing.T, d *policy.Document, target string) *policy.Filter {
	t.Helper()
	f, err := d.Compile(nodeByHandle(t, target), nodes)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return f
}

const srePolicy = `{
  "groups": { "group:sre": ["alice@example.com", "bob@example.com"] },
  "tagOwners": { "tag:prod": ["group:sre"], "tag:dev": ["group:sre"] },
  "acls": [
    { "action": "accept", "src": ["group:sre"], "dst": ["tag:prod:22,443"] }
  ]
}`

// ── the core matrix ─────────────────────────────────────────────────────────

func TestPermitMatrix(t *testing.T) {
	d := mustParse(t, srePolicy)

	cases := []struct {
		name   string
		target string
		src    string
		port   uint16
		want   bool
	}{
		{"sre member to prod on 22", "hProd", "hA", 22, true},
		{"other sre member to prod on 443", "hProd", "hB", 443, true},
		{"non-member to prod on 22", "hProd", "hC", 22, false},
		{"sre member to prod on an unlisted port", "hProd", "hA", 80, false},
		{"sre member to a dev node", "hDev", "hA", 22, false},
		{"tagged node as a source", "hProd", "hDev", 22, false},
		{"prod node to itself", "hProd", "hProd", 22, false},
		{"unknown source", "hProd", "nobody", 22, false},
		{"port zero", "hProd", "hA", 0, false},
		{"port 65535", "hProd", "hA", 65535, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := compile(t, d, tc.target)
			if got := f.Permits(tc.src, tc.port); got != tc.want {
				t.Fatalf("Permits(%q, %d) = %v, want %v", tc.src, tc.port, got, tc.want)
			}
		})
	}
}

func TestCompileEgressCarriesHumanExplanationProvenance(t *testing.T) {
	d := mustParse(t, srePolicy)
	f, err := d.CompileEgress(nodeByHandle(t, "hA"), nodes)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Rules) != 1 {
		t.Fatalf("rules = %#v", f.Rules)
	}
	got := f.Rules[0].Provenance
	if got.Rule != 1 || got.SourceTerm != "group:sre" || got.DestinationTerm != "tag:prod" {
		t.Fatalf("provenance = %#v", got)
	}
}

// A node carrying several tags is reachable under a rule naming any of them.
func TestMultipleTagsOnOneNode(t *testing.T) {
	d := mustParse(t, `{
      "groups": { "group:sre": ["alice@example.com"] },
      "tagOwners": { "tag:prod": ["group:sre"], "tag:dev": ["group:sre"] },
      "acls": [
        { "action": "accept", "src": ["group:sre"], "dst": ["tag:dev:8080"] }
      ]
    }`)
	f := compile(t, d, "hBoth")
	if !f.Permits("hA", 8080) {
		t.Fatal("a rule on tag:dev did not reach a node tagged both prod and dev")
	}
	if f.Permits("hA", 22) {
		t.Fatal("an unlisted port was permitted")
	}
}

// A tagged node has no user and so is never a group member. Tags replace user
// ownership rather than adding to it, so a server's access does not follow
// whoever happened to enrol it.
func TestTaggedNodesAreNotGroupMembers(t *testing.T) {
	d := mustParse(t, `{
      "groups": { "group:everyone": ["alice@example.com", "bob@example.com"] },
      "tagOwners": { "tag:prod": ["group:everyone"] },
      "acls": [
        { "action": "accept", "src": ["group:everyone"], "dst": ["tag:prod:22"] }
      ]
    }`)
	f := compile(t, d, "hProd")
	if f.Permits("hProd", 22) || f.Permits("hDev", 22) {
		t.Fatal("a tagged node was treated as a group member")
	}
	if !f.Permits("hA", 22) {
		t.Fatal("a real group member was denied")
	}
}

// ── ports ───────────────────────────────────────────────────────────────────

func TestPortSpecifications(t *testing.T) {
	cases := []struct {
		spec   string
		permit []uint16
		deny   []uint16
	}{
		{"22", []uint16{22}, []uint16{21, 23}},
		{"22,443", []uint16{22, 443}, []uint16{80, 442, 444}},
		{"8000-8010", []uint16{8000, 8005, 8010}, []uint16{7999, 8011}},
		{"22,8000-8010,443", []uint16{22, 443, 8000, 8010}, []uint16{80, 8011}},
		{"*", []uint16{0, 22, 65535}, nil},
		{"0-65535", []uint16{0, 65535}, nil},
		{"65535", []uint16{65535}, []uint16{65534}},
	}
	for _, tc := range cases {
		t.Run(tc.spec, func(t *testing.T) {
			d := mustParse(t, `{
              "groups": { "group:sre": ["alice@example.com"] },
              "tagOwners": { "tag:prod": ["group:sre"] },
              "acls": [
                { "action": "accept", "src": ["group:sre"], "dst": ["tag:prod:`+tc.spec+`"] }
              ]
            }`)
			f := compile(t, d, "hProd")
			for _, p := range tc.permit {
				if !f.Permits("hA", p) {
					t.Errorf("port %d should be permitted by %q", p, tc.spec)
				}
			}
			for _, p := range tc.deny {
				if f.Permits("hA", p) {
					t.Errorf("port %d should be denied by %q", p, tc.spec)
				}
			}
		})
	}
}

// ── wildcards ───────────────────────────────────────────────────────────────

func TestWildcards(t *testing.T) {
	t.Run("wildcard source", func(t *testing.T) {
		d := mustParse(t, `{
          "tagOwners": { "tag:prod": ["group:sre"] },
          "groups": { "group:sre": ["alice@example.com"] },
          "acls": [{ "action": "accept", "src": ["*"], "dst": ["tag:prod:22"] }]
        }`)
		f := compile(t, d, "hProd")
		for _, src := range []string{"hA", "hC", "hDev", "someone-unknown"} {
			if !f.Permits(src, 22) {
				t.Errorf("wildcard source denied %q", src)
			}
		}
	})

	t.Run("wildcard destination reaches every node", func(t *testing.T) {
		d := mustParse(t, `{
          "groups": { "group:sre": ["alice@example.com"] },
          "acls": [{ "action": "accept", "src": ["group:sre"], "dst": ["*:22"] }]
        }`)
		for _, target := range []string{"hProd", "hDev", "hB", "hC"} {
			if !compile(t, d, target).Permits("hA", 22) {
				t.Errorf("wildcard destination did not reach %q", target)
			}
		}
	})
}

// ── default deny ────────────────────────────────────────────────────────────

// A filter with no matching rule denies. A policy typo must remove access, not
// grant it.
func TestDefaultDeny(t *testing.T) {
	empty := mustParse(t, `{}`)
	f := compile(t, empty, "hProd")
	if len(f.Rules) != 0 {
		t.Fatalf("an empty policy compiled to %d rules", len(f.Rules))
	}
	for _, src := range []string{"hA", "*", ""} {
		for _, port := range []uint16{0, 22, 443, 65535} {
			if f.Permits(src, port) {
				t.Fatalf("empty policy permitted %q on %d", src, port)
			}
		}
	}
}

// A rule whose sources resolve to nobody must produce no rule at all — never a
// rule with an empty source list, which a permissive evaluator could read as
// "any".
func TestEmptyGroupGrantsNothing(t *testing.T) {
	d := mustParse(t, `{
      "groups": { "group:nobody": [] },
      "tagOwners": { "tag:prod": ["group:nobody"] },
      "acls": [{ "action": "accept", "src": ["group:nobody"], "dst": ["tag:prod:22"] }]
    }`)
	f := compile(t, d, "hProd")
	if len(f.Rules) != 0 {
		t.Fatalf("an empty group produced %d rules: %+v", len(f.Rules), f.Rules)
	}
	for _, src := range []string{"hA", "hB", "*", ""} {
		if f.Permits(src, 22) {
			t.Fatalf("an empty group permitted %q", src)
		}
	}
}

// ── per-node compilation ────────────────────────────────────────────────────

// A node's filter must describe only traffic to that node: it should learn
// nothing about rules that do not involve it.
func TestFilterIsScopedToItsNode(t *testing.T) {
	d := mustParse(t, `{
      "groups": { "group:sre": ["alice@example.com"] },
      "tagOwners": { "tag:prod": ["group:sre"], "tag:dev": ["group:sre"] },
      "acls": [
        { "action": "accept", "src": ["group:sre"], "dst": ["tag:prod:22"] },
        { "action": "accept", "src": ["hC"], "dst": ["tag:dev:9000"] }
      ]
    }`)

	prod := compile(t, d, "hProd")
	if len(prod.Rules) != 1 {
		t.Fatalf("prod filter has %d rules, want 1", len(prod.Rules))
	}
	for _, r := range prod.Rules {
		for _, p := range r.Ports {
			if p.First == 9000 {
				t.Fatal("the prod node was shipped a rule that only concerns dev")
			}
		}
	}

	dev := compile(t, d, "hDev")
	if !dev.Permits("hC", 9000) {
		t.Fatal("the dev node did not get its own rule")
	}
	if dev.Permits("hA", 22) {
		t.Fatal("the dev node got the prod rule")
	}
}

// An unchanged policy must compile to a byte-identical filter, or the netmap's
// content hash would change on every recompilation and defeat its own purpose.
func TestCompilationIsDeterministic(t *testing.T) {
	d := mustParse(t, srePolicy)
	first := compile(t, d, "hProd")
	for i := 0; i < 20; i++ {
		next := compile(t, d, "hProd")
		if len(first.Rules) != len(next.Rules) {
			t.Fatal("rule count changed between identical compilations")
		}
		for j := range first.Rules {
			if strings.Join(first.Rules[j].Srcs, ",") != strings.Join(next.Rules[j].Srcs, ",") {
				t.Fatal("source order changed between identical compilations")
			}
		}
	}
}

// ── validation ──────────────────────────────────────────────────────────────

func TestValidationRejects(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"unnamed group", `{"groups": {"sre": ["a@b.c"]}}`, "group:something"},
		{"unnamed tag", `{"tagOwners": {"prod": ["group:x"]}}`, "tag:something"},
		{"tag with no owners", `{"tagOwners": {"tag:prod": []}}`, "no owners"},
		{"deny action", `{"acls":[{"action":"deny","src":["*"],"dst":["*:22"]}]}`, "only \"accept\""},
		{"empty src", `{"acls":[{"action":"accept","src":[],"dst":["*:22"]}]}`, "empty src"},
		{"empty dst", `{"acls":[{"action":"accept","src":["*"],"dst":[]}]}`, "empty src"},
		{"dst without ports", `{"acls":[{"action":"accept","src":["*"],"dst":["tag:prod"]}]}`, "no port"},
		{"dst with empty selector", `{"acls":[{"action":"accept","src":["*"],"dst":[":22"]}]}`, "empty selector"},
		{"inverted port range", `{"acls":[{"action":"accept","src":["*"],"dst":["*:100-1"]}]}`, "inverted"},
		{"port out of range", `{"acls":[{"action":"accept","src":["*"],"dst":["*:70000"]}]}`, "port"},
		{"undefined group in src", `{"acls":[{"action":"accept","src":["group:ghost"],"dst":["*:22"]}]}`, "undefined"},
		{"unknown field", `{"nonsense": 1}`, "cannot parse"},
		{"not json", `not json at all`, "cannot parse"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := policy.Parse([]byte(tc.src))
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
			if !errors.Is(err, policy.ErrInvalid) && !errors.Is(err, policy.ErrParse) {
				t.Fatalf("error %v is neither ErrInvalid nor ErrParse", err)
			}
		})
	}
}

// "tag:prod:22" is the tag "tag:prod" on port 22, not the tag "tag" on
// "prod:22". Splitting from the left would quietly compile every tagged rule
// into something that matches nothing.
func TestSelectorsContainingColonsSplitFromTheRight(t *testing.T) {
	d := mustParse(t, srePolicy)
	f := compile(t, d, "hProd")
	if len(f.Rules) == 0 {
		t.Fatal("tag:prod:22,443 compiled to no rules, so the split is wrong")
	}
	if !f.Permits("hA", 22) || !f.Permits("hA", 443) {
		t.Fatal("the tag selector did not match")
	}
}

func TestValidPolicyRoundTrips(t *testing.T) {
	d := mustParse(t, srePolicy)
	if len(d.Groups) != 1 || len(d.ACLs) != 1 || len(d.TagOwners) != 2 {
		t.Fatalf("parsed document does not match the source: %+v", d)
	}
	if d.ACLs[0].Action != "accept" {
		t.Fatalf("action: %q", d.ACLs[0].Action)
	}
}

// ── the outbound direction ──────────────────────────────────────────────────

func compileEgress(t *testing.T, d *policy.Document, target string) *policy.EgressFilter {
	t.Helper()
	f, err := d.CompileEgress(nodeByHandle(t, target), nodes)
	if err != nil {
		t.Fatalf("compile egress: %v", err)
	}
	return f
}

// The mirror of TestPermitMatrix, from the sender's side. Enumerated rather
// than spot-checked for the same reason: the two directions are separate code
// paths and a mistake in either is invisible until someone relies on it.
func TestEgressMatrix(t *testing.T) {
	d := mustParse(t, srePolicy)

	cases := []struct {
		name   string
		target string
		dst    string
		port   uint16
		want   bool
	}{
		{"sre member to prod on 22", "hA", "hProd", 22, true},
		{"sre member to prod on 443", "hA", "hProd", 443, true},
		{"sre member to prod on an unlisted port", "hA", "hProd", 80, false},
		{"sre member to a dev node", "hA", "hDev", 22, false},
		{"non-member sending anywhere", "hC", "hProd", 22, false},
		{"a tagged node sending", "hProd", "hProd", 22, false},
		{"unknown destination", "hA", "nobody", 22, false},
		{"port zero", "hA", "hProd", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := compileEgress(t, d, tc.target)
			if got := f.Permits(tc.dst, tc.port); got != tc.want {
				t.Fatalf("Permits(%q, %d) = %v, want %v", tc.dst, tc.port, got, tc.want)
			}
		})
	}
}

// **The property that makes shipping both filters necessary.** A Karst ACL is a
// unidirectional grant, so a node's inbound rules say nothing about what it may
// send. If either filter were derived from the other, this would fail.
func TestTheTwoDirectionsAreNotDerivableFromEachOther(t *testing.T) {
	d := mustParse(t, srePolicy)

	// hProd may be reached by hA on 22, and may send to nobody at all.
	if !compile(t, d, "hProd").Permits("hA", 22) {
		t.Fatal("hProd should accept 22 from hA")
	}
	if compileEgress(t, d, "hProd").Permits("hA", 22) {
		t.Fatal("hProd may accept from hA without being allowed to send to it")
	}

	// And hA is the exact opposite.
	if !compileEgress(t, d, "hA").Permits("hProd", 22) {
		t.Fatal("hA should be allowed to send to hProd on 22")
	}
	if compile(t, d, "hA").Permits("hProd", 22) {
		t.Fatal("hA may send to hProd without accepting from it")
	}
}

// Default deny in the outbound direction too. A policy that grants nothing must
// compile to a filter that permits nothing, or a typo opens the network.
func TestEgressDefaultDeny(t *testing.T) {
	d := mustParse(t, `{"acls": []}`)
	f := compileEgress(t, d, "hA")
	if len(f.Rules) != 0 {
		t.Fatalf("an empty policy compiled to %d rules", len(f.Rules))
	}
	for _, port := range []uint16{0, 22, 443, 65535} {
		if f.Permits("hProd", port) {
			t.Fatalf("an empty policy permitted port %d", port)
		}
	}
}

// A destination selector resolving to nobody must grant nothing — and must not
// become a rule with an empty destination list, which a permissive evaluator
// could read as "any".
func TestEgressToAnEmptyGroupGrantsNothing(t *testing.T) {
	d := mustParse(t, `{
	  "groups": { "group:sre": ["alice@example.com"], "group:empty": [] },
	  "acls": [
	    { "action": "accept", "src": ["group:sre"], "dst": ["group:empty:22"] }
	  ]
	}`)
	f := compileEgress(t, d, "hA")
	for _, r := range f.Rules {
		if len(r.Dsts) == 0 {
			t.Fatal("a rule with an empty destination list was emitted")
		}
	}
	if f.Permits("hB", 22) || f.Permits("hProd", 22) {
		t.Fatal("a rule to an empty group granted access")
	}
}

func TestEgressWildcards(t *testing.T) {
	d := mustParse(t, `{
	  "acls": [ { "action": "accept", "src": ["*"], "dst": ["*:*"] } ]
	}`)
	f := compileEgress(t, d, "hA")
	if !f.Permits("hProd", 22) || !f.Permits("anything", 0) {
		t.Fatal("a wildcard policy must permit everything outbound")
	}
}

// Without a stable order, map iteration would make every recompilation look
// like a change and defeat the netmap's version hash.
func TestEgressCompilationIsDeterministic(t *testing.T) {
	d := mustParse(t, srePolicy)
	first := compileEgress(t, d, "hA")
	for i := 0; i < 20; i++ {
		again := compileEgress(t, d, "hA")
		if len(again.Rules) != len(first.Rules) {
			t.Fatal("rule count varies between compilations")
		}
		for j := range again.Rules {
			if strings.Join(again.Rules[j].Dsts, ",") != strings.Join(first.Rules[j].Dsts, ",") {
				t.Fatalf("compilation %d differs from the first", i)
			}
		}
	}
}

func TestErrorLocationUsesJSONSyntaxOffset(t *testing.T) {
	for _, test := range []struct {
		document string
		line     int
	}{
		{"{\n\"acls\": [],\n}", 3},
		{"{\n\"groups\": {},\n\"acls\": [\n}\n", 4},
	} {
		_, err := policy.Parse([]byte(test.document))
		if err == nil {
			t.Fatal("expected malformed JSON")
		}
		line, _ := policy.ErrorLocation([]byte(test.document), err)
		if line != test.line {
			t.Fatalf("got line %d, want %d", line, test.line)
		}
	}
}
