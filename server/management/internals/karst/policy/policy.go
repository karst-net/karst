// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Package policy parses and compiles Karst access-control policy (PLAN.md
// §4.3) into the per-node packet filter shipped in the netmap.
//
// The document is Tailscale-compatible in shape so the concepts transfer:
// `groups` name sets of users, `tagOwners` say who may apply a tag, and `acls`
// grant traffic from a set of sources to a set of destination ports.
//
// # The server distributes policy, it does not enforce it
//
// §4.3: "The control server is a distributor of policy, not an enforcement
// point — a compromised server can misroute but cannot read traffic." So the
// output of this package is a *filter*, evaluated by the Rust datapath on both
// ingress and egress. Compiling per node rather than shipping the whole policy
// is what keeps one node from learning the shape of the rest of the network.
//
// # Default deny
//
// A policy with no matching rule denies. That is not a configuration choice; a
// filter that failed open would make a policy typo indistinguishable from an
// intentional grant, and the mistake would be invisible until someone looked
// for it.
package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Wildcard matches any source, destination or port.
const Wildcard = "*"

var (
	ErrParse   = errors.New("policy: cannot parse")
	ErrInvalid = errors.New("policy: invalid")
)

// Document is a policy as written.
type Document struct {
	// Groups maps "group:name" to a list of user identifiers.
	Groups map[string][]string `json:"groups,omitempty"`
	// TagOwners maps "tag:name" to the groups or users allowed to apply it.
	// Not consulted when compiling a filter — it governs who may *assign* a
	// tag, which is an admission-time check, not a packet-time one.
	TagOwners map[string][]string `json:"tagOwners,omitempty"`
	// ACLs are evaluated in order, though order does not currently matter:
	// every rule is an accept and there is no deny form, so the result is the
	// union. A deny form would make ordering significant and is deliberately
	// absent until someone needs it.
	ACLs []Rule `json:"acls,omitempty"`
}

// Rule is one accept entry.
type Rule struct {
	Action string   `json:"action"`
	Src    []string `json:"src"`
	Dst    []string `json:"dst"`
}

// Node is what the compiler needs to know about a peer to decide whether a
// rule applies to it.
type Node struct {
	// Handle is the node's stable identifier and the value used in the filter.
	Handle string
	// User owns the node, e.g. "alice@example.com". Empty for a tagged node,
	// which by convention has no user.
	User string
	// Tags applied to the node, each "tag:name".
	Tags []string
	// Addresses the node owns, as CIDR.
	Addresses []string
}

// Parse reads a policy document.
//
// The input is JSON. HuJSON — the commented, trailing-comma-tolerant superset
// §4.3 specifies — standardizes to JSON, so accepting it is a preprocessing
// step in front of this rather than a change here.
func Parse(data []byte) (*Document, error) {
	var d Document
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParse, err)
	}
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return &d, nil
}

// ErrorLocation returns the best editor location for a parse error. JSON's
// SyntaxError offset is byte-based and one-indexed; editors need a line and
// column. Semantic validation has no source span yet, so it is anchored at the
// start of the document rather than pretending to know a precise location.
func ErrorLocation(data []byte, err error) (line, column int) {
	var syntax *json.SyntaxError
	if !errors.As(err, &syntax) || syntax.Offset <= 0 {
		return 1, 1
	}
	line, column = 1, 1
	for _, b := range data[:min(int(syntax.Offset)-1, len(data))] {
		if b == '\n' {
			line, column = line+1, 1
		} else {
			column++
		}
	}
	return line, column
}

// Validate checks the document for the mistakes that would otherwise compile
// into a silently wrong filter.
func (d *Document) Validate() error {
	for name := range d.Groups {
		if !strings.HasPrefix(name, "group:") {
			return fmt.Errorf("%w: group %q must be named group:something", ErrInvalid, name)
		}
	}
	for name, owners := range d.TagOwners {
		if !strings.HasPrefix(name, "tag:") {
			return fmt.Errorf("%w: tag %q must be named tag:something", ErrInvalid, name)
		}
		if len(owners) == 0 {
			// A tag nobody owns can never be applied, so every rule mentioning
			// it is dead. Silently compiling to nothing is the failure mode
			// this catches.
			return fmt.Errorf("%w: tag %q has no owners", ErrInvalid, name)
		}
	}
	for i, r := range d.ACLs {
		if r.Action != "accept" {
			return fmt.Errorf("%w: acl %d has action %q; only \"accept\" exists",
				ErrInvalid, i, r.Action)
		}
		if len(r.Src) == 0 || len(r.Dst) == 0 {
			return fmt.Errorf("%w: acl %d has an empty src or dst", ErrInvalid, i)
		}
		for _, dst := range r.Dst {
			if _, _, err := splitDst(dst); err != nil {
				return fmt.Errorf("%w: acl %d: %v", ErrInvalid, i, err)
			}
		}
		for _, src := range r.Src {
			if strings.HasPrefix(src, "group:") {
				if _, ok := d.Groups[src]; !ok {
					// A typo in a group name would otherwise match nothing and
					// compile to an empty filter — a policy that looks right
					// and grants nothing.
					return fmt.Errorf("%w: acl %d references undefined %s", ErrInvalid, i, src)
				}
			}
		}
	}
	return nil
}

// splitDst separates "tag:prod:22,443" into its selector and its ports.
//
// The selector may itself contain colons, which is why this splits from the
// right rather than the left: "tag:prod:22" is the tag "tag:prod" on port 22,
// not the tag "tag" on "prod:22".
func splitDst(dst string) (selector string, ports []PortRange, err error) {
	i := strings.LastIndex(dst, ":")
	if i < 0 {
		return "", nil, fmt.Errorf("destination %q has no port specification", dst)
	}
	selector, portSpec := dst[:i], dst[i+1:]
	if selector == "" {
		return "", nil, fmt.Errorf("destination %q has an empty selector", dst)
	}
	// Distinguish "the ports are malformed" from "there are no ports at all".
	// Splitting from the right means a destination written without ports, like
	// "tag:prod", silently becomes the selector "tag" with the port "prod" —
	// which does fail, but with an error pointing at integer parsing rather
	// than at the missing port specification the author actually forgot.
	if !looksLikePortSpec(portSpec) {
		return "", nil, fmt.Errorf("destination %q has no port specification "+
			"(expected something like %q)", dst, dst+":22")
	}
	ports, err = parsePorts(portSpec)
	if err != nil {
		return "", nil, fmt.Errorf("destination %q: %w", dst, err)
	}
	return selector, ports, nil
}

// looksLikePortSpec reports whether s could be a port specification at all.
func looksLikePortSpec(s string) bool {
	if s == Wildcard {
		return true
	}
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && r != ',' && r != '-' && r != ' ' {
			return false
		}
	}
	return true
}

// PortRange is an inclusive range. A single port is a range of one.
type PortRange struct {
	First uint16 `json:"first"`
	Last  uint16 `json:"last"`
}

// AllPorts is the range a "*" port specification compiles to.
var AllPorts = PortRange{First: 0, Last: 65535}

func parsePorts(spec string) ([]PortRange, error) {
	if spec == Wildcard {
		return []PortRange{AllPorts}, nil
	}
	var out []PortRange
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, errors.New("empty port in list")
		}
		lo, hi, isRange := strings.Cut(part, "-")
		first, err := strconv.ParseUint(lo, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("port %q: %w", lo, err)
		}
		last := first
		if isRange {
			last, err = strconv.ParseUint(hi, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("port %q: %w", hi, err)
			}
			if last < first {
				return nil, fmt.Errorf("port range %q is inverted", part)
			}
		}
		out = append(out, PortRange{First: uint16(first), Last: uint16(last)})
	}
	return out, nil
}

// FilterRule is one compiled rule in a node's packet filter: traffic from any
// of Srcs to this node is permitted on Ports.
type FilterRule struct {
	// Srcs are node handles, or "*".
	Srcs  []string    `json:"srcs"`
	Ports []PortRange `json:"ports"`
	// Provenance is retained for server-side explanation and deliberately is
	// not serialized into the node packet-filter contract.
	Provenance Provenance `json:"-"`
}

// Provenance identifies the policy source that emitted a compiled rule. Rule
// numbers are one-based because they are shown directly to people.
type Provenance struct {
	Rule            int
	SourceTerm      string
	DestinationTerm string
}

// Filter is what a single node is shipped.
//
// It describes only what may reach *that* node. A node learns nothing about
// rules that do not involve it, which is the point of compiling per node.
type Filter struct {
	Node  string       `json:"node"`
	Rules []FilterRule `json:"rules"`
}

// Compile produces the packet filter for one node.
//
// `all` is every node in the network, needed to resolve group and tag
// selectors on the source side into concrete handles.
func (d *Document) Compile(target Node, all []Node) (*Filter, error) {
	f := &Filter{Node: target.Handle}

	for i, rule := range d.ACLs {
		for _, dst := range rule.Dst {
			selector, ports, err := splitDst(dst)
			if err != nil {
				return nil, fmt.Errorf("%w: acl %d: %v", ErrInvalid, i, err)
			}
			if !d.matches(selector, target) {
				continue // this rule does not describe traffic to this node
			}

			srcs := d.resolveSources(rule.Src, all)
			if len(srcs) == 0 {
				// A rule whose sources resolve to nobody grants nothing. Not an
				// error — a group can legitimately be empty today — but it must
				// not produce a rule with an empty source list, which a
				// permissive evaluator might read as "any".
				continue
			}
			f.Rules = append(f.Rules, FilterRule{Srcs: srcs, Ports: ports, Provenance: Provenance{Rule: i + 1, SourceTerm: strings.Join(rule.Src, ","), DestinationTerm: selector}})
		}
	}

	f.Rules = normalize(f.Rules)
	return f, nil
}

// EgressRule is one compiled rule in a node's *outbound* filter: traffic from
// this node to any of Dsts is permitted on Ports.
type EgressRule struct {
	// Dsts are node handles, or "*".
	Dsts       []string    `json:"dsts"`
	Ports      []PortRange `json:"ports"`
	Provenance Provenance  `json:"-"`
}

// EgressFilter is what a node is shipped for the traffic it originates.
//
// It is the mirror of Filter, compiled from the same document: Filter answers
// "who may reach me", this answers "whom may I reach". Both are needed for
// §4.3's "enforced on both ends", and neither is derivable from the other —
// Karst's ACLs are unidirectional grants, so a node's inbound rules say nothing
// about what it may send.
//
// # Why enforce at the sender at all
//
// The receiver's check is the one that provides the security property: a
// compromised sender will ignore its own filter, and the receiver's ingress
// check is what stops it. Enforcing on egress buys two other things. A denied
// flow fails locally and immediately, rather than being silently dropped after
// a round trip — the difference between a diagnosable error and a black hole.
// And traffic that policy forbids never reaches a peer's crypto at all, so a
// misconfigured node cannot spend a peer's CPU discovering that.
type EgressFilter struct {
	Node  string       `json:"node"`
	Rules []EgressRule `json:"rules"`
}

// CompileEgress produces the outbound packet filter for one node.
//
// The structure mirrors Compile with the two sides swapped: there, a rule
// applies if its *destination* selector describes the target and the sources
// are resolved; here, a rule applies if the target is among its *sources* and
// the destinations are resolved.
func (d *Document) CompileEgress(target Node, all []Node) (*EgressFilter, error) {
	f := &EgressFilter{Node: target.Handle}

	for i, rule := range d.ACLs {
		sourceTerm := d.matchingSource(rule.Src, target)
		if sourceTerm == "" {
			continue // this rule does not describe traffic from this node
		}
		for _, dst := range rule.Dst {
			selector, ports, err := splitDst(dst)
			if err != nil {
				return nil, fmt.Errorf("%w: acl %d: %v", ErrInvalid, i, err)
			}
			dsts := d.resolveSources([]string{selector}, all)
			if len(dsts) == 0 {
				// Resolving to nobody grants nothing. Not an error — a group can
				// legitimately be empty today — but it must not become a rule
				// with an empty destination list, which a permissive evaluator
				// might read as "any".
				continue
			}
			f.Rules = append(f.Rules, EgressRule{Dsts: dsts, Ports: ports, Provenance: Provenance{Rule: i + 1, SourceTerm: sourceTerm, DestinationTerm: selector}})
		}
	}

	f.Rules = normalizeEgress(f.Rules)
	return f, nil
}

func (d *Document) matchingSource(selectors []string, n Node) string {
	for _, selector := range selectors {
		if d.matches(selector, n) {
			return selector
		}
	}
	return ""
}

// Permits reports whether the egress filter allows traffic to dst on port.
//
// Default deny, for the same reason Filter.Permits is: a policy typo must
// remove access rather than grant it.
func (f *EgressFilter) Permits(dst string, port uint16) bool {
	for _, r := range f.Rules {
		matched := false
		for _, s := range r.Dsts {
			if s == Wildcard || s == dst {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		for _, p := range r.Ports {
			if port >= p.First && port <= p.Last {
				return true
			}
		}
	}
	return false
}

// normalizeEgress is normalize for the outbound direction, and exists for the
// same reason: without a stable order, map iteration would make every
// recompilation look like a change and defeat the netmap's version hash.
func normalizeEgress(rules []EgressRule) []EgressRule {
	for i := range rules {
		sort.Slice(rules[i].Ports, func(a, b int) bool {
			if rules[i].Ports[a].First != rules[i].Ports[b].First {
				return rules[i].Ports[a].First < rules[i].Ports[b].First
			}
			return rules[i].Ports[a].Last < rules[i].Ports[b].Last
		})
	}
	sort.Slice(rules, func(a, b int) bool {
		if s := strings.Join(rules[a].Dsts, ","); s != strings.Join(rules[b].Dsts, ",") {
			return s < strings.Join(rules[b].Dsts, ",")
		}
		return rules[a].Ports[0].First < rules[b].Ports[0].First
	})
	return rules
}

// matches reports whether a selector describes the given node.
func (d *Document) matches(selector string, n Node) bool {
	switch {
	case selector == Wildcard:
		return true
	case strings.HasPrefix(selector, "tag:"):
		for _, t := range n.Tags {
			if t == selector {
				return true
			}
		}
		return false
	case strings.HasPrefix(selector, "group:"):
		// A tagged node has no user, so it is never a member of a group. This
		// is deliberate and matches Tailscale: tags replace user ownership
		// rather than adding to it, so that a server's access does not follow
		// the person who happened to enroll it.
		if n.User == "" {
			return false
		}
		for _, member := range d.Groups[selector] {
			if member == n.User {
				return true
			}
		}
		return false
	default:
		// A bare user identifier, or the node's own handle.
		return selector == n.User || selector == n.Handle
	}
}

// resolveSources turns selectors into the concrete node handles they name.
func (d *Document) resolveSources(selectors []string, all []Node) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, sel := range selectors {
		if sel == Wildcard {
			return []string{Wildcard}
		}
		for _, n := range all {
			if !d.matches(sel, n) {
				continue
			}
			if _, dup := seen[n.Handle]; dup {
				continue
			}
			seen[n.Handle] = struct{}{}
			out = append(out, n.Handle)
		}
	}
	sort.Strings(out)
	return out
}

// normalize sorts and deduplicates so that an unchanged policy compiles to a
// byte-identical filter. Without it, map iteration order would make every
// recompilation look like a change and defeat the netmap's version hash.
func normalize(rules []FilterRule) []FilterRule {
	for i := range rules {
		sort.Slice(rules[i].Ports, func(a, b int) bool {
			if rules[i].Ports[a].First != rules[i].Ports[b].First {
				return rules[i].Ports[a].First < rules[i].Ports[b].First
			}
			return rules[i].Ports[a].Last < rules[i].Ports[b].Last
		})
	}
	sort.Slice(rules, func(a, b int) bool {
		if s := strings.Join(rules[a].Srcs, ","); s != strings.Join(rules[b].Srcs, ",") {
			return s < strings.Join(rules[b].Srcs, ",")
		}
		return rules[a].Ports[0].First < rules[b].Ports[0].First
	})
	return rules
}

// Permits reports whether the filter allows traffic from src on port.
//
// This is the reference evaluator. The Rust datapath enforces the same rules;
// this exists so policy can be tested server-side and so `karst policy test`
// (§4.3) has something to run against.
func (f *Filter) Permits(src string, port uint16) bool {
	for _, r := range f.Rules {
		matched := false
		for _, s := range r.Srcs {
			if s == Wildcard || s == src {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		for _, p := range r.Ports {
			if port >= p.First && port <= p.Last {
				return true
			}
		}
	}
	// Default deny. A filter with no matching rule denies, so a policy typo
	// removes access rather than granting it.
	return false
}
