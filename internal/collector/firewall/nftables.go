// Package firewall detects host firewall state on Linux and Windows.
package firewall

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// maxExprDepth bounds recursion into nft JSON expressions.
const maxExprDepth = 64

// errNoJSON indicates nft printed something that is not its JSON schema.
var errNoJSON = errors.New("output is not nftables JSON")

// RulesetAnalysis summarizes inbound filtering in an nftables ruleset.
type RulesetAnalysis struct {
	// InputChains is the number of active base chains attached to the
	// input hook of the ip, ip6 or inet families.
	InputChains int
	// Filtering lists human-readable reasons why inbound traffic is
	// filtered. Empty means no drop or reject can be reached from any
	// input base chain.
	Filtering []string
}

type chainKey struct{ family, table, name string }

type nftChain struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Hook   string `json:"hook"`
	Policy string `json:"policy"`
}

type nftRule struct {
	Family string          `json:"family"`
	Table  string          `json:"table"`
	Chain  string          `json:"chain"`
	Expr   json.RawMessage `json:"expr"`
}

type nftTable struct {
	Family string          `json:"family"`
	Name   string          `json:"name"`
	Flags  json.RawMessage `json:"flags"`
}

// AnalyzeRuleset parses the output of `nft -j list ruleset` and determines
// whether any input base chain can drop or reject traffic, either through
// its policy or through a drop/reject verdict reachable via jump/goto.
//
// This is deliberately a presence test, not a proof of a default-deny
// policy: a single "drop" rule counts as filtering.
func AnalyzeRuleset(data []byte) (RulesetAnalysis, error) {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&doc); err != nil {
		return RulesetAnalysis{}, fmt.Errorf("%w: %v", errNoJSON, err)
	}
	if doc.Nftables == nil {
		return RulesetAnalysis{}, errNoJSON
	}

	dormant := map[[2]string]bool{}
	chains := map[chainKey]nftChain{}
	var chainOrder []chainKey
	rules := map[chainKey][]json.RawMessage{}

	for _, obj := range doc.Nftables {
		if raw, ok := obj["table"]; ok {
			var t nftTable
			if err := json.Unmarshal(raw, &t); err != nil {
				return RulesetAnalysis{}, fmt.Errorf("table object: %w", err)
			}
			if bytes.Contains(t.Flags, []byte(`"dormant"`)) {
				dormant[[2]string{t.Family, t.Name}] = true
			}
		}
		if raw, ok := obj["chain"]; ok {
			var c nftChain
			if err := json.Unmarshal(raw, &c); err != nil {
				return RulesetAnalysis{}, fmt.Errorf("chain object: %w", err)
			}
			k := chainKey{c.Family, c.Table, c.Name}
			if _, seen := chains[k]; !seen {
				chainOrder = append(chainOrder, k)
			}
			chains[k] = c
		}
		if raw, ok := obj["rule"]; ok {
			var r nftRule
			if err := json.Unmarshal(raw, &r); err != nil {
				return RulesetAnalysis{}, fmt.Errorf("rule object: %w", err)
			}
			k := chainKey{r.Family, r.Table, r.Chain}
			rules[k] = append(rules[k], r.Expr)
		}
	}

	var res RulesetAnalysis
	for _, k := range chainOrder {
		c := chains[k]
		if c.Hook != "input" || c.Type != "filter" || dormant[[2]string{k.family, k.table}] {
			continue
		}
		if !slices.Contains([]string{"ip", "ip6", "inet"}, k.family) {
			continue
		}
		res.InputChains++
		label := fmt.Sprintf("%s %s %s", k.family, k.table, k.name)
		if c.Policy == "drop" {
			res.Filtering = append(res.Filtering, label+": input hook with policy drop")
			continue
		}
		visited := map[chainKey]bool{}
		if via, ok := reachesDrop(k, rules, visited, 0); ok {
			res.Filtering = append(res.Filtering, label+": input hook, "+via)
		}
	}
	return res, nil
}

// reachesDrop reports whether a drop/reject verdict is reachable from chain
// k through its rules and any chains they jump or goto.
func reachesDrop(k chainKey, rules map[chainKey][]json.RawMessage, visited map[chainKey]bool, depth int) (string, bool) {
	if visited[k] || depth > maxExprDepth {
		return "", false
	}
	visited[k] = true
	for _, raw := range rules[k] {
		var expr any
		if err := json.Unmarshal(raw, &expr); err != nil {
			continue
		}
		verdict, targets := scanExpr(expr, 0)
		if verdict != "" {
			if depth == 0 {
				return verdict + " rule", true
			}
			return fmt.Sprintf("%s rule in chain %s", verdict, k.name), true
		}
		for _, target := range targets {
			next := chainKey{k.family, k.table, target}
			if via, ok := reachesDrop(next, rules, visited, depth+1); ok {
				return via, true
			}
		}
	}
	return "", false
}

// scanExpr walks an expression tree looking for drop/reject verdicts and
// jump/goto targets. Verdict maps and sets are covered by the generic walk.
func scanExpr(v any, depth int) (string, []string) {
	if depth > maxExprDepth {
		return "", nil
	}
	var targets []string
	switch t := v.(type) {
	case map[string]any:
		for key, val := range t {
			switch key {
			case "drop", "reject":
				return key, nil
			case "jump", "goto":
				if m, ok := val.(map[string]any); ok {
					if target, ok := m["target"].(string); ok {
						targets = append(targets, target)
					}
				}
			default:
				verdict, sub := scanExpr(val, depth+1)
				if verdict != "" {
					return verdict, nil
				}
				targets = append(targets, sub...)
			}
		}
	case []any:
		for _, item := range t {
			verdict, sub := scanExpr(item, depth+1)
			if verdict != "" {
				return verdict, nil
			}
			targets = append(targets, sub...)
		}
	}
	slices.Sort(targets)
	return "", slices.Compact(targets)
}

// ParseUFWEnabled reads ENABLED= from /etc/ufw/ufw.conf.
func ParseUFWEnabled(data []byte) (enabled, found bool) {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		value, ok := strings.CutPrefix(line, "ENABLED=")
		if !ok {
			continue
		}
		value = strings.ToLower(strings.Trim(value, `"'`))
		enabled, found = value == "yes", true
	}
	return enabled, found
}
