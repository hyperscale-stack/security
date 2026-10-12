// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp_test

// Rule-level coverage of the corpus (plan review F1): every refusal rule of
// the package, found by parsing its sources, must be pinned by at least one
// corpus entry, or be listed below with the reason it cannot be.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Rule constructors and the sentinel each one rejects with.
var ruleConstructors = map[string]string{
	"gateMalformed":    "ErrMalformedResponse",
	"gateTooLarge":     "ErrResponseTooLarge",
	"invalidSignature": "ErrInvalidSignature",
}

// dynamicRules expands the rejections whose sentinel or detail is not a
// literal, by source expression.
var dynamicRules = map[string][]string{
	// checkIssuers(el, what) runs on the Response and on the Assertion.
	`ErrIssuerMismatch|what + " needs exactly one Issuer"`: {
		rejectionMessage("ErrIssuerMismatch", "Response needs exactly one Issuer"),
		rejectionMessage("ErrIssuerMismatch", "Assertion needs exactly one Issuer"),
	},
	`ErrIssuerMismatch|what + " Issuer Format is not entity"`: {
		rejectionMessage("ErrIssuerMismatch", "Response Issuer Format is not entity"),
		rejectionMessage("ErrIssuerMismatch", "Assertion Issuer Format is not entity"),
	},
	// gosaml2 ErrInvalidValue keys (verify.go invalidValueReason).
	`invalidValueReason(invalid)|""`: {
		rejectionMessage("ErrDestinationMismatch", ""), rejectionMessage("ErrRecipientMismatch", ""),
		rejectionMessage("ErrIssuerMismatch", ""), rejectionMessage("ErrResponseStatus", ""),
		rejectionMessage("ErrAssertionExpired", ""), rejectionMessage("ErrMalformedResponse", ""),
		rejectionMessage("ErrInvalidAssertion", ""),
	},
	// The gate's own messages are collected from gateMalformed/gateTooLarge.
	`ErrMalformedResponse|err.Error()`: nil,
	`ErrResponseTooLarge|ge.msg`:       nil,
	// invalidSignature's own body: its details are collected at its calls.
	`ErrInvalidSignature|detail`: nil,
	// Store and resolver errors pass through: their sentinels are pinned by
	// the replay entries and the connection tests.
	`err|""`: nil,
}

// uncoverableRules are refusals no corpus entry can produce, with why.
var uncoverableRules = map[string]string{
	// Request shapes, not response content (TestCompleteLogin_MalformedRequest).
	rejectionMessage("ErrMalformedRequest", "need one SAMLResponse and at most one RelayState"): "request shape",
	rejectionMessage("ErrMalformedRequest", "method is not POST"):                               "request shape",
	rejectionMessage("ErrMalformedRequest", "content type is not a form"):                       "request shape",
	rejectionMessage("ErrMalformedRequest", "unreadable body"):                                  "request shape",
	rejectionMessage("ErrMalformedRequest", "malformed form"):                                   "request shape",
	// Configuration changes between the two legs (TestCompleteLogin_CrossConnectionSubstitution).
	rejectionMessage("ErrTransactionMismatch", ""): "connection re-pointed after BeginLogin",
	// Defence in depth, shadowed by an earlier rule on every input.
	rejectionMessage("ErrResponseTooLarge", "XML document too large"):                               "the SAMLResponse is bounded by MaxResponseSize (at most 1 MiB, base64) first",
	rejectionMessage("ErrResponseTooLarge", "too many namespace declarations on an element"):        "shadowed by the attribute bound: a declaration is an attribute and both caps are 16",
	rejectionMessage("ErrMalformedResponse", "expected exactly one verified assertion"):             "the pre-check admits exactly one assertion",
	rejectionMessage("ErrInvalidSignature", "the assertion is not covered by a verified signature"): "the pre-check requires a signature; gosaml2 verifies every present one",
	rejectionMessage("ErrMalformedResponse", "missing IssueInstant"):                                "the pre-check requires IssueInstant in UTC form",
	rejectionMessage("ErrInvalidAssertion", "missing bearer subject confirmation"):                  "the pre-check requires one bearer confirmation",
	rejectionMessage("ErrInvalidAssertion", "bearer confirmation without NotOnOrAfter"):             "gosaml2 refuses it first (missing element)",
	rejectionMessage("ErrMalformedResponse", "bad Conditions NotBefore"):                            "the pre-check validates every time value",
	rejectionMessage("ErrMalformedResponse", "bad Conditions NotOnOrAfter"):                         "the pre-check validates every time value",
	rejectionMessage("ErrInvalidAssertion", "missing AuthnStatement or AuthnInstant"):               "the pre-check requires them",
	rejectionMessage("ErrDestinationMismatch", "Destination is not the connection's ACS URL"):       "gosaml2 checks a present Destination first (ErrDestinationMismatch without detail)",
	rejectionMessage("ErrRecipientMismatch", "Recipient is not the connection's ACS URL"):           "gosaml2 checks the Recipient first (ErrRecipientMismatch without detail)",
	rejectionMessage("ErrIssuerMismatch", "Issuer is not the connection's IdP entity ID"):           "gosaml2 checks both Issuers first (ErrIssuerMismatch without detail)",
	rejectionMessage("ErrResponseTooLarge", "verifier traversal budget exceeded"):                   "the element cap keeps responses under the budget (TestGosaml2TraversalBudgetIsPinned)",
	rejectionMessage("ErrInvalidSignature", "not signed"):                                           "the pre-check refuses unsigned responses first",
	rejectionMessage("ErrIssuerMismatch", "missing Issuer"):                                         "the pre-check requires both Issuers",
	rejectionMessage("ErrResponseStatus", ""):                                                       "a non-Success status is reported as a *StatusError before gosaml2 runs",
	rejectionMessage("ErrMalformedResponse", ""):                                                    "gosaml2 parse and round-trip failures: the gate refuses those inputs first",
	rejectionMessage("ErrInvalidAssertion", ""):                                                     "other gosaml2 values: the pre-check refuses them first",
	rejectionMessage("ErrUnknownConnection", ""):                                                    "connection deleted between the two legs",
	rejectionMessage("ErrInvalidConnection", ""):                                                    "connection invalidated between the two legs",
}

// collectRules parses the package sources and returns the exact messages of
// every refusal rule.
func collectRules(t *testing.T) []string {
	t.Helper()

	files, err := filepath.Glob("*.go")
	require.NoError(t, err)

	fset := token.NewFileSet()
	consts := map[string]string{}

	var parsed []*ast.File

	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}

		f, err := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, err)

		parsed = append(parsed, f)
		collectConsts(f, consts)
	}

	seen := map[string]bool{}

	var rules []string

	add := func(msgs ...string) {
		for _, m := range msgs {
			if !seen[m] {
				seen[m] = true
				rules = append(rules, m)
			}
		}
	}

	for _, f := range parsed {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			fn, ok := call.Fun.(*ast.Ident)
			if !ok {
				return true
			}

			switch {
			case fn.Name == "reject" && len(call.Args) == 3:
				add(rejectRule(t, call.Args[0], call.Args[1], consts)...)
			case ruleConstructors[fn.Name] != "" && len(call.Args) == 1:
				detail, ok := stringValue(call.Args[0], consts)
				require.True(t, ok, "%s(%s): non-constant detail", fn.Name, types.ExprString(call.Args[0]))
				add(rejectionMessage(ruleConstructors[fn.Name], detail))
			case fn.Name == "unsupportedAlgorithm":
				add(rejectionMessage("ErrUnsupportedAlgorithm", ""))
			}

			return true
		})
	}

	sort.Strings(rules)

	return rules
}

// rejectRule returns the messages of one reject(sentinel, detail, cause).
func rejectRule(t *testing.T, sentinel, detail ast.Expr, consts map[string]string) []string {
	t.Helper()

	name := types.ExprString(sentinel)
	d, isConst := stringValue(detail, consts)

	_, known := corpusSentinels[name]
	_, connection := connectionSentinels[name]

	if (known || connection) && isConst {
		return []string{rejectionMessage(name, d)}
	}

	key := name + "|" + types.ExprString(detail)

	msgs, ok := dynamicRules[key]
	require.True(t, ok, "unclassified dynamic rejection reject(%s, %s, …): add it to dynamicRules", name, types.ExprString(detail))

	return msgs
}

// stringValue evaluates a string literal or a string constant.
func stringValue(e ast.Expr, consts map[string]string) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}

		s, err := strconv.Unquote(v.Value)

		return s, err == nil
	case *ast.Ident:
		s, ok := consts[v.Name]

		return s, ok
	default:
		return "", false
	}
}

// collectConsts records the package's string constants.
func collectConsts(f *ast.File, consts map[string]string) {
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}

		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}

			for i, n := range vs.Names {
				if i < len(vs.Values) {
					if s, ok := stringValue(vs.Values[i], consts); ok {
						consts[n.Name] = s
					}
				}
			}
		}
	}
}

// TestCorpusCoversEveryRule requires every refusal rule of the package in
// at least one corpus entry, unless listed in uncoverableRules.
func TestCorpusCoversEveryRule(t *testing.T) {
	t.Parallel()

	m := loadCorpus(t)
	pinned := map[string]bool{}

	for _, f := range m.Fixtures {
		if f.Expect.Outcome != outcomeAccepted {
			pinned[f.Expect.message(false)] = true
			pinned[f.Expect.message(true)] = true
		}
	}

	var missing, stale []string

	rules := collectRules(t)
	require.Greater(t, len(rules), 80, "the source scan found too few rules")

	for _, rule := range rules {
		_, excused := uncoverableRules[rule]

		switch {
		case !pinned[rule] && !excused:
			missing = append(missing, rule)
		case pinned[rule] && excused:
			stale = append(stale, rule)
		}
	}

	require.Empty(t, missing, "refusal rules no corpus entry pins")
	require.Empty(t, stale, "rules pinned by the corpus but still listed as uncoverable")

	for rule := range uncoverableRules {
		require.True(t, slices.Contains(rules, rule), "uncoverableRules lists a rule the sources no longer have: %s", rule)
	}
}
