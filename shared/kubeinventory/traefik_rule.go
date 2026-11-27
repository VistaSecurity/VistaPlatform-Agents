package kubeinventory

// Traefik route rules (an IngressRoute's match). A rule is free text that
// commonly carries shared secrets (Header(`X-Api-Key`, `...`),
// Query(`token`, `...`), ClientIP lists), so it is never sent as written: it
// is tokenised and rebuilt with only the literals that are known not to be
// secrets, and a rule that cannot be tokenised is not sent at all.
//
// The syntax read here, of Traefik v2 and v3 alike: matcher calls
// Name(arg, arg...) whose arguments are string literals in backticks (raw) or
// double quotes (Go escapes), joined by && and ||, negated by !, grouped by
// parentheses.

import (
	"strconv"
	"strings"
)

// traefikRedacted replaces a literal that is not sent.
const traefikRedacted = "[REDACTED]"

// Matchers whose every argument is sent: hosts, paths, methods, protocols.
var traefikPublicMatchers = map[string]bool{
	"Host": true, "HostSNI": true, "HostRegexp": true, "HostSNIRegexp": true,
	"Path": true, "PathPrefix": true, "PathRegexp": true, "Method": true, "ALPN": true,
}

// Matchers whose first argument is a key name (a header or query parameter)
// and is sent; their values are not.
var traefikKeyMatchers = map[string]bool{
	"Header": true, "HeaderRegexp": true, "Headers": true, "HeadersRegexp": true, "Query": true, "QueryRegexp": true,
}

type ruleTokenKind int

const (
	tokIdent ruleTokenKind = iota
	tokLiteral
	tokOpen
	tokClose
	tokComma
	tokAnd
	tokOr
	tokNot
)

type ruleToken struct {
	kind  ruleTokenKind
	text  string // the identifier, or the literal as written (quotes included)
	quote byte   // a literal's quote character
	value string // a literal's value
}

// tokenizeRule splits a rule into tokens; false when it holds anything else.
func tokenizeRule(s string) ([]ruleToken, bool) {
	var out []ruleToken
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(':
			out = append(out, ruleToken{kind: tokOpen})
			i++
		case c == ')':
			out = append(out, ruleToken{kind: tokClose})
			i++
		case c == ',':
			out = append(out, ruleToken{kind: tokComma})
			i++
		case c == '!':
			out = append(out, ruleToken{kind: tokNot})
			i++
		case strings.HasPrefix(s[i:], "&&"):
			out = append(out, ruleToken{kind: tokAnd})
			i += 2
		case strings.HasPrefix(s[i:], "||"):
			out = append(out, ruleToken{kind: tokOr})
			i += 2
		case c == '`':
			end := strings.IndexByte(s[i+1:], '`')
			if end < 0 {
				return nil, false
			}
			raw := s[i : i+end+2]
			out = append(out, ruleToken{kind: tokLiteral, text: raw, quote: '`', value: raw[1 : len(raw)-1]})
			i += end + 2
		case c == '"':
			j := i + 1
			for ; j < len(s) && s[j] != '"'; j++ {
				if s[j] == '\\' {
					j++
				}
			}
			if j >= len(s) {
				return nil, false
			}
			raw := s[i : j+1]
			value, err := strconv.Unquote(raw)
			if err != nil {
				return nil, false
			}
			out = append(out, ruleToken{kind: tokLiteral, text: raw, quote: '"', value: value})
			i = j + 1
		case c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z':
			j := i
			for j < len(s) && (s[j] >= 'A' && s[j] <= 'Z' || s[j] >= 'a' && s[j] <= 'z' || s[j] >= '0' && s[j] <= '9') {
				j++
			}
			out = append(out, ruleToken{kind: tokIdent, text: s[i:j]})
			i = j
		default:
			return nil, false
		}
	}
	return out, true
}

// ruleCall is one matcher call found in a rule.
type ruleCall struct {
	name  string
	args  []ruleToken
	depth int // group depth (parentheses that are not a call's)
}

// ruleShape is a rule checked for structure: every literal is an argument of
// a call, calls do not nest, parentheses balance.
type ruleShape struct {
	tokens []ruleToken
	calls  []ruleCall
	// orAtDepth counts || by group depth.
	orAtDepth map[int]int
	negated   bool
}

func parseRule(s string) (*ruleShape, bool) {
	tokens, ok := tokenizeRule(s)
	if !ok || len(tokens) == 0 {
		return nil, false
	}
	shape := &ruleShape{tokens: tokens, orAtDepth: map[int]int{}}
	depth := 0
	var call *ruleCall
	for i := 0; i < len(tokens); i++ {
		t := tokens[i]
		if call != nil {
			switch t.kind {
			case tokLiteral:
				call.args = append(call.args, t)
				// A literal is followed by a comma and another literal, or
				// by the call's close.
				if i+1 >= len(tokens) {
					return nil, false
				}
				switch tokens[i+1].kind {
				case tokComma:
					if i+2 >= len(tokens) || tokens[i+2].kind != tokLiteral {
						return nil, false
					}
					i++
				case tokClose:
				default:
					return nil, false
				}
			case tokClose:
				shape.calls = append(shape.calls, *call)
				call = nil
			default:
				return nil, false
			}
			continue
		}
		switch t.kind {
		case tokIdent:
			if i+1 >= len(tokens) || tokens[i+1].kind != tokOpen {
				return nil, false
			}
			call = &ruleCall{name: t.text, depth: depth}
			i++
		case tokOpen:
			depth++
		case tokClose:
			depth--
			if depth < 0 {
				return nil, false
			}
		case tokAnd:
		case tokOr:
			shape.orAtDepth[depth]++
		case tokNot:
			shape.negated = true
		default:
			return nil, false
		}
	}
	if call != nil || depth != 0 {
		return nil, false
	}
	return shape, true
}

// redactedRule is the rule rebuilt with only the literals that may be sent,
// or "" when it cannot be tokenised safely. The structure is kept: matcher
// names, operators, grouping.
func redactedRule(s string) string {
	shape, ok := parseRule(s)
	if !ok {
		return ""
	}
	var b strings.Builder
	name, arg := "", 0
	inCall := false
	for _, t := range shape.tokens {
		switch t.kind {
		case tokIdent:
			b.WriteString(t.text)
			name, arg, inCall = t.text, 0, true
		case tokOpen:
			b.WriteByte('(')
		case tokClose:
			b.WriteByte(')')
			inCall = false
		case tokComma:
			b.WriteString(", ")
			arg++
		case tokAnd:
			b.WriteString(" && ")
		case tokOr:
			b.WriteString(" || ")
		case tokNot:
			b.WriteByte('!')
		case tokLiteral:
			if !inCall {
				return ""
			}
			if traefikPublicMatchers[name] || (traefikKeyMatchers[name] && arg == 0) {
				b.WriteString(t.text)
			} else {
				b.WriteByte(t.quote)
				b.WriteString(traefikRedacted)
				b.WriteByte(t.quote)
			}
		}
	}
	return b.String()
}

// traefikHosts are the host names a route's rule names, only where they are
// certain: literal arguments of Host(...) or HostSNI(...), in a rule without
// negation or host regular expression, where every || is at the top level
// and every alternative names a host. Anything else yields no hosts (the
// route is still sent, with its redacted rule).
func traefikHosts(match string) []string {
	shape, ok := parseRule(match)
	if !ok || shape.negated {
		return nil
	}
	for d, n := range shape.orAtDepth {
		if d > 0 && n > 0 {
			return nil
		}
	}
	// Each top-level alternative must name a host.
	arms, armHasHost := 1, map[int]bool{}
	depth, arm := 0, 0
	callIndex := 0
	var hosts []string
	for i := 0; i < len(shape.tokens); i++ {
		t := shape.tokens[i]
		switch t.kind {
		case tokIdent:
			c := shape.calls[callIndex]
			callIndex++
			switch c.name {
			case "HostRegexp", "HostSNIRegexp":
				return nil
			case "Host", "HostSNI":
				armHasHost[arm] = true
				for _, a := range c.args {
					if h := cleanHost(a.value); h != "" {
						hosts = append(hosts, h)
					}
				}
			}
			// Skip the call's own tokens.
			for i++; shape.tokens[i].kind != tokClose; i++ {
			}
		case tokOpen:
			depth++
		case tokClose:
			depth--
		case tokOr:
			if depth == 0 {
				arm++
				arms++
			}
		}
	}
	for a := 0; a < arms; a++ {
		if !armHasHost[a] {
			return nil
		}
	}
	return limit(sortedUnique(hosts), 64)
}
