// Package managedprotocol is the agent side of managed protocol version 1, the
// contract between a customer-deployed agent and the Vista Platform control
// plane (docs/managed-protocol.md; message schemas in schemas/managed/v1/).
//
// Three rules live here, so both agents apply them the same way:
//
//   - Every request names the protocol in the Vista-Agent-Protocol header, so
//     the platform can refuse an agent it does not speak before decoding a body.
//   - Every registration, heartbeat and job answer names the platform's protocol
//     (in the body, or in the same header when the answer has no body), and the
//     agent works only while that is a version it implements. An answer with no
//     protocol (an older platform) or another version is refused: nothing is
//     executed and nothing is submitted until the agent or the platform is
//     changed. The agent never guesses a shape.
//   - Capabilities are additive: the platform answers with the capabilities it
//     will use with this agent, the agent keeps the intersection with its own,
//     and an unknown capability is ignored by both sides.
package managedprotocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Version is the only managed protocol version this build implements.
const Version = 1

// Header carries the protocol version on every agent request ("1") and, on a
// platform answer without a body, the version and capabilities
// ("1; capabilities=a,b").
const Header = "Vista-Agent-Protocol"

// Agent kinds named in a registration request.
const (
	AgentKindSensor      = "sensor"
	AgentKindDeviceAgent = "device-agent"
)

// CodeProtocolUnsupported is the code of the platform's 426 answer to an agent
// speaking a protocol version it does not support.
const CodeProtocolUnsupported = "agent_protocol_unsupported"

// CodeUnsupportedCommand is the code an agent acknowledges a command or job
// with when it does not run that kind of work: an unknown type, a legacy
// payload, or work whose capability was not negotiated.
const CodeUnsupportedCommand = "unsupported_command"

// Protocol is the protocol object carried in registration requests and in the
// platform's registration, heartbeat and job answers.
type Protocol struct {
	Version      int      `json:"version"`
	Capabilities []string `json:"capabilities"`
}

// Offer is the protocol object an agent with these capabilities sends.
func Offer(capabilities []string) Protocol {
	return Protocol{Version: Version, Capabilities: normalize(capabilities)}
}

// SetRequestHeader names the protocol on an outgoing request.
func SetRequestHeader(h http.Header) {
	h.Set(Header, strconv.Itoa(Version))
}

// NewRequest is http.NewRequest for a managed-protocol call: the protocol
// header is always set, and Content-Type is set when there is a body.
func NewRequest(method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	SetRequestHeader(req.Header)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// FormatHeader renders a platform answer's header value.
func FormatHeader(p Protocol) string {
	v := strconv.Itoa(p.Version)
	if caps := normalize(p.Capabilities); len(caps) > 0 {
		v += "; capabilities=" + strings.Join(caps, ",")
	}
	return v
}

// ParseHeader reads a Vista-Agent-Protocol header value. ok is false when the
// value is empty; err is set when it is present but not a protocol statement.
func ParseHeader(value string) (p Protocol, ok bool, err error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return Protocol{}, false, nil
	}
	parts := strings.Split(value, ";")
	v, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || v < 1 {
		return Protocol{}, true, fmt.Errorf("%s header %q does not start with a protocol version", Header, value)
	}
	p.Version = v
	for _, param := range parts[1:] {
		key, val, found := strings.Cut(strings.TrimSpace(param), "=")
		if !found || strings.TrimSpace(key) != "capabilities" {
			continue // unknown parameters are additive, like capabilities
		}
		for _, c := range strings.Split(val, ",") {
			if c = strings.TrimSpace(c); c != "" {
				p.Capabilities = append(p.Capabilities, c)
			}
		}
	}
	p.Capabilities = normalize(p.Capabilities)
	return p, true, nil
}

// ErrorBody is the platform's refusal body (schemas/managed/v1/error.schema.json).
type ErrorBody struct {
	Code          string `json:"code"`
	Message       string `json:"message,omitempty"`
	AgentProtocol int    `json:"agent_protocol,omitempty"`
	Supported     []int  `json:"supported,omitempty"`
}

// IncompatibleError says the platform does not speak a protocol this agent
// implements. Its Error text is the one line an operator reads.
type IncompatibleError struct {
	// PlatformVersion is the version the platform named; 0 when it named none.
	PlatformVersion int
	// Supported is what a 426 said the platform supports, when it said.
	Supported []int
	// StatusCode is the HTTP status of the answer (426, or the 2xx whose body
	// lacked a usable protocol).
	StatusCode int
	// Detail is the platform's own message, when it sent one.
	Detail string
}

func (e *IncompatibleError) Error() string {
	speaks := "no managed protocol version"
	switch {
	case e.PlatformVersion > 0:
		speaks = fmt.Sprintf("managed protocol %d", e.PlatformVersion)
	case containsInt(e.Supported, Version):
		// The platform speaks protocol 1 and still refused: the request did
		// not name it. That is this build's fault, not the platform's.
		speaks = fmt.Sprintf("managed protocol %d but refused this agent's request as not naming it", Version)
	case len(e.Supported) > 0:
		speaks = "managed protocol " + joinInts(e.Supported)
	}
	msg := fmt.Sprintf("platform speaks %s; this agent supports %d; nothing will be collected until the agent or the platform is changed", speaks, Version)
	if e.Detail != "" {
		msg += " (platform: " + e.Detail + ")"
	}
	return msg
}

// ViolationError is an answer that names protocol 1 but breaks one of its
// rules: a registration or rotation answer carrying a private key the platform
// generated, or an enrollment answer without the agent secret protocol 1
// always issues. The agent applies nothing from such an answer.
type ViolationError struct {
	Reason string
}

func (e *ViolationError) Error() string {
	return fmt.Sprintf("the platform's answer breaks managed protocol %d: %s; nothing from it was applied", Version, e.Reason)
}

// IsViolation reports whether err is (or wraps) a ViolationError.
func IsViolation(err error) bool {
	var v *ViolationError
	return errors.As(err, &v)
}

// IsIncompatible reports whether err is (or wraps) an IncompatibleError.
func IsIncompatible(err error) bool {
	var inc *IncompatibleError
	return errors.As(err, &inc)
}

// ErrNotNegotiated is returned for a result submission attempted before any
// answer from the platform has named its protocol.
var ErrNotNegotiated = errors.New("the platform's managed protocol is not known yet; nothing is submitted until a heartbeat or job answer names it")

// FromStatus turns a 426 answer into an IncompatibleError. body is the answer's
// body (already read). It returns nil for any other status.
func FromStatus(status int, header http.Header, body []byte) error {
	if status != http.StatusUpgradeRequired {
		return nil
	}
	e := &IncompatibleError{StatusCode: status}
	var eb ErrorBody
	if json.Unmarshal(body, &eb) == nil {
		e.Supported = eb.Supported
		e.Detail = strings.TrimSpace(eb.Message)
	}
	if p, ok, err := ParseHeader(header.Get(Header)); ok && err == nil && p.Version != Version {
		e.PlatformVersion = p.Version
	}
	return e
}

// Negotiate checks the platform's protocol from an answer and returns the
// capabilities in force: the intersection of the platform's and own. p is the
// body's protocol object (nil when the body has none).
func Negotiate(p *Protocol, status int, own []string) ([]string, error) {
	if p == nil {
		return nil, &IncompatibleError{StatusCode: status}
	}
	if p.Version != Version {
		return nil, &IncompatibleError{PlatformVersion: p.Version, StatusCode: status}
	}
	return Intersect(own, p.Capabilities), nil
}

// NegotiateHeader is Negotiate for an answer without a body: the protocol is
// read from the header.
func NegotiateHeader(header http.Header, status int, own []string) ([]string, error) {
	p, ok, err := ParseHeader(header.Get(Header))
	if !ok || err != nil {
		return nil, &IncompatibleError{StatusCode: status}
	}
	return Negotiate(&p, status, own)
}

// CheckHeaderIfPresent refuses an answer whose header names another version.
// An answer without the header passes: only registration, heartbeat and job
// answers are required to name the protocol.
func CheckHeaderIfPresent(header http.Header, status int) error {
	p, ok, err := ParseHeader(header.Get(Header))
	if !ok {
		return nil
	}
	if err != nil {
		return &IncompatibleError{StatusCode: status}
	}
	if p.Version != Version {
		return &IncompatibleError{PlatformVersion: p.Version, StatusCode: status}
	}
	return nil
}

// Intersect returns the capabilities in both lists, sorted, without duplicates.
func Intersect(own, platform []string) []string {
	have := map[string]bool{}
	for _, c := range platform {
		have[strings.TrimSpace(c)] = true
	}
	var out []string
	for _, c := range normalize(own) {
		if have[c] {
			out = append(out, c)
		}
	}
	return out
}

func normalize(caps []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, c := range caps {
		c = strings.TrimSpace(c)
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

func containsInt(v []int, n int) bool {
	for _, x := range v {
		if x == n {
			return true
		}
	}
	return false
}

func joinInts(v []int) string {
	s := make([]string, len(v))
	for i, n := range v {
		s[i] = strconv.Itoa(n)
	}
	return strings.Join(s, " or ")
}

// State is what an agent knows about the platform's protocol.
type State int

const (
	// StateUnknown: no answer has named the platform's protocol yet.
	StateUnknown State = iota
	// StateCompatible: the last answer named version 1.
	StateCompatible
	// StateIncompatible: the last answer named none, or another version.
	StateIncompatible
)

// Gate holds the negotiated protocol for one agent. Every answer that names (or
// fails to name) the platform's protocol is recorded; job execution and result
// submission ask Ready first. Safe for concurrent use.
type Gate struct {
	own []string

	mu    sync.Mutex
	cond  *sync.Cond
	state State
	caps  []string
	err   error
	// logf is where the refusal line goes; log.Printf when nil.
	logf func(format string, args ...any)
}

// NewGate returns a gate for an agent with these capabilities.
func NewGate(own []string) *Gate {
	g := &Gate{own: normalize(own)}
	g.cond = sync.NewCond(&g.mu)
	return g
}

// SetLogger replaces where the gate logs its one refusal line.
func (g *Gate) SetLogger(logf func(format string, args ...any)) {
	g.mu.Lock()
	g.logf = logf
	g.mu.Unlock()
}

// Own is this agent's own capability list.
func (g *Gate) Own() []string { return append([]string(nil), g.own...) }

// Compatible records an answer that named version 1 with these negotiated
// capabilities.
func (g *Gate) Compatible(caps []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.state == StateIncompatible {
		g.printf("✅ The platform now speaks managed protocol %d; collection resumes (capabilities: %s)", Version, strings.Join(caps, ","))
	}
	g.state, g.caps, g.err = StateCompatible, append([]string(nil), caps...), nil
	g.cond.Broadcast()
}

// Observe records the outcome of checking an answer: nil leaves the gate as it
// is, an IncompatibleError closes it. Any other error is returned unchanged
// and not recorded. It returns err, so a caller can write `return
// gate.Observe(err)`.
func (g *Gate) Observe(err error) error {
	var inc *IncompatibleError
	if err == nil || !errors.As(err, &inc) {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.state != StateIncompatible || g.err == nil || g.err.Error() != inc.Error() {
		g.printf("⛔ %s", inc.Error())
	}
	g.state, g.caps, g.err = StateIncompatible, nil, inc
	g.cond.Broadcast()
	return err
}

// Ready returns nil while the platform is known to speak version 1, the
// IncompatibleError while it is known not to, and ErrNotNegotiated before any
// answer has said.
func (g *Gate) Ready() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.readyLocked()
}

func (g *Gate) readyLocked() error {
	switch g.state {
	case StateCompatible:
		return nil
	case StateIncompatible:
		return g.err
	default:
		return ErrNotNegotiated
	}
}

// WaitReady is Ready, waiting up to d for a first answer when none has named
// the protocol yet. It does not wait while the gate is known incompatible.
func (g *Gate) WaitReady(d time.Duration) error {
	deadline := time.Now().Add(d)
	timer := time.AfterFunc(d, func() {
		g.mu.Lock()
		g.cond.Broadcast()
		g.mu.Unlock()
	})
	defer timer.Stop()
	g.mu.Lock()
	defer g.mu.Unlock()
	for g.state == StateUnknown && time.Now().Before(deadline) {
		g.cond.Wait()
	}
	return g.readyLocked()
}

// State reports the gate's state.
func (g *Gate) State() State {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.state
}

// Capabilities is the negotiated capability list (empty unless compatible).
func (g *Gate) Capabilities() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.caps...)
}

// Has reports whether capability c was negotiated with the platform.
func (g *Gate) Has(c string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.state != StateCompatible {
		return false
	}
	for _, have := range g.caps {
		if have == c {
			return true
		}
	}
	return false
}

// Problem is the refusal line while the gate is incompatible, "" otherwise. A
// heartbeat carries it as protocol_error so the console can show why.
func (g *Gate) Problem() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.state == StateIncompatible && g.err != nil {
		return g.err.Error()
	}
	return ""
}

func (g *Gate) printf(format string, args ...any) {
	if g.logf != nil {
		g.logf(format, args...)
		return
	}
	log.Printf(format, args...)
}
