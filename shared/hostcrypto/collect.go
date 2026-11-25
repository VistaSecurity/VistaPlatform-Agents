package hostcrypto

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
)

// Options configure one collection. The zero value is a valid local
// collection with every bound at its default and every opt-in off.
type Options struct {
	// Mode is local or remote. Empty means whatever the target is; a mode
	// that contradicts the target is refused, because a "local" report built
	// over a remote connection would claim parsing it never did.
	Mode hostinventory.Mode
	// Platform overrides detection ("linux", "darwin", "windows").
	Platform string
	// AgentID is stamped on the Report in LOCAL mode only, as in host
	// inventory: the agent is not the host a remote collection describes.
	AgentID string
	// HomeDirectories opts in to per-user material.
	HomeDirectories bool
	// DefaultKeystorePasswords opts in to trying well-known keystore
	// passwords. Only whether one worked is recorded.
	DefaultKeystorePasswords bool
	// ExcludePaths are never entered by any pass.
	ExcludePaths []string
	// SweepRoots are the roots of pass 4. Empty means no sweep.
	SweepRoots []string
	// MaxFiles bounds the files visited in one run (default 200,000).
	MaxFiles int
	// MaxFileBytes is the largest file opened (default 10 MiB).
	MaxFileBytes int64
	// MaxRecordsPerSection bounds each section's list (default 2,000).
	MaxRecordsPerSection int
	// MaxDuration bounds one run (default 15 minutes).
	MaxDuration time.Duration
	// Now supplies the timestamp; nil means time.Now. Tests pin it.
	Now func() time.Time
}

const (
	defaultMaxRecordsPerSection = 2000
	defaultMaxDuration          = 15 * time.Minute
)

func (o Options) maxFiles() int {
	if o.MaxFiles > 0 {
		return o.MaxFiles
	}
	return defaultMaxFiles
}

func (o Options) maxFileBytes() int64 {
	if o.MaxFileBytes > 0 {
		return o.MaxFileBytes
	}
	return defaultMaxFileBytes
}

func (o Options) maxRecordsPerSection() int {
	if o.MaxRecordsPerSection > 0 {
		return o.MaxRecordsPerSection
	}
	return defaultMaxRecordsPerSection
}

func (o Options) maxDuration() time.Duration {
	if o.MaxDuration > 0 {
		return o.MaxDuration
	}
	return defaultMaxDuration
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now().UTC()
	}
	return time.Now().UTC()
}

// ---------------------------------------------------------------------------
// Report helpers
// ---------------------------------------------------------------------------

// maxErrorMessage bounds a recorded failure, as in host inventory.
const maxErrorMessage = 300

// outcomeRank orders section outcomes so a later, weaker outcome cannot hide
// an earlier, worse one: failed > partial > ok > unsupported = skipped.
//
// The rule: an outcome is recorded when it ranks HIGHER than what the section
// already holds. So two passes that both touch "certificates", one of which
// failed, leave "failed"; a pass that read part of a section and a later one
// that read its own part in full leave "partial"; and "skipped" or
// "unsupported" stand only when nothing else was recorded (a section a pass
// skipped and another then read in full says "ok"). Between skipped and
// unsupported, the first recorded stands.
func outcomeRank(o string) int {
	switch o {
	case SectionFailed:
		return 4
	case SectionPartial:
		return 3
	case SectionOK:
		return 2
	case SectionUnsupported, SectionSkipped:
		return 1
	}
	return 0
}

// mark records a section outcome under the precedence of outcomeRank.
func (r *Report) mark(section, outcome string) {
	if r.Sections == nil {
		r.Sections = make(map[string]string)
	}
	cur, ok := r.Sections[section]
	if !ok || outcomeRank(outcome) > outcomeRank(cur) {
		r.Sections[section] = outcome
	}
}

// fail marks a section failed and records why.
func (r *Report) fail(section string, err error) {
	r.mark(section, SectionFailed)
	r.recordError(section, err)
}

// partial marks a section that holds part of the answer and records why.
func (r *Report) partial(section string, err error) {
	r.mark(section, SectionPartial)
	r.recordError(section, err)
}

// skip marks a section the operator did not turn on or the mode cannot do.
func (r *Report) skip(section string) { r.mark(section, SectionSkipped) }

// limit records that a bound cut a section short, once per section and bound,
// and marks the section partial: a truncated list is not a complete one.
func (r *Report) limit(section, limit, detail string) {
	r.mark(section, SectionPartial)
	for _, l := range r.Limits {
		if l.Section == section && l.Limit == limit {
			return
		}
	}
	r.Limits = append(r.Limits, LimitHit{Section: section, Limit: limit, Detail: boundMessage(detail)})
}

// recordError appends a bounded StepError.
//
// Two rules on top of the bound:
//
//   - A failure that is a permission denial says, in the message, what the
//     platform needs to see it (jobPrivilegeNote): the platform's console
//     shows the message as the reason a section is partial, and "permission
//     denied" alone does not tell an operator what to change. The note is
//     taken back off at the end of a run that turned out to be elevated
//     (jobDropPrivilegeNotes), where it would be wrong.
//   - The same step and message recorded again is counted, not repeated:
//     "... (2 times)". Several known locations share a listing root (/opt for
//     /opt/java/* and /opt/jdk*, the depth-0 listing that looks for links),
//     and each listing reports the same unreadable directories.
func (r *Report) recordError(step string, err error) {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	msg = boundMessage(msg)
	if jobIsPermission(err, msg) && !jobSaysPrivilege(msg) {
		msg += jobPrivilegeNote(r.Platform)
	}
	for i := range r.Errors {
		if r.Errors[i].Step != step {
			continue
		}
		base, n := jobSplitRepeat(r.Errors[i].Message)
		if base == msg {
			r.Errors[i].Message = fmt.Sprintf("%s (%d times)", msg, n+1)
			return
		}
	}
	r.Errors = append(r.Errors, StepError{Step: step, Message: msg})
}

// jobIsPermission reports whether a failure is the account not being allowed
// to read something. Some passes wrap the Target's sentinels; others restate
// a listing's denials as a count, which only the words carry.
func jobIsPermission(err error, msg string) bool {
	if err != nil && (errors.Is(err, ErrPermission) || errors.Is(err, fs.ErrPermission)) {
		return true
	}
	m := strings.ToLower(msg)
	return strings.Contains(m, "permission denied") || strings.Contains(m, "access is denied") ||
		strings.Contains(m, "directories could not be read")
}

// jobPrivilegeNotes are what each platform needs for a complete answer.
var jobPrivilegeNotes = map[string]string{
	hostinventory.PlatformLinux:   " (needs root)",
	hostinventory.PlatformDarwin:  " (needs root and Full Disk Access)",
	hostinventory.PlatformWindows: " (needs SYSTEM or an elevated administrator)",
}

// jobSaysPrivilege reports whether a message already names what it needs.
func jobSaysPrivilege(m string) bool {
	return strings.Contains(m, "root") || strings.Contains(m, "SYSTEM") ||
		strings.Contains(m, "administrator") || strings.Contains(m, "Full Disk Access")
}

// jobPrivilegeNote is the note for a platform.
func jobPrivilegeNote(platform string) string {
	if n, ok := jobPrivilegeNotes[platform]; ok {
		return n
	}
	return " (needs root or SYSTEM)"
}

// jobSplitRepeat splits "msg (N times)" into msg and N; anything else is
// itself, once.
func jobSplitRepeat(m string) (string, int) {
	if !strings.HasSuffix(m, " times)") {
		return m, 1
	}
	i := strings.LastIndex(m, " (")
	if i < 0 {
		return m, 1
	}
	var n int
	if _, err := fmt.Sscanf(m[i:], " (%d times)", &n); err != nil || n < 2 {
		return m, 1
	}
	return m[:i], n
}

// jobDropPrivilegeNotes takes the notes off again when the run was in fact
// elevated (and, on macOS, had Full Disk Access): a denial then has another
// cause, and "needs root" would send an operator the wrong way.
func (r *Report) jobDropPrivilegeNotes() {
	if r.Access.Elevated == nil || !*r.Access.Elevated {
		return
	}
	if r.Platform == hostinventory.PlatformDarwin && (r.Access.FullDiskAccess == nil || !*r.Access.FullDiskAccess) {
		return
	}
	for i := range r.Errors {
		for _, n := range jobPrivilegeNotes {
			r.Errors[i].Message = strings.Replace(r.Errors[i].Message, n, "", 1)
		}
		r.Errors[i].Message = strings.Replace(r.Errors[i].Message, " (needs root or SYSTEM)", "", 1)
	}
}

// boundMessage keeps a message to one line of at most 300 bytes. Every error
// this package builds names a path or a count, never content; the bound and
// the line folding are for errors from below (a runner's stderr).
func boundMessage(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f {
			c = ' '
		}
		b = append(b, c)
	}
	if len(b) > maxErrorMessage {
		// Cut on a rune boundary.
		cut := maxErrorMessage
		for cut > 0 && b[cut]&0xC0 == 0x80 {
			cut--
		}
		return string(b[:cut]) + "…(truncated)"
	}
	return string(b)
}

// SectionState returns the recorded outcome for a section, or "" when no pass
// has claimed it.
func (r *Report) SectionState(section string) string {
	if r == nil {
		return ""
	}
	return r.Sections[section]
}

// SectionOK reports whether a section ran to completion, the only safe basis
// for reading an empty list as "none found".
func (r *Report) SectionOK(section string) bool {
	return r.SectionState(section) == SectionOK
}

// ---------------------------------------------------------------------------
// Budget
// ---------------------------------------------------------------------------

// budget is the run's shared allowance of files visited and its deadline.
// Passes consult it before work; it is safe for concurrent use.
type budget struct {
	mu       sync.Mutex
	maxFiles int
	visited  int
	deadline time.Time
	now      func() time.Time
}

func newBudget(maxFiles int, deadline time.Time, now func() time.Time) *budget {
	if now == nil {
		now = time.Now
	}
	return &budget{maxFiles: maxFiles, deadline: deadline, now: now}
}

// take spends n files from the allowance. It returns how many were granted:
// n while the allowance lasts, fewer (possibly 0) when it runs out.
func (b *budget) take(n int) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	left := b.maxFiles - b.visited
	if left <= 0 {
		return 0
	}
	if n > left {
		n = left
	}
	b.visited += n
	return n
}

// remaining is how many files the allowance still has.
func (b *budget) remaining() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if left := b.maxFiles - b.visited; left > 0 {
		return left
	}
	return 0
}

// expired reports whether the run's time is up.
func (b *budget) expired() bool {
	return !b.deadline.IsZero() && !b.now().Before(b.deadline)
}

// ---------------------------------------------------------------------------
// Collection
// ---------------------------------------------------------------------------

// collection is what every pass works on: the target, the options, the report
// being built, the de-duplicating registry and the shared budget. Its report
// methods lock, so passes may run concurrently.
type collection struct {
	target   Target
	opts     Options
	report   *Report
	registry *registry
	budget   *budget

	// loc is the state passes 1 and 2 share (pass_known.go, pass_config.go):
	// what was visited, the configuration files found, the references
	// followed. Created by the first of them; nil until then.
	loc *locState

	// runCtx is the run's context, and callerBound the caller's deadline
	// when it is earlier than MaxDuration (0 otherwise): what a limit names.
	runCtx         context.Context
	callerBound    time.Duration
	callerDeadline bool

	mu sync.Mutex
}

func (c *collection) mark(section, outcome string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.report.mark(section, outcome)
}

// fail marks a section failed, unless the run's time is up or its context
// ended: a step cut short by the deadline or by the caller is partial, with
// the limit, never failed.
func (c *collection) fail(section string, err error) {
	if c.stopping(err) {
		c.limit(section, "max_duration", c.stopDetail())
		c.note(section, err)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.report.fail(section, err)
}

// stopping reports whether err, or the run's own state, says the run is
// being stopped by its deadline or its caller.
func (c *collection) stopping(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if c.runCtx != nil && c.runCtx.Err() != nil {
		return true
	}
	return c.budget != nil && c.budget.expired()
}

// stopDetail says which bound stopped the run: the caller's cancellation, the
// caller's deadline, or Options.MaxDuration, with the bound that applied.
func (c *collection) stopDetail() string {
	if c.runCtx != nil && errors.Is(c.runCtx.Err(), context.Canceled) {
		return "the caller cancelled the collection"
	}
	if c.callerDeadline {
		if c.callerBound <= 0 {
			return "stopped at the caller's deadline (already past when the collection started)"
		}
		return fmt.Sprintf("stopped at the caller's deadline (%s after the start)", c.callerBound.Round(time.Millisecond))
	}
	return fmt.Sprintf("stopped after %s", c.opts.maxDuration())
}

// stoppedBefore is what a pass asks first: when time is already up, every
// section the pass would have read gets the limit (partial: not read, not
// failed) and the pass does not run.
func (c *collection) stoppedBefore(ctx context.Context, sections ...string) bool {
	if ctx.Err() == nil && (c.budget == nil || !c.budget.expired()) {
		return false
	}
	for _, s := range sections {
		c.limit(s, "max_duration", c.stopDetail())
	}
	return true
}

func (c *collection) partial(section string, err error) {
	if c.stopping(err) {
		c.limit(section, "max_duration", c.stopDetail())
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.report.partial(section, err)
}

func (c *collection) skip(section string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.report.skip(section)
}

func (c *collection) limit(section, limit, detail string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.report.limit(section, limit, detail)
}

// note records an error without changing the section's outcome, for a pass
// that works out its outcome itself.
func (c *collection) note(section string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.report.recordError(section, err)
}

// files asks the budget for n files on behalf of section, recording the
// max_files limit (once) when it cannot grant them all.
func (c *collection) files(section string, n int) int {
	got := c.budget.take(n)
	if got < n {
		c.limit(section, "max_files", fmt.Sprintf("stopped after %d files", c.opts.maxFiles()))
	}
	return got
}

// timeUp reports whether the run's deadline has passed or its context ended,
// recording the max_duration limit for section (once) when it has.
func (c *collection) timeUp(ctx context.Context, section string) bool {
	if ctx.Err() != nil || c.budget.expired() {
		c.limit(section, "max_duration", c.stopDetail())
		return true
	}
	return false
}

// readConfig is the ONE way a pass reads a configuration file: through
// [Target.ReadText], with the keep words of the parser for product
// ([ConfigKeepWords]). A product with no keep words is refused here, before
// the target is asked anything, so a pass cannot read configuration it has no
// parser for. Redactions are not an error; the parser sees what was kept.
func (c *collection) readConfig(ctx context.Context, path string, product string) ([]byte, error) {
	keep := ConfigKeepWords(product)
	if len(keep) == 0 {
		return nil, fmt.Errorf("hostcrypto: %s: no keep words for product %q: %w", path, product, ErrNotPublic)
	}
	text, _, err := c.target.ReadText(ctx, path, keep)
	return text, err
}

// pass is one of the collector's passes.
type pass func(ctx context.Context, c *collection)

// passes are the collector's passes, in the order they run. This list is the
// ONE place the order is set (no pass registers itself), because it matters:
//
//  1. known locations (pass_known.go): each platform's table of places;
//  2. the platform (pass_platform.go): certificate stores and keychains,
//     disk encryption, TPM, Secure Boot, FIPS mode, tokens, libraries;
//  3. following the configuration (pass_config.go), which also hands the
//     files passes 1 and 2 found to the registry;
//  4. the running system (pass_running.go), which adds its sightings to
//     what is already registered, so it runs after the configuration;
//  5. the sweep (pass_sweep.go), last: it only adds what nothing else found.
var passes = []pass{passKnownLocations, platPass, passFollowConfiguration, platRunningPass, passSweep}

// newReport starts a Report for opts: timestamp, mode, platform, the agent id
// in local mode only, the scope asked for, and an empty Sections map.
func newReport(opts Options) *Report {
	rep := &Report{
		Collected: opts.now(),
		Mode:      opts.Mode,
		Platform:  opts.Platform,
		Sections:  make(map[string]string),
		Scope: Scope{
			HomeDirectories:          opts.HomeDirectories,
			DefaultKeystorePasswords: opts.DefaultKeystorePasswords,
			ExcludedPaths:            sortedCopy(opts.ExcludePaths),
			SweepRoots:               sortedCopy(opts.SweepRoots),
		},
	}
	if opts.Mode == hostinventory.ModeLocal {
		rep.AgentID = opts.AgentID
	}
	return rep
}

func sortedCopy(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

// Collect runs every registered pass against t and returns the Report.
//
// It returns an error only when nothing could be established: no target, a
// mode that contradicts the target, a platform it cannot detect or does not
// know. Everything else is a section outcome in the Report.
//
// A section absent from Report.Sections means no pass has claimed it yet. In
// this slice no pass is registered, so a Report has only "platform"; the
// passes mark the sections they own, and a reader must treat an absent
// section like a failed one: nothing is known.
func Collect(ctx context.Context, t Target, opts Options) (*Report, error) {
	if t == nil {
		return nil, errors.New("hostcrypto: nil target")
	}
	targetMode := hostinventory.ModeRemote
	if t.Local() {
		targetMode = hostinventory.ModeLocal
	}
	switch opts.Mode {
	case "":
		opts.Mode = targetMode
	case hostinventory.ModeLocal, hostinventory.ModeRemote:
		if opts.Mode != targetMode {
			return nil, fmt.Errorf("hostcrypto: mode %q does not match the target (%s)", opts.Mode, targetMode)
		}
	default:
		return nil, fmt.Errorf("hostcrypto: unknown mode %q", opts.Mode)
	}

	// The bound that applies is the earlier of the caller's deadline and
	// MaxDuration; a limit says which.
	var callerBound time.Duration
	callerDeadline := false
	if d, ok := ctx.Deadline(); ok {
		if left := time.Until(d); left < opts.maxDuration() {
			callerBound, callerDeadline = max(left, 0), true
		}
	}
	ctx, cancel := context.WithTimeout(ctx, opts.maxDuration())
	defer cancel()

	rep := newReport(opts)
	if rep.Platform == "" {
		detected, err := hostinventory.DetectPlatform(ctx, t)
		if err != nil {
			rep.fail(SectionPlatform, err)
			return rep, fmt.Errorf("hostcrypto: could not determine the target platform: %w", err)
		}
		rep.Platform = detected
	}
	switch rep.Platform {
	case hostinventory.PlatformLinux, hostinventory.PlatformDarwin, hostinventory.PlatformWindows:
	default:
		rep.fail(SectionPlatform, fmt.Errorf("unsupported platform %q", rep.Platform))
		return rep, fmt.Errorf("hostcrypto: unsupported platform %q", rep.Platform)
	}
	rep.mark(SectionPlatform, SectionOK)
	opts.Platform = rep.Platform

	// The read bound reaches the target, so Identify's window and every read
	// honour Options.MaxFileBytes.
	if b, ok := t.(interface{ SetMaxFileBytes(int64) }); ok {
		b.SetMaxFileBytes(opts.maxFileBytes())
	}

	deadline, _ := ctx.Deadline()
	reg := newRegistry(opts.maxRecordsPerSection())
	if t.Local() {
		reg.resolve = localRealPath
	} else if rep.Platform == hostinventory.PlatformDarwin {
		// macOS's top-level links, which a local collection resolves
		// through the filesystem: a path seen as /var/... (a listing, a
		// command line) and as /private/var/... (lsof) is one file.
		for _, d := range []string{"/var", "/tmp", "/etc"} {
			reg.addLink(d, "/private"+d)
		}
	}
	c := &collection{
		target:   t,
		opts:     opts,
		report:   rep,
		registry: reg,
		budget:   newBudget(opts.maxFiles(), deadline, nil),

		runCtx:         ctx,
		callerBound:    callerBound,
		callerDeadline: callerDeadline,
	}
	for _, p := range passes {
		p(ctx, c)
	}
	c.registry.finish(rep)
	rep.jobDropPrivilegeNotes()
	rep.Collected = opts.now()
	return rep, nil
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

// foundByRank orders FoundBy values, strongest first: a running process
// holding a file beats a configuration naming it, which beats a known place,
// which beats the sweep.
func foundByRank(f string) int {
	switch f {
	case FoundByProcess:
		return 0
	case FoundByConfig:
		return 1
	case FoundByKnownLocation, FoundByPlatformStore:
		return 2
	case FoundBySweep:
		return 3
	}
	return 4
}

// mergeLocation folds a second sighting of an item into the first: the
// strongest FoundBy wins and UsedBy is the union, in first-seen order. The
// rest of the record is the first sighting's.
func mergeLocation(dst *Location, src Location) {
	if foundByRank(src.FoundBy) < foundByRank(dst.FoundBy) {
		dst.FoundBy = src.FoundBy
	}
	for _, u := range src.UsedBy {
		dup := false
		for _, have := range dst.UsedBy {
			if have == u {
				dup = true
				break
			}
		}
		if !dup {
			dst.UsedBy = append(dst.UsedBy, u)
		}
	}
}

// localRealPath resolves a local path through every symbolic link, or
// returns it unchanged when it cannot.
func localRealPath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}

// realPath is the path an item is de-duplicated on: resolved through the
// filesystem on a local target, through the links the passes have seen
// (FileInfo.LinkTarget) on a remote one, at most eight hops.
func (r *registry) realPath(p string) string {
	if p == "" {
		return p
	}
	if r.resolve != nil {
		return r.resolve(p)
	}
	if strings.HasPrefix(p, "/") {
		// A Unix path as a command line or a listing spelled it: "//" and
		// "." collapse, and a link on any component (macOS /var is
		// /private/var) is followed, as the host would.
		return r.realUnix(path.Clean(p), 0)
	}
	for i := 0; i < 8; i++ {
		t, ok := r.links[p]
		if !ok {
			break
		}
		p = t
	}
	return p
}

// realUnix follows the known links of a clean Unix path, component by
// component, at most eight hops in all.
func (r *registry) realUnix(p string, hops int) string {
	if hops >= 8 || len(r.links) == 0 {
		return p
	}
	for i := 1; i <= len(p); i++ {
		if i < len(p) && p[i] != '/' {
			continue
		}
		prefix := p[:i]
		t, ok := r.links[prefix]
		if !ok {
			continue
		}
		t = path.Clean(joinLinkTarget(prefix, t))
		return r.realUnix(path.Clean(t+p[i:]), hops+1)
	}
	return p
}

// addLink records that path is a link to target, as a remote listing
// reported it. A relative target is resolved against the link's directory,
// in the link's own separator style.
func (r *registry) addLink(linkPath, target string) {
	if linkPath == "" || target == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.links == nil {
		r.links = map[string]string{}
	}
	r.links[linkPath] = joinLinkTarget(linkPath, target)
}

// joinLinkTarget resolves a link target the way the far host would.
func joinLinkTarget(linkPath, target string) string {
	if strings.HasPrefix(target, "/") || strings.HasPrefix(target, `\`) || (len(target) > 2 && target[1] == ':') {
		return target
	}
	if strings.Contains(linkPath, `\`) && !strings.Contains(linkPath, "/") {
		i := strings.LastIndexByte(linkPath, '\\')
		return linkPath[:i+1] + target
	}
	return path.Join(path.Dir(linkPath), target)
}

// key is a Location's identity as a de-duplication key: its REAL path, so
// /etc/ssl/certs/abcd.0 and the bundle file it links to are one item.
func (r *registry) key(l Location) string {
	return r.realPath(l.Path) + "\x00" + l.Store + "\x00" + l.Container + "\x00" + l.Alias
}

// mergeInto folds a second sighting of an item into the first and keeps the
// shortest literal path it was reached by (ties: the lexically first), so the
// record names the path a person would recognise and the output is the same
// whatever order the passes ran in.
func mergeInto(dst *Location, src Location) {
	mergeLocation(dst, src)
	if src.Path != "" && (len(src.Path) < len(dst.Path) || len(src.Path) == len(dst.Path) && src.Path < dst.Path) {
		dst.Path = src.Path
	}
}

// keyed is one section's items, by key, in first-seen order.
type keyed[T any] struct {
	index map[string]int
	items []T
}

func (k *keyed[T]) get(key string) (*T, bool) {
	if k.index == nil {
		return nil, false
	}
	i, ok := k.index[key]
	if !ok {
		return nil, false
	}
	return &k.items[i], true
}

func (k *keyed[T]) put(key string, v T) {
	if k.index == nil {
		k.index = map[string]int{}
	}
	k.index[key] = len(k.items)
	k.items = append(k.items, v)
}

// registry de-duplicates what the passes find. The same certificate is often
// reached three ways (the trust directory, the nginx configuration that names
// it, the process holding it open); it is ONE item whose Location says the
// strongest way and lists every user.
//
// It enforces MaxRecordsPerSection: past the bound a NEW item is dropped and
// the section records a max_records limit once; a sighting of an item already
// held is still merged. It is safe for concurrent use.
type registry struct {
	mu         sync.Mutex
	maxRecords int

	certs     keyed[Certificate]
	keys      keyed[PrivateKey]
	keystores keyed[Keystore]
	configs   keyed[CryptoConfig]
	libraries keyed[CryptoLibrary]
	authKeys  keyed[AuthorizedKeysFile]
	known     keyed[KnownHostsFile]
	hostKeys  keyed[SSHPublicKey]

	// sshCount is the SSH section's combined count: authorized keys files,
	// known hosts files and host public keys share one bound.
	sshCount int
	// limited records which sections hit the bound, for finish.
	limited map[string]bool

	// resolve, when set, resolves a path to its real path (a local target);
	// otherwise links (from remote listings) are followed.
	resolve func(string) string
	links   map[string]string
}

func newRegistry(maxRecords int) *registry {
	if maxRecords <= 0 {
		maxRecords = defaultMaxRecordsPerSection
	}
	return &registry{maxRecords: maxRecords, limited: map[string]bool{}}
}

// admit reports whether a new item may join a section of n items.
func (r *registry) admit(section string, n int) bool {
	if n < r.maxRecords {
		return true
	}
	r.limited[section] = true
	return false
}

// addCertificate adds or merges a certificate. Key: its location and
// fingerprint, so a bundle's members and a store's entries stay distinct.
func (r *registry) addCertificate(c Certificate) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := r.key(c.Location) + "\x00" + c.FingerprintSHA256
	if have, ok := r.certs.get(key); ok {
		mergeInto(&have.Location, c.Location)
		// An anchor in any sighting is an anchor, whichever came first.
		if c.TrustAnchor && !have.TrustAnchor {
			*have = ksTrustAnchor(*have)
		}
		return true
	}
	if !r.admit(SectionCertificates, len(r.certs.items)) {
		return false
	}
	r.certs.put(key, c)
	return true
}

// addPrivateKey adds or merges a private key. Key: its location and public
// key hash.
func (r *registry) addPrivateKey(k PrivateKey) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := r.key(k.Location) + "\x00" + k.PublicKeySHA256 + "\x00" + k.SSHFingerprint
	if have, ok := r.keys.get(key); ok {
		mergeInto(&have.Location, k.Location)
		return true
	}
	if !r.admit(SectionPrivateKeys, len(r.keys.items)) {
		return false
	}
	r.keys.put(key, k)
	return true
}

// addKeystore adds or merges a keystore. Key: its location.
func (r *registry) addKeystore(k Keystore) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := r.key(k.Location)
	if have, ok := r.keystores.get(key); ok {
		mergeInto(&have.Location, k.Location)
		return true
	}
	if !r.admit(SectionKeystores, len(r.keystores.items)) {
		return false
	}
	r.keystores.put(key, k)
	return true
}

// addConfig adds or merges a configuration. Key: location, product, context,
// so one file read for two products (or two nginx server blocks) stays two.
func (r *registry) addConfig(cfg CryptoConfig) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := r.key(cfg.Location) + "\x00" + cfg.Product + "\x00" + cfg.Context
	if have, ok := r.configs.get(key); ok {
		mergeInto(&have.Location, cfg.Location)
		return true
	}
	if !r.admit(SectionConfigs, len(r.configs.items)) {
		return false
	}
	r.configs.put(key, cfg)
	return true
}

// addLibrary adds or merges a library. Key: name, path, version, package;
// LoadedBy is merged.
func (r *registry) addLibrary(l CryptoLibrary) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := l.Name + "\x00" + l.Path + "\x00" + l.Version + "\x00" + l.Package
	if have, ok := r.libraries.get(key); ok {
		have.LoadedBy = unionStrings(have.LoadedBy, l.LoadedBy)
		if have.Source != "process" && l.Source == "process" {
			have.Source = l.Source
		}
		return true
	}
	if !r.admit(SectionLibraries, len(r.libraries.items)) {
		return false
	}
	l.LoadedBy = unionStrings(nil, l.LoadedBy)
	r.libraries.put(key, l)
	return true
}

// addAuthorizedKeys adds or merges an authorized_keys file. Key: location.
func (r *registry) addAuthorizedKeys(a AuthorizedKeysFile) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := r.key(a.Location)
	if have, ok := r.authKeys.get(key); ok {
		mergeInto(&have.Location, a.Location)
		return true
	}
	if !r.admit(SectionSSH, r.sshCount) {
		return false
	}
	r.sshCount++
	r.authKeys.put(key, a)
	return true
}

// addKnownHosts adds or merges a known_hosts file. Key: location.
func (r *registry) addKnownHosts(k KnownHostsFile) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := r.key(k.Location)
	if have, ok := r.known.get(key); ok {
		mergeInto(&have.Location, k.Location)
		return true
	}
	if !r.admit(SectionSSH, r.sshCount) {
		return false
	}
	r.sshCount++
	r.known.put(key, k)
	return true
}

// addHostPublicKey adds a host key's public half. Key: fingerprint.
func (r *registry) addHostPublicKey(k SSHPublicKey) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := k.Algorithm + "\x00" + k.Fingerprint
	if _, ok := r.hostKeys.get(key); ok {
		return true
	}
	if !r.admit(SectionSSH, r.sshCount) {
		return false
	}
	r.sshCount++
	r.hostKeys.put(key, k)
	return true
}

func unionStrings(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range append(append([]string(nil), a...), b...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

// locLess orders two locations by path, then store, container and alias.
func locLess(a, b Location) (less, equal bool) {
	for _, p := range [][2]string{{a.Path, b.Path}, {a.Store, b.Store}, {a.Container, b.Container}, {a.Alias, b.Alias}} {
		if p[0] != p[1] {
			return p[0] < p[1], false
		}
	}
	return false, true
}

// sortUsage orders UsedBy so a golden Report is byte-stable whatever order
// the passes ran in.
func sortUsage(u []Usage) {
	sort.SliceStable(u, func(i, j int) bool {
		a, b := u[i], u[j]
		switch {
		case a.Kind != b.Kind:
			return a.Kind < b.Kind
		case a.ConfigPath != b.ConfigPath:
			return a.ConfigPath < b.ConfigPath
		case a.RootConfigPath != b.RootConfigPath:
			return a.RootConfigPath < b.RootConfigPath
		case a.Directive != b.Directive:
			return a.Directive < b.Directive
		case a.Product != b.Product:
			return a.Product < b.Product
		case a.Context != b.Context:
			return a.Context < b.Context
		case a.Process != b.Process:
			return a.Process < b.Process
		case a.Address != b.Address:
			return a.Address < b.Address
		case a.Port != b.Port:
			return a.Port < b.Port
		}
		return a.Transport < b.Transport
	})
}

// finish writes the registry into rep as sorted, deterministic slices, and
// records max_records for every section that hit the bound.
func (r *registry) finish(rep *Report) {
	r.mu.Lock()
	defer r.mu.Unlock()

	certs := append([]Certificate(nil), r.certs.items...)
	sort.SliceStable(certs, func(i, j int) bool {
		if less, eq := locLess(certs[i].Location, certs[j].Location); !eq {
			return less
		}
		return certs[i].FingerprintSHA256 < certs[j].FingerprintSHA256
	})
	for i := range certs {
		sortUsage(certs[i].Location.UsedBy)
	}
	rep.Certificates = certs

	keys := append([]PrivateKey(nil), r.keys.items...)
	sort.SliceStable(keys, func(i, j int) bool {
		if less, eq := locLess(keys[i].Location, keys[j].Location); !eq {
			return less
		}
		if keys[i].PublicKeySHA256 != keys[j].PublicKeySHA256 {
			return keys[i].PublicKeySHA256 < keys[j].PublicKeySHA256
		}
		return keys[i].SSHFingerprint < keys[j].SSHFingerprint
	})
	for i := range keys {
		sortUsage(keys[i].Location.UsedBy)
	}
	rep.PrivateKeys = keys

	stores := append([]Keystore(nil), r.keystores.items...)
	sort.SliceStable(stores, func(i, j int) bool {
		less, _ := locLess(stores[i].Location, stores[j].Location)
		return less
	})
	for i := range stores {
		sortUsage(stores[i].Location.UsedBy)
	}
	rep.Keystores = stores

	configs := append([]CryptoConfig(nil), r.configs.items...)
	sort.SliceStable(configs, func(i, j int) bool {
		if less, eq := locLess(configs[i].Location, configs[j].Location); !eq {
			return less
		}
		if configs[i].Product != configs[j].Product {
			return configs[i].Product < configs[j].Product
		}
		return configs[i].Context < configs[j].Context
	})
	for i := range configs {
		sortUsage(configs[i].Location.UsedBy)
	}
	rep.Configs = configs

	libs := append([]CryptoLibrary(nil), r.libraries.items...)
	sort.SliceStable(libs, func(i, j int) bool {
		a, b := libs[i], libs[j]
		switch {
		case a.Name != b.Name:
			return a.Name < b.Name
		case a.Path != b.Path:
			return a.Path < b.Path
		case a.Version != b.Version:
			return a.Version < b.Version
		}
		return a.Package < b.Package
	})
	rep.Libraries = libs

	auth := append([]AuthorizedKeysFile(nil), r.authKeys.items...)
	sort.SliceStable(auth, func(i, j int) bool {
		less, _ := locLess(auth[i].Location, auth[j].Location)
		return less
	})
	rep.SSH.AuthorizedKeys = auth

	known := append([]KnownHostsFile(nil), r.known.items...)
	sort.SliceStable(known, func(i, j int) bool {
		less, _ := locLess(known[i].Location, known[j].Location)
		return less
	})
	rep.SSH.KnownHosts = known

	hk := append([]SSHPublicKey(nil), r.hostKeys.items...)
	sort.SliceStable(hk, func(i, j int) bool {
		if hk[i].Algorithm != hk[j].Algorithm {
			return hk[i].Algorithm < hk[j].Algorithm
		}
		return hk[i].Fingerprint < hk[j].Fingerprint
	})
	rep.SSH.HostPublicKeys = hk

	sections := make([]string, 0, len(r.limited))
	for s := range r.limited {
		sections = append(sections, s)
	}
	sort.Strings(sections)
	for _, s := range sections {
		rep.limit(s, "max_records", fmt.Sprintf("kept the first %d records", r.maxRecords))
	}

	sort.SliceStable(rep.Limits, func(i, j int) bool {
		if rep.Limits[i].Section != rep.Limits[j].Section {
			return rep.Limits[i].Section < rep.Limits[j].Section
		}
		return rep.Limits[i].Limit < rep.Limits[j].Limit
	})
	sort.SliceStable(rep.Errors, func(i, j int) bool { return rep.Errors[i].Step < rep.Errors[j].Step })
}
