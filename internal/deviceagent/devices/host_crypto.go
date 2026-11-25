package devices

import (
	"context"
	"errors"
	"fmt"
	"math"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform-agents/internal/deviceagent/models"
	"github.com/vistasecurity/vistaplatform-agents/internal/deviceagent/security"
	"github.com/vistasecurity/vistaplatform-agents/shared/agentconfig"
	"github.com/vistasecurity/vistaplatform-agents/shared/hostcrypto"
	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
	"github.com/vistasecurity/vistaplatform-agents/shared/redact"
)

// Host crypto inventory (docs/host-crypto.md), in the agent.
//
// Three ways in, one collector (shared/hostcrypto), one at a time:
//
//   - the LOCAL schedule (cmd/device-agent, setting host_crypto_enabled),
//     which has no job and posts to its own intake, as host inventory does;
//   - a `host_crypto` job with mode "local": the platform asking for a
//     collection of the agent's own host now, rather than at the next tick;
//   - a `host_crypto` job with mode "remote": another host, reached over SSH
//     with the job's sealed credentials, exactly as a remote host_inventory
//     job reaches it (buildRemoteRunner: the same parameters, the same
//     shared/sshtrust host-key policy, the same refusal of WinRM).
//
// Unlike host inventory, a local job is run rather than refused. A host
// inventory local job would have nowhere to land; a host crypto job always
// lands in its own result, and "collect now" is a request an operator
// reasonably makes after changing a host.

// JobTypeHostCrypto is the job type the platform queues for a collection.
const JobTypeHostCrypto = hostcrypto.JobTypeHostCrypto

// The agent's own maxima for a job's bounds: the published maxima of
// schemas/managed/v1/defs/host-crypto-job.json. A larger value is lowered to
// the maximum, never refused, so an operator who asks for "as much as
// possible" gets that; a value that is not a positive whole number is refused.
const (
	HostCryptoMaxFiles             = 1_000_000
	HostCryptoMaxFileBytes         = 64 << 20
	HostCryptoMaxRecordsPerSection = 10_000
	HostCryptoMaxDuration          = time.Hour
	HostCryptoMinDuration          = time.Minute
	HostCryptoMaxExcludePaths      = agentconfig.MaxPathListEntries
	HostCryptoMaxSweepRoots        = 16
)

// hostCryptoDefaultDuration is the collector's own default run bound, used to
// size a job's timeout when the job names none.
const hostCryptoDefaultDuration = 15 * time.Minute

// hostCryptoJobMargin is added to a job's run bound for its overall timeout:
// the SSH dial and the result's submission happen outside the collector's
// own clock.
const hostCryptoJobMargin = 2 * time.Minute

// hostCryptoOptionKeys are the options a job may carry. Closed: an option
// this build does not know is refused, because silently ignoring one (an
// exclusion, say) would run a collection the operator did not ask for.
var hostCryptoOptionKeys = map[string]bool{
	"home_directories":           true,
	"default_keystore_passwords": true,
	"exclude_paths":              true,
	"sweep_roots":                true,
	"max_files":                  true,
	"max_file_bytes":             true,
	"max_records_per_section":    true,
	"max_duration_seconds":       true,
}

// HostCryptoJob is a host_crypto job's parameters, read and checked.
type HostCryptoJob struct {
	Mode hostinventory.Mode
	// Options are the collector's options. Mode, Platform and AgentID are
	// set by the collection that runs them, not here.
	Options hostcrypto.Options
	// Lowered names each bound that was above its maximum and was lowered.
	Lowered []string
}

// ParseHostCryptoJob reads a host_crypto job's parameters.
func ParseHostCryptoJob(params map[string]interface{}) (HostCryptoJob, error) {
	var job HostCryptoJob
	switch mode := hostinventory.Mode(strings.ToLower(paramString(params, "mode"))); mode {
	case hostinventory.ModeLocal, hostinventory.ModeRemote:
		job.Mode = mode
	case "":
		return job, errors.New(`host_crypto jobs must set parameters.mode to "local" or "remote"`)
	default:
		return job, fmt.Errorf("unknown host crypto mode %q", mode)
	}
	raw, present := params["options"]
	if !present || raw == nil {
		return job, nil
	}
	opts, ok := raw.(map[string]interface{})
	if !ok {
		return job, errors.New("parameters.options must be an object")
	}
	var err error
	job.Options, job.Lowered, err = ParseHostCryptoOptions(opts)
	return job, err
}

// ParseHostCryptoOptions reads a job's options into the collector's.
func ParseHostCryptoOptions(opts map[string]interface{}) (hostcrypto.Options, []string, error) {
	var out hostcrypto.Options
	var lowered, unknown []string
	for k := range opts {
		if !hostCryptoOptionKeys[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return out, nil, fmt.Errorf("unknown host crypto option(s): %s", strings.Join(unknown, ", "))
	}
	var err error
	if out.HomeDirectories, err = hostCryptoBool(opts, "home_directories"); err != nil {
		return out, nil, err
	}
	if out.DefaultKeystorePasswords, err = hostCryptoBool(opts, "default_keystore_passwords"); err != nil {
		return out, nil, err
	}
	if out.ExcludePaths, err = hostCryptoPaths(opts, "exclude_paths", HostCryptoMaxExcludePaths); err != nil {
		return out, nil, err
	}
	if out.SweepRoots, err = hostCryptoPaths(opts, "sweep_roots", HostCryptoMaxSweepRoots); err != nil {
		return out, nil, err
	}
	n, low, err := hostCryptoBound(opts, "max_files", HostCryptoMaxFiles)
	if err != nil {
		return out, nil, err
	}
	out.MaxFiles, lowered = int(n), appendIf(lowered, low, "max_files")
	if n, low, err = hostCryptoBound(opts, "max_file_bytes", HostCryptoMaxFileBytes); err != nil {
		return out, nil, err
	}
	out.MaxFileBytes, lowered = n, appendIf(lowered, low, "max_file_bytes")
	if n, low, err = hostCryptoBound(opts, "max_records_per_section", HostCryptoMaxRecordsPerSection); err != nil {
		return out, nil, err
	}
	out.MaxRecordsPerSection, lowered = int(n), appendIf(lowered, low, "max_records_per_section")
	if n, low, err = hostCryptoBound(opts, "max_duration_seconds", int64(HostCryptoMaxDuration/time.Second)); err != nil {
		return out, nil, err
	}
	if n > 0 {
		d := time.Duration(n) * time.Second
		if d < HostCryptoMinDuration {
			// Raised rather than refused, like every interval floor here: a
			// run bound under a minute ends a remote collection before its
			// first pass.
			d, low = HostCryptoMinDuration, true
		}
		out.MaxDuration = d
	}
	lowered = appendIf(lowered, low, "max_duration_seconds")
	return out, lowered, nil
}

func appendIf(list []string, cond bool, s string) []string {
	if cond {
		return append(list, s)
	}
	return list
}

func hostCryptoBool(opts map[string]interface{}, key string) (bool, error) {
	v, ok := opts[key]
	if !ok || v == nil {
		return false, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("option %s must be true or false", key)
	}
	return b, nil
}

// hostCryptoPaths reads a list of absolute paths under the one path rule
// (agentconfig.CheckPath), refusing the whole list for one bad entry.
func hostCryptoPaths(opts map[string]interface{}, key string, max int) ([]string, error) {
	v, ok := opts[key]
	if !ok || v == nil {
		return nil, nil
	}
	list, ok := v.([]interface{})
	if !ok {
		return nil, fmt.Errorf("option %s must be a list of paths", key)
	}
	if len(list) > max {
		return nil, fmt.Errorf("option %s lists %d paths; at most %d are allowed", key, len(list), max)
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("option %s must be a list of paths", key)
		}
		if problem := agentconfig.CheckPath(s); problem != "" {
			return nil, fmt.Errorf("option %s: %s", key, problem)
		}
		out = append(out, s)
	}
	return out, nil
}

// hostCryptoBound reads a positive whole number, lowering it to max.
func hostCryptoBound(opts map[string]interface{}, key string, max int64) (int64, bool, error) {
	v, ok := opts[key]
	if !ok || v == nil {
		return 0, false, nil
	}
	f, ok := v.(float64)
	if !ok || f != math.Trunc(f) || f < 1 {
		return 0, false, fmt.Errorf("option %s must be a positive whole number", key)
	}
	if f > float64(max) {
		return max, true, nil
	}
	return int64(f), false, nil
}

// hostCryptoJobTimeout is the overall bound of a host_crypto job that names
// no timeout_seconds: its run bound plus a margin. DefaultJobTimeout (five
// minutes) would end a collection whose own bound is fifteen.
func hostCryptoJobTimeout(params map[string]interface{}) time.Duration {
	d := hostCryptoDefaultDuration
	if job, err := ParseHostCryptoJob(params); err == nil && job.Options.MaxDuration > 0 {
		d = job.Options.MaxDuration
	}
	return d + hostCryptoJobMargin
}

// ---------------------------------------------------------------------------
// One collection at a time
// ---------------------------------------------------------------------------

// hostCryptoSlot admits one collection per process. Two collections on one
// host compete for the same disk for no gain, and a remote job beside a
// local one would double the agent's footprint at the moment it is busiest.
var hostCryptoSlot = make(chan struct{}, 1)

// ErrHostCryptoBusy is returned when a collection could not start because
// another was running until ctx ended.
var ErrHostCryptoBusy = errors.New("another host crypto collection is running")

// acquireHostCrypto waits for the slot until ctx ends. A free slot is taken
// even when ctx has already ended, so a collection cancelled before it began
// still runs its (immediately cut) passes and reports what it could, rather
// than racing the two ready cases.
func acquireHostCrypto(ctx context.Context) (func(), error) {
	if release, ok := TryAcquireHostCrypto(); ok {
		return release, nil
	}
	select {
	case hostCryptoSlot <- struct{}{}:
		return func() { <-hostCryptoSlot }, nil
	case <-ctx.Done():
		return nil, ErrHostCryptoBusy
	}
}

// TryAcquireHostCrypto takes the slot only if it is free: the schedule skips
// a cycle rather than queue behind a job.
func TryAcquireHostCrypto() (func(), bool) {
	select {
	case hostCryptoSlot <- struct{}{}:
		return func() { <-hostCryptoSlot }, true
	default:
		return nil, false
	}
}

// ---------------------------------------------------------------------------
// Collections
// ---------------------------------------------------------------------------

// CollectLocalHostCrypto collects the host the agent runs on. The caller
// holds the slot (TryAcquireHostCrypto) or is a standalone run.
func CollectLocalHostCrypto(ctx context.Context, agentID string, opts hostcrypto.Options) (*hostcrypto.Report, error) {
	opts.Mode = hostinventory.ModeLocal
	opts.AgentID = agentID
	// The agent's own platform: asking the host with uname, as a remote
	// collection must, would only add a way to fail.
	opts.Platform = runtime.GOOS
	return hostcrypto.Collect(ctx, hostcrypto.NewLocalTarget(), opts)
}

// CollectRemoteHostCrypto collects the host runner reaches. The platform is
// asked of the host first (uname, else PowerShell), because which target
// speaks to it — POSIX tools or PowerShell — depends on the answer. The
// agent id is never stamped: the agent is not the host described.
func CollectRemoteHostCrypto(ctx context.Context, runner hostinventory.Runner, opts hostcrypto.Options) (*hostcrypto.Report, error) {
	platform, err := hostinventory.DetectPlatform(ctx, runner)
	if err != nil {
		return nil, fmt.Errorf("could not determine the remote host's platform: %w", err)
	}
	var target hostcrypto.Target
	switch platform {
	case hostinventory.PlatformWindows:
		if _, ok := runner.(hostinventory.InputRunner); !ok {
			// The Windows target sends its scripts on standard input; a
			// runner that cannot would push them through cmd.exe's 8,191
			// characters instead. Refuse rather than collect less.
			return nil, errors.New("the transport cannot send a script on standard input, which a Windows host needs")
		}
		target = hostcrypto.NewRemoteWindowsTarget(runner)
	case hostinventory.PlatformLinux, hostinventory.PlatformDarwin:
		target = hostcrypto.NewRemoteUnixTarget(runner, platform)
	default:
		return nil, fmt.Errorf("unsupported remote platform %q", platform)
	}
	opts.Mode = hostinventory.ModeRemote
	opts.Platform = platform
	opts.AgentID = ""
	return hostcrypto.Collect(ctx, target, opts)
}

// ---------------------------------------------------------------------------
// The job
// ---------------------------------------------------------------------------

// SetShutdown hands the executor the agent's lifetime: when ctx ends, a host
// crypto collection in flight is cancelled and what it had is reported as a
// partial result. Jobs otherwise run on a context detached from the
// lifetime, so a short job's result is not lost to a shutdown; a collection
// of up to an hour is the exception, because the agent's stop grace is
// thirty seconds.
func (e *JobExecutor) SetShutdown(ctx context.Context) { e.shutdown = ctx }

// SetHostCryptoExcludes hands the executor the operator's
// host_crypto_exclude_paths setting. Its paths are added to every job's own
// exclude_paths, local and remote alike (on a remote host they are paths on
// that host): an operator's "never enter" binds every collection this agent
// makes, not only the scheduled one.
func (e *JobExecutor) SetHostCryptoExcludes(f func() []string) { e.hostCryptoExcludes = f }

// SetHostCryptoConsents hands the executor the agent's CONFIRMED opt-ins.
// A job may ask for less, never for more: a queued job is a person's
// request for a collection, not a consent the platform confirmed.
func (e *JobExecutor) SetHostCryptoConsents(f func() (homeDirectories, defaultKeystorePasswords bool)) {
	e.hostCryptoConsents = f
}

// clampHostCryptoConsents lowers a job's opt-ins to the confirmed ones and
// names each one it lowered.
func clampHostCryptoConsents(o *hostcrypto.Options, consents func() (bool, bool)) []string {
	home, defaults := false, false
	if consents != nil {
		home, defaults = consents()
	}
	var clamped []string
	if o.HomeDirectories && !home {
		o.HomeDirectories = false
		clamped = append(clamped, "home_directories")
	}
	if o.DefaultKeystorePasswords && !defaults {
		o.DefaultKeystorePasswords = false
		clamped = append(clamped, "default_keystore_passwords")
	}
	return clamped
}

// MergeHostCryptoExcludes returns the job's exclusions with the setting's
// added, each once, in the job's order and then the setting's.
func MergeHostCryptoExcludes(job, setting []string) []string {
	if len(setting) == 0 {
		return job
	}
	seen := make(map[string]bool, len(job)+len(setting))
	out := make([]string, 0, len(job)+len(setting))
	for _, list := range [][]string{job, setting} {
		for _, p := range list {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// executeHostCrypto runs a host_crypto job.
func (e *JobExecutor) executeHostCrypto(parent context.Context, job *models.Job) error {
	if e.negotiated != nil && !e.negotiated(hostcrypto.CapabilityHostCrypto) {
		return e.submitUnsupported(job, "the platform did not negotiate "+hostcrypto.CapabilityHostCrypto+" with this agent")
	}
	params, err := ParseHostCryptoJob(job.Parameters)
	if err != nil {
		return e.submitFailure(job, err.Error())
	}
	if e.hostCryptoExcludes != nil {
		params.Options.ExcludePaths = MergeHostCryptoExcludes(params.Options.ExcludePaths, e.hostCryptoExcludes())
	}
	clamped := clampHostCryptoConsents(&params.Options, e.hostCryptoConsents)

	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	if e.shutdown != nil {
		stop := context.AfterFunc(e.shutdown, cancel)
		defer stop()
	}

	release, err := acquireHostCrypto(ctx)
	if err != nil {
		return e.submitFailure(job, err.Error())
	}
	defer release()

	target := "this host"
	var hostKey map[string]interface{}
	var rep *hostcrypto.Report
	var collectErr error
	switch params.Mode {
	case hostinventory.ModeLocal:
		rep, collectErr = CollectLocalHostCrypto(ctx, e.config.AgentID, params.Options)
	case hostinventory.ModeRemote:
		target = paramString(job.Parameters, "ip_address")
		if target == "" {
			target = paramString(job.Parameters, "hostname")
		}
		transport, err := hostinventory.ParseTransport(paramString(job.Parameters, "transport"))
		if err != nil {
			return e.submitFailure(job, err.Error())
		}
		decrypted, err := security.DecryptCredentials(job.Credentials, job.ID.String(), e.config.CredentialSecrets()...)
		if err != nil {
			return e.submitFailure(job, fmt.Sprintf("Failed to decrypt credentials: %v", err))
		}
		dial := e.dialRemote
		if dial == nil {
			dial = buildRemoteRunner
		}
		runner, err := dial(transport, job.Parameters, decrypted)
		if err != nil {
			security.ClearCredentials(decrypted)
			return e.submitFailure(job, fmt.Sprintf("Could not reach the target: %v", err))
		}
		// The session is authenticated; the credentials are done with.
		security.ClearCredentials(decrypted)
		hostKey = hostCryptoHostKey(runner)
		rep, collectErr = CollectRemoteHostCrypto(ctx, runner, params.Options)
		if closer, ok := runner.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
	}
	stopped := e.shutdown != nil && e.shutdown.Err() != nil
	if rep != nil {
		for _, opt := range clamped {
			// The scope already reads false for it; this says why.
			rep.Errors = append(rep.Errors, hostcrypto.StepError{Step: "scope",
				Message: opt + " was asked for by the job but is not confirmed for this agent; not collected"})
		}
	}
	if e.auditLogger != nil {
		outcome, details := "success", map[string]interface{}{"job_type": job.Type, "mode": string(params.Mode)}
		if rep != nil {
			details["platform"] = rep.Platform
			details["certificates"] = len(rep.Certificates)
			details["private_keys"] = len(rep.PrivateKeys)
		}
		if len(params.Lowered) > 0 {
			details["bounds_lowered"] = strings.Join(params.Lowered, ",")
		}
		if collectErr != nil || stopped {
			outcome = "failure"
		}
		e.auditLogger.LogInterrogation(job.ID.String(), target, JobTypeHostCrypto, outcome, details, collectErr)
	}
	res := HostCryptoJobResult(job, rep, collectErr, stopped)
	if len(hostKey) > 0 {
		res.Metadata = hostKey
	}
	return e.submitter.SubmitResult(res)
}

// hostKeyReporter is a transport that knows the SSH host key it connected
// through (a test's fake transport implements it).
type hostKeyReporter interface {
	HostKeyInfo() (fingerprint, keyType, verification string)
}

// hostCryptoHostKey is the host key a remote collection connected through and
// how it was trusted ("pinned", "known_hosts", "first_use", "skipped"), under
// the metadata names the device-interrogation results already use
// (ssh_host_key_fingerprint, ssh_host_key_verification) plus its type. With
// them the platform can record the key a first-use connection saw and pin
// it for the next job; without them every unpinned job would stay
// trust-on-first-use with nobody told which key was trusted.
func hostCryptoHostKey(r hostinventory.Runner) map[string]interface{} {
	var fp, typ, how string
	switch t := r.(type) {
	case *hostinventory.SSHRunner:
		fp, typ, how = t.HostKeyFingerprint, t.HostKeyType, t.HostKeyVerified
	case hostKeyReporter:
		fp, typ, how = t.HostKeyInfo()
	default:
		return nil
	}
	if fp == "" {
		return nil
	}
	m := map[string]interface{}{"ssh_host_key_fingerprint": fp}
	if typ != "" {
		m["ssh_host_key_type"] = typ
	}
	if how != "" {
		m["ssh_host_key_verification"] = how
	}
	return m
}

// HostCryptoJobResult is the result a host_crypto job sends.
//
// A collection that produced a report sends it, whether or not the
// collection failed as a whole: a report whose platform section failed, or
// one cut short by a shutdown, still says which sections were read, and a
// failure that throws that away tells the operator less than the agent
// knows. success is true only for a collection that ran to its end; its
// sections then say how much of the host it saw.
func HostCryptoJobResult(job *models.Job, rep *hostcrypto.Report, collectErr error, stopped bool) *models.JobResult {
	failure := func(msg string) *models.JobResult {
		return &models.JobResult{JobID: job.ID, Success: false, Error: redact.Text(msg), CompletedAt: time.Now()}
	}
	if rep == nil {
		if collectErr == nil {
			collectErr = errors.New("the collector returned no report")
		}
		return failure("Host crypto inventory failed: " + collectErr.Error())
	}
	payload, _, err := hostcrypto.ResultPayload(rep, hostcrypto.DefaultMaxResultBytes)
	if err != nil {
		// Nothing of the report is sent: ErrKeyMaterial must never be
		// answered by sending the report anyway.
		return failure("Host crypto inventory could not be sent: " + err.Error())
	}
	res := &models.JobResult{JobID: job.ID, Success: true, HostCrypto: payload, CompletedAt: time.Now()}
	switch {
	case stopped:
		res.Success = false
		res.Error = "the agent stopped before the collection finished; the report is partial"
	case collectErr != nil:
		res.Success = false
		res.Error = redact.Text("Host crypto inventory failed: " + collectErr.Error())
	}
	return res
}
