package main

// The LOCAL host crypto inventory schedule (docs/host-crypto.md), beside the
// host inventory one and built the same way: a supervisor the control plane
// turns on and off, a cadence it can change while a wait is in flight, a
// floor the agent enforces itself, and jitter that only ever adds. What is
// different is that the settings it collects WITH (the two opt-ins and the
// excluded paths) are read at the start of every collection, so a change
// applies to the next one without restarting the loop.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vistasecurity/vistaplatform-agents/internal/deviceagent/api"
	"github.com/vistasecurity/vistaplatform-agents/internal/deviceagent/config"
	"github.com/vistasecurity/vistaplatform-agents/internal/deviceagent/devices"
	"github.com/vistasecurity/vistaplatform-agents/shared/agentconfig"
	"github.com/vistasecurity/vistaplatform-agents/shared/agentconfig/desiredstate"
	"github.com/vistasecurity/vistaplatform-agents/shared/hostcrypto"
)

// hostCryptoSettings are what a scheduled collection is made with.
type hostCryptoSettings struct {
	homeDirectories          bool
	defaultKeystorePasswords bool
	excludePaths             []string
	sweepRoots               []string
}

// hostCryptoSupervisor starts and stops the local loop as the platform turns
// it on and off, and holds the settings the loop reads.
type hostCryptoSupervisor struct {
	mu       sync.Mutex
	run      func(iv *interval, stop <-chan struct{})
	iv       *interval
	stop     chan struct{}
	enabled  bool
	interval time.Duration
	settings hostCryptoSettings
}

func newHostCryptoSupervisor(interval time.Duration, settings hostCryptoSettings, run func(iv *interval, stop <-chan struct{})) *hostCryptoSupervisor {
	if interval <= 0 {
		interval = config.DefaultHostCryptoInterval
	}
	return &hostCryptoSupervisor{run: run, interval: interval, settings: settings}
}

// setEnabled starts or stops the loop; idempotent, as the platform re-sends
// the whole desired state on every beat. Stopping cancels a collection in
// flight: an agent told to stop reading its host's key files stops now.
func (s *hostCryptoSupervisor) setEnabled(on bool) error {
	return s.setEnabledBecause(on, "")
}

// shutdown stops the loop because the agent is stopping, and says so.
func (s *hostCryptoSupervisor) shutdown() error {
	return s.setEnabledBecause(false, "because the agent is stopping")
}

func (s *hostCryptoSupervisor) setEnabledBecause(on bool, why string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if on == s.enabled {
		return nil
	}
	s.enabled = on
	if !on {
		if s.stop != nil {
			close(s.stop)
			s.stop = nil
		}
		if why == "" {
			why = "by the agent's settings"
		}
		log.Printf("🔐 Host crypto inventory stopped %s", why)
		return nil
	}
	if s.run == nil {
		return fmt.Errorf("this agent cannot collect host crypto inventory")
	}
	s.iv = newInterval(s.interval)
	s.stop = make(chan struct{})
	// No interval here: until the platform's settings arrive the one held is
	// the file's (or the default), and the loop names the one it waits.
	log.Printf("🔐 Host crypto inventory on; it collects once the platform's settings have arrived")
	if devices.HostCryptoInContainer() {
		log.Printf("🔐 Note: this agent runs in a Kubernetes pod, so a local host crypto collection describes the container, not the node")
	}
	go s.run(s.iv, s.stop)
	return nil
}

func (s *hostCryptoSupervisor) isEnabled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enabled
}

// setInterval changes the cadence. Below the floor is refused here: the
// platform raises it before storing, so only an older platform or a
// hand-made request reaches this.
func (s *hostCryptoSupervisor) setInterval(d time.Duration) error {
	if d < config.MinHostCryptoInterval {
		return fmt.Errorf("%v is below the one-hour minimum", d)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.interval = d
	if s.iv != nil {
		s.iv.set(d)
	}
	return nil
}

func (s *hostCryptoSupervisor) setHomeDirectories(on bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.settings.homeDirectories = on
	return nil
}

func (s *hostCryptoSupervisor) setDefaultKeystorePasswords(on bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.settings.defaultKeystorePasswords = on
	return nil
}

// setExcludePaths takes the canonical path list. One bad entry refuses the
// whole value, so the agent keeps the list it had rather than running with
// part of a new one.
func (s *hostCryptoSupervisor) setExcludePaths(list string) error {
	paths, problems := agentconfig.ParsePathList(list)
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.settings.excludePaths = paths
	return nil
}

// setSweepRoots takes the canonical sweep-roots list, under its own rules
// (at most 16, never a whole filesystem); a bad value keeps the old list.
func (s *hostCryptoSupervisor) setSweepRoots(list string) error {
	roots, problems := agentconfig.ParsePathFor(agentconfig.Registry[agentconfig.KeyHostCryptoSweepRoots], list)
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.settings.sweepRoots = roots
	return nil
}

// options is the collector's options for the next scheduled collection: the
// settings as they are now and every bound at the collector's default; the
// sweep covers the host_crypto_sweep_roots setting (none by default).
func (s *hostCryptoSupervisor) options() hostcrypto.Options {
	s.mu.Lock()
	defer s.mu.Unlock()
	return hostcrypto.Options{
		HomeDirectories:          s.settings.homeDirectories,
		DefaultKeystorePasswords: s.settings.defaultKeystorePasswords,
		ExcludePaths:             append([]string(nil), s.settings.excludePaths...),
		SweepRoots:               append([]string(nil), s.settings.sweepRoots...),
	}
}

// registerHostCryptoSettings wires the five host crypto settings. Each is
// registered so the platform is told when one cannot be applied, never left
// believing it was.
func registerHostCryptoSettings(applier *desiredstate.Applier, hc *hostCryptoSupervisor) {
	applier.Handle(agentconfig.KeyHostCryptoEnabled, desiredstate.BoolSetter(hc.setEnabled))
	applier.Handle(agentconfig.KeyHostCryptoInterval, desiredstate.DurationSetter(agentconfig.KeyHostCryptoInterval, hc.setInterval))
	applier.Handle(agentconfig.KeyHostCryptoHomeDirectories, desiredstate.BoolSetter(hc.setHomeDirectories))
	applier.Handle(agentconfig.KeyHostCryptoDefaultKeystorePasswords, desiredstate.BoolSetter(hc.setDefaultKeystorePasswords))
	applier.Handle(agentconfig.KeyHostCryptoExcludePaths, desiredstate.TextSetter(hc.setExcludePaths))
	applier.Handle(agentconfig.KeyHostCryptoSweepRoots, desiredstate.TextSetter(hc.setSweepRoots))
}

// hostCryptoLocalValues is what the configuration file says about host
// crypto, in the registry's keys, for localValues.
func hostCryptoLocalValues(cfg *config.Config, v agentconfig.Values) {
	v[agentconfig.KeyHostCryptoEnabled] = agentconfig.Bool(cfg.HostCryptoEnabled)
	if cfg.HostCryptoInterval > 0 {
		v[agentconfig.KeyHostCryptoInterval] = agentconfig.Int(int64(cfg.HostCryptoInterval / time.Second))
	}
	// The two consents are never reported: the device does not hold them.
	if len(cfg.HostCryptoExcludePaths) > 0 {
		v[agentconfig.KeyHostCryptoExcludePaths] = agentconfig.Text(agentconfig.FormatPathList(cfg.HostCryptoExcludePaths))
	}
	if len(cfg.HostCryptoSweepRoots) > 0 {
		v[agentconfig.KeyHostCryptoSweepRoots] = agentconfig.Text(agentconfig.FormatPathList(cfg.HostCryptoSweepRoots))
	}
}

// hostCryptoSubmitter is the slice of the API client the local loop needs.
type hostCryptoSubmitter interface {
	HostCryptoNegotiated() error
	SubmitHostCrypto(report *hostcrypto.Report) error
}

// hostCryptoCollector is the collection step, injectable so the loop can be
// driven without reading the test machine's key files.
type hostCryptoCollector func(ctx context.Context, agentID string, opts hostcrypto.Options) (*hostcrypto.Report, error)

// collectHostCrypto is the supervisor's loop for this agent.
func (a *DeviceAgent) collectHostCrypto(iv *interval, stop <-chan struct{}) {
	collect := a.hostCryptoCollector
	if collect == nil {
		collect = devices.CollectLocalHostCrypto
	}
	runLocalHostCryptoLoop(a.apiClient, a.config.AgentID, iv, stop, a.desiredStateApplied, a.hostCrypto.options, collect, config.MinHostCryptoInterval)
}

// desiredStateApplied reports whether a desired state the platform sent has
// been applied: until then the settings are the file's, and a scheduled
// collection made with them would be one the platform never confirmed.
func (a *DeviceAgent) desiredStateApplied() bool {
	if a.applier == nil {
		return false
	}
	rev, _, _ := a.applier.Report()
	return rev != ""
}

// hostCryptoReadyPoll is how often the loop looks for the first desired
// state; a variable so tests need not wait a second.
var hostCryptoReadyPoll = time.Second

// runLocalHostCryptoLoop collects at once, then on the interval, until stop
// closes. One collection at a time across the whole agent: a cycle that finds
// a job's collection running is skipped, not queued. A failure is logged and
// the next cycle tries again.
func runLocalHostCryptoLoop(sub hostCryptoSubmitter, agentID string, every *interval, stop <-chan struct{},
	ready func() bool, options func() hostcrypto.Options, collectFn hostCryptoCollector, floor time.Duration) {
	if sub == nil || options == nil || collectFn == nil || ready == nil {
		return
	}
	// No collection before the platform's first desired state is applied:
	// the opt-ins (and the switch itself) are the platform's to set.
	for !ready() {
		select {
		case <-stop:
			return
		case <-time.After(hostCryptoReadyPoll):
		}
	}
	if every == nil {
		every = newInterval(config.DefaultHostCryptoInterval)
	}
	collect := func() {
		// Nothing is collected for a platform with nowhere to put it.
		if err := sub.HostCryptoNegotiated(); err != nil {
			log.Printf("🔐 Host crypto inventory not collected: %v", err)
			return
		}
		release, ok := devices.TryAcquireHostCrypto()
		if !ok {
			log.Printf("🔐 Host crypto inventory skipped this cycle: another collection is running")
			return
		}
		defer release()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			select {
			case <-stop:
				cancel()
			case <-ctx.Done():
			}
		}()
		report, err := collectFn(ctx, agentID, options())
		select {
		case <-stop:
			// Stopped while collecting (turned off, or the agent is
			// shutting down): what was read is not sent, and the next start
			// collects afresh.
			log.Printf("🔐 Host crypto inventory stopped before it finished; nothing sent")
			return
		default:
		}
		if report == nil {
			log.Printf("⚠️  Host crypto inventory failed: %v", err)
			return
		}
		if err != nil {
			log.Printf("⚠️  Host crypto inventory did not complete: %v", err)
		}
		if err := sub.SubmitHostCrypto(report); err != nil {
			var tooLarge *api.ReportTooLargeError
			if errors.As(err, &tooLarge) {
				log.Printf("⚠️  Host crypto inventory NOT submitted: %d bytes exceeds the platform's cap. Platform said: %s",
					tooLarge.Bytes, tooLarge.Detail)
				return
			}
			log.Printf("⚠️  Host crypto inventory submission failed (retrying at the next collection): %v", err)
			return
		}
		log.Printf("🔐 Host crypto inventory submitted: %s, %d certificates, %d private keys, %d keystores, %d configurations%s",
			report.Platform, len(report.Certificates), len(report.PrivateKeys), len(report.Keystores), len(report.Configs),
			hostCryptoSectionSuffix(report))
	}

	collect()
	log.Printf("🔐 Host crypto inventory: next collection in about %v", every.get())
	for waitCycle(every, stop, func(d time.Duration) time.Duration {
		if d < floor {
			d = floor
		}
		return jitteredInterval(d)
	}) {
		collect()
	}
}

// hostCryptoSectionSuffix names the sections that did not complete, so the
// log line cannot report a partial collection as a whole one.
func hostCryptoSectionSuffix(report *hostcrypto.Report) string {
	var failed, partial []string
	for section, state := range report.Sections {
		switch state {
		case hostcrypto.SectionFailed:
			failed = append(failed, section)
		case hostcrypto.SectionPartial:
			partial = append(partial, section)
		}
	}
	sort.Strings(failed)
	sort.Strings(partial)
	var parts []string
	if len(failed) > 0 {
		parts = append(parts, "failed: "+strings.Join(failed, ", "))
	}
	if len(partial) > 0 {
		parts = append(parts, "partial: "+strings.Join(partial, ", "))
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, "; ") + ")"
}
