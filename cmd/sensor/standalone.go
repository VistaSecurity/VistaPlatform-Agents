package main

// Standalone mode (docs/design/standalone-mode.md): `crypto-sensor capture`
// and `crypto-sensor scan` run without a Vista Platform. They read no
// configuration file, register nothing, send no heartbeat and open no
// connection to a control plane; they collect what the operator named and
// write it through shared/agentoutput. Running the binary with no subcommand
// is the managed sensor, exactly as before.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/vistasecurity/vistaplatform-agents/shared/agentoutput"
	"github.com/vistasecurity/vistaplatform-agents/shared/discovery"
)

// standaloneAgent names the sensor in every standalone record.
const standaloneAgent = "crypto-sensor"

// standaloneEnv is what a standalone command reads from the process. main
// builds it from the real process; tests replace the parts they need. It is
// never configurable from the command line.
type standaloneEnv struct {
	ctx    context.Context
	stdout io.Writer
	stderr io.Writer
	// dialer is the network a scan dials (nil: the system's).
	dialer discovery.Dialer
	// lookup resolves a scan's hostname target, once (nil: the system
	// resolver).
	lookup func(ctx context.Context, host string) ([]netip.Addr, error)
}

// standaloneCommand reports whether args name a standalone subcommand.
func standaloneCommand(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "capture", "scan":
		return true
	}
	return false
}

// runStandaloneMain runs a standalone subcommand for main and returns its exit
// status. SIGINT and SIGTERM end the run early; what was seen is still
// written.
func runStandaloneMain(args []string) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runStandalone(standaloneEnv{ctx: ctx, stdout: os.Stdout, stderr: os.Stderr}, args)
}

// runStandalone dispatches args[0] (capture or scan).
func runStandalone(env standaloneEnv, args []string) int {
	if env.ctx == nil {
		env.ctx = context.Background()
	}
	if env.lookup == nil {
		env.lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	switch args[0] {
	case "capture":
		return runCapture(env, args[1:])
	case "scan":
		return runScan(env, args[1:])
	}
	_, _ = fmt.Fprintf(env.stderr, "%s: unknown command %q\n", standaloneAgent, args[0])
	return 1
}

// outputFlags are the flags every standalone command shares.
type outputFlags struct {
	out     string
	format  string
	quiet   bool
	verbose bool
}

func (o *outputFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&o.out, "out", "-", "write the output to `PATH` (created 0600, renamed into place when the run ends); - is standard output")
	fs.StringVar(&o.format, "format", "jsonl", "output format: jsonl, json or csv (csv has one row per endpoint)")
	fs.BoolVar(&o.quiet, "quiet", false, "do not print the summary on standard error")
	fs.BoolVar(&o.verbose, "verbose", false, "log the decoders' and the scan engine's diagnostics on standard error")
}

func (o *outputFlags) options(env standaloneEnv) (agentoutput.Options, error) {
	format, err := agentoutput.ParseFormat(o.format)
	if err != nil {
		return agentoutput.Options{}, err
	}
	return agentoutput.Options{
		Path: o.out, Format: format, Agent: standaloneAgent, AgentVersion: Version, Quiet: o.quiet,
		Stdout: env.stdout, Stderr: env.stderr,
	}, nil
}

// quietLogs sends the standard logger to stderr with --verbose and nowhere
// otherwise: the packages a standalone command drives log as the managed
// sensor does, and that is noise beside the summary. It returns the restore.
func (o *outputFlags) quietLogs(env standaloneEnv) func() {
	prev := log.Writer()
	if o.verbose {
		log.SetOutput(env.stderr)
	} else {
		log.SetOutput(io.Discard)
	}
	return func() { log.SetOutput(prev) }
}

// newFlagSet is a command's flag set: errors and help go to stderr, and the
// usage says what the command is and that it contacts no platform.
func newFlagSet(env standaloneEnv, name, synopsis, about string) *flag.FlagSet {
	fs := flag.NewFlagSet(standaloneAgent+" "+name, flag.ContinueOnError)
	fs.SetOutput(env.stderr)
	fs.Usage = func() {
		w := fs.Output()
		_, _ = fmt.Fprintf(w, "Usage: %s %s %s\n\n%s\n\n", standaloneAgent, name, synopsis, about)
		_, _ = fmt.Fprintln(w, "Standalone mode: this command contacts no Vista Platform. It registers nothing,")
		_, _ = fmt.Fprintln(w, "uploads nothing, reads no sensor configuration file and assesses nothing: it")
		_, _ = fmt.Fprintln(w, "writes what it observed, in the format docs/standalone-output.md describes.")
		_, _ = fmt.Fprintln(w, "\nFlags:")
		fs.PrintDefaults()
		_, _ = fmt.Fprintln(w, "\nExit status: 0 complete, 1 the run could not do its work, 2 a partial result.")
	}
	return fs
}

// parseFlags parses args; it returns (code, false) when the command should
// exit now: 0 after --help, 1 on a flag error (already reported).
func parseFlags(fs *flag.FlagSet, args []string) (int, bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, false
		}
		return 1, false
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(fs.Output(), "%s: unexpected argument %q\n", fs.Name(), fs.Arg(0))
		return 1, false
	}
	return 0, true
}

// usageError reports a refusal before any work and returns the exit status.
func usageError(env standaloneEnv, command, format string, args ...any) int {
	_, _ = fmt.Fprintf(env.stderr, "%s %s: %s\n", standaloneAgent, command, fmt.Sprintf(format, args...))
	return 1
}

// setFlags renders the flags given on the command line for the run record.
// Neither command takes a secret, so every value is safe to record.
func setFlags(fs *flag.FlagSet) map[string]string {
	out := map[string]string{}
	fs.Visit(func(f *flag.Flag) { out[f.Name] = f.Value.String() })
	return out
}

// stringList is a repeatable string flag.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

// sortedKeys returns a map's keys in order, for stable messages.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
