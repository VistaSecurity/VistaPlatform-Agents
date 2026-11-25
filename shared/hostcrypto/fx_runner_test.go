package hostcrypto

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
)

// The tests run real host programs (sh, awk, openssl, pwsh) through
// fxLocalRunner, not hostinventory's LocalRunner, for two reasons.
//
// The production per-command bound (fxProductionBound, hostinventory's
// commandTimeout) kills a command that runs long. On a loaded machine a test
// command can be slow for no fault of the program, and a kill then reads as
// a wrong answer ("exit -1"). The tests' bound is generous and separate; the
// production bound is tested once, in TestRemoteUnixProductionBound, with a
// deliberately slow host program. And any test command that alone took
// longer than the production bound fails the package (TestMain): a program
// that slow would be killed in production, whatever the machine.
//
// Every real command takes one of runtime.GOMAXPROCS slots first, so the
// package never runs more host programs at once than there are cores,
// however many tests and workers run in parallel.

// fxProductionBound is hostinventory's commandTimeout, the bound a
// production runner kills a command at.
const fxProductionBound = 90 * time.Second

// fxTestBound is the tests' own per-command bound: a hung command still
// fails, but a slow machine does not.
const fxTestBound = 10 * time.Minute

// fxMaxOutput is the runner's output bound, as in production.
const fxMaxOutput = 8 << 20

var (
	fxSlots = make(chan struct{}, max(1, runtime.GOMAXPROCS(0)))

	fxInFlight, fxMostInFlight int

	fxSlowMu   sync.Mutex
	fxSlowest  time.Duration
	fxSlowWhat string
)

type fxRunner struct{}

// fxLocalRunner is the tests' local runner.
func fxLocalRunner() fxRunner { return fxRunner{} }

var _ hostinventory.InputRunner = fxRunner{}

func (r fxRunner) Run(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
	return r.RunInput(ctx, argv, nil)
}

// fxBounded is a buffer that keeps the first fxMaxOutput bytes.
type fxBounded struct {
	bytes.Buffer
	over bool
}

func (b *fxBounded) Write(p []byte) (int, error) {
	if room := fxMaxOutput - b.Len(); len(p) > room {
		b.over = true
		b.Buffer.Write(p[:max(room, 0)])
		return len(p), nil
	}
	return b.Buffer.Write(p)
}

// RunInput is LocalRunner.RunInput with the tests' bound and a slot.
func (fxRunner) RunInput(ctx context.Context, argv []string, stdin []byte) ([]byte, []byte, int, error) {
	if len(argv) == 0 {
		return nil, nil, -1, errors.New("empty argv")
	}
	select {
	case fxSlots <- struct{}{}:
	case <-ctx.Done():
		return nil, nil, -1, ctx.Err()
	}
	fxSlowMu.Lock()
	fxInFlight++
	fxMostInFlight = max(fxMostInFlight, fxInFlight)
	fxSlowMu.Unlock()
	defer func() {
		fxSlowMu.Lock()
		fxInFlight--
		fxSlowMu.Unlock()
		<-fxSlots
	}()
	ctx, cancel := context.WithTimeout(ctx, fxTestBound)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	var out, errb fxBounded
	cmd.Stdout, cmd.Stderr = &out, &errb
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	start := time.Now()
	err := cmd.Run()
	fxNoteDuration(time.Since(start), argv)
	if out.over {
		return out.Bytes(), errb.Bytes(), -1, hostinventory.ErrTruncated
	}
	var ee *exec.ExitError
	switch {
	case err == nil:
		return out.Bytes(), errb.Bytes(), 0, nil
	case errors.As(err, &ee):
		return out.Bytes(), errb.Bytes(), ee.ExitCode(), nil
	default:
		return out.Bytes(), errb.Bytes(), -1, err
	}
}

func (fxRunner) ReadFile(ctx context.Context, p string) ([]byte, error) {
	return hostinventory.NewLocalRunner().ReadFile(ctx, p)
}

// fxNoteDuration keeps the slowest command.
func fxNoteDuration(d time.Duration, argv []string) {
	fxSlowMu.Lock()
	defer fxSlowMu.Unlock()
	if d > fxSlowest {
		fxSlowest = d
		what := strings.Join(argv, " ")
		if len(what) > 200 {
			what = what[:200] + "..."
		}
		fxSlowWhat = what
	}
}

func TestMain(m *testing.M) {
	code := m.Run()
	fxSlowMu.Lock()
	msg := fxSlowCheck(fxSlowest, fxSlowWhat)
	fxSlowMu.Unlock()
	if msg != "" {
		fmt.Fprintln(os.Stderr, "FAIL: "+msg)
		code = 1
	}
	os.Exit(code)
}

// fxSlowCheck says why the slowest command fails the package, or "".
func fxSlowCheck(slow time.Duration, what string) string {
	if slow <= fxProductionBound {
		return ""
	}
	return fmt.Sprintf("a host command ran %s, past the production bound of %s: %s", slow.Round(time.Second), fxProductionBound, what)
}

func TestFxSlowCheck(t *testing.T) {
	if fxSlowCheck(fxProductionBound, "x") != "" || fxSlowCheck(fxProductionBound+time.Second, "x") == "" {
		t.Error("the slowest-command check is wrong at the bound")
	}
}

// The tests never run more host programs at once than there are cores.
func TestFxRunnerSlots(t *testing.T) {
	if !tgtRealToolsAvailable() {
		t.Skip("POSIX tools not available")
	}
	n := runtime.GOMAXPROCS(0)
	var wg sync.WaitGroup
	for i := 0; i < 4*n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _, _ = fxLocalRunner().Run(context.Background(), []string{"sh", "-c", "sleep 0.2"})
		}()
	}
	wg.Wait()
	fxSlowMu.Lock()
	most := fxMostInFlight
	fxSlowMu.Unlock()
	if most > n || (n > 1 && most < 2) {
		t.Errorf("%d host programs at once on %d cores", most, n)
	}
}

// The awk program uses no dynamic regex where it runs per line: busybox
// awk compiles a regex held in a string again at every use (awkRunRegex).
// The one exception is SPECIAL, the @statements token split, which needs a
// single quote that the shell-quoted program cannot spell.
func TestAwkNoDynamicRegex(t *testing.T) {
	if msg := awkDynamicRegex(awkRules); msg != "" {
		t.Error(msg)
	}
	if strings.Count(awkRules, "gsub(SPECIAL,") != 1 {
		t.Error("SPECIAL is used beyond the statement split")
	}
	// The check can fail, in each of its forms.
	for _, bad := range []string{`match(s, RUN)`, `sub(PAT, "", t)`, `gsub(X, "", t)`, `if (s ~ RE) x = 1`} {
		if awkDynamicRegex(bad) == "" {
			t.Errorf("the check passes %q", bad)
		}
	}
	if msg := awkDynamicRegex(`match(s, /a+/); sub(/^[ \t]+/, "", t); if (s !~ /x/) y = 1; gsub(SPECIAL, "\n&\n", s)`); msg != "" {
		t.Errorf("the check refuses literals: %s", msg)
	}
}

var (
	awkSubRe   = regexp.MustCompile(`\bg?sub\(\s*([^,]+),`)
	awkMatchRe = regexp.MustCompile(`\bmatch\([^,]+,\s*([^)]+)\)`)
	awkTildeRe = regexp.MustCompile(`~\s*([^\s/][^\s)]*)`)
)

// awkDynamicRegex names the first regex operand in prog that is not a
// literal (SPECIAL, in gsub, excepted).
func awkDynamicRegex(prog string) string {
	for _, m := range awkSubRe.FindAllStringSubmatch(prog, -1) {
		if a := strings.TrimSpace(m[1]); !strings.HasPrefix(a, "/") && a != "SPECIAL" {
			return "sub or gsub with a dynamic regex: " + m[0]
		}
	}
	for _, m := range awkMatchRe.FindAllStringSubmatch(prog, -1) {
		if !strings.HasPrefix(strings.TrimSpace(m[1]), "/") {
			return "match with a dynamic regex: " + m[0]
		}
	}
	if m := awkTildeRe.FindString(prog); m != "" {
		return "a dynamic regex after ~: " + m
	}
	return ""
}

// TestRemoteUnixProductionBound runs a remote read through the PRODUCTION
// runner (hostinventory's LocalRunner and its command bound) against a host
// whose awk is deliberately slower than that bound: the command is killed,
// the read is an error, and nothing crosses. It waits out the bound (about
// 95 seconds), in parallel with the rest of the package.
func TestRemoteUnixProductionBound(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out the 90-second production bound")
	}
	if !tgtRealToolsAvailable() {
		t.Skip("POSIX tools not available")
	}
	t.Parallel()
	bin := t.TempDir()
	// Past the bound by a few seconds: killing the shell does not kill the
	// pipeline it started, so the command ends when this does.
	slow := "#!/bin/sh\nsleep " + strconv.Itoa(int(fxProductionBound/time.Second)+5) + "\n"
	if err := os.WriteFile(filepath.Join(bin, "awk"), []byte(slow), 0o755); err != nil {
		t.Fatal(err)
	}
	p := tgtWrite(t, t.TempDir(), "a.conf", []byte("ssl_protocols TLSv1.2;\npassword S3cr3t\n"), 0o644)
	fxSettle()
	rt := NewRemoteUnixTarget(tgtPathRunner{inner: hostinventory.NewLocalRunner(), path: bin + string(os.PathListSeparator) + os.Getenv("PATH")}, runtime.GOOS)
	start := time.Now()
	out, _, err := rt.ReadText(context.Background(), p, []string{"ssl_protocols"})
	took := time.Since(start)
	if err == nil || len(out) != 0 || !strings.Contains(err.Error(), "exit -1") {
		t.Fatalf("a killed command: %q, %v", out, err)
	}
	if took < fxProductionBound || took > fxProductionBound+30*time.Second {
		t.Errorf("the production bound killed the command after %s, want about %s", took.Round(time.Second), fxProductionBound)
	}
}

// TestAwkBracketSlash: no bracket expression of the awk program spells "/"
// as \/ (busybox keeps the backslash there), and under every awk installed
// the program's base64 classes refuse a backslash.
func TestAwkBracketSlash(t *testing.T) {
	if m := regexp.MustCompile(`\[[^\]\n]*\\/[^\]\n]*\]`).FindString(awkRules); m != "" {
		t.Errorf("a bracket expression spells / as \\/: %s", m)
	}
	if !tgtRealToolsAvailable() {
		t.Skip("POSIX tools not available")
	}
	// One line per class: a run of RedactRunLength with a backslash in the
	// middle, a body line and a key blob with one.
	half := strings.Repeat("A", RedactRunLength)
	prog := `{ r = 0; if (match($0, ` + awkRunRegex + `) && index(substr($0, RSTART, RLENGTH), "\\")) r = 1
  if ($0 ~ /^[A-Za-z0-9+\057=]+$/) r = r + 2
  if ($0 ~ /^[A-Za-z0-9+\057]+=*$/) r = r + 4
  printf "%d", r }`
	input := half + `\` + half + "\n" + `AB\CD` + "\n" + "AB/CD\n"
	for impl, r := range tgtAwks(t) {
		out, errb, exit, err := r.Run(context.Background(), []string{"env", "LC_ALL=C", "sh", "-c", `printf '%s' "$1" | awk "$2"`, "sh", input, prog})
		if err != nil || exit != 0 || string(out) != "006" {
			t.Errorf("%s: %q (exit %d %v %s), want 006: no class may match a backslash", impl, out, exit, err, errb)
		}
	}
}
