// Package agentoutput writes what a standalone run observed (see
// docs/design/standalone-mode.md): one envelope per record, in JSON Lines, one
// JSON document, or a CSV of the endpoints the run saw, to a file or standard
// output, with a human summary on standard error.
//
// It is the only place the standalone commands of both agents write their
// results, so the format is defined once. It never opens a network connection
// and is CGO-free.
package agentoutput

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Schema is the envelope's identifier. Its version changes only for a breaking
// change to the envelope or to the meaning of a kind; new fields and kinds are
// additive. schemas/output/v1/record.schema.json holds the envelope.
const Schema = "vista.agent-output/v1"

// Kind names what a record's data is.
type Kind string

// The kinds a standalone run writes. run is always first and summary always
// last.
const (
	KindRun                 Kind = "run"
	KindPassiveObservation  Kind = "passive_observation"
	KindScanHost            Kind = "scan_host"
	KindDeviceInterrogation Kind = "device_interrogation"
	KindHostInventory       Kind = "host_inventory"
	KindError               Kind = "error"
	KindSummary             Kind = "summary"
)

// Format is an output format.
type Format string

// The output formats.
const (
	FormatJSONL Format = "jsonl"
	FormatJSON  Format = "json"
	FormatCSV   Format = "csv"
)

// Formats lists the formats, for help text.
var Formats = []Format{FormatJSONL, FormatJSON, FormatCSV}

// ParseFormat maps a --format value onto a Format; "" is jsonl.
func ParseFormat(s string) (Format, error) {
	switch Format(strings.ToLower(strings.TrimSpace(s))) {
	case "", FormatJSONL:
		return FormatJSONL, nil
	case FormatJSON:
		return FormatJSON, nil
	case FormatCSV:
		return FormatCSV, nil
	}
	return "", fmt.Errorf("unknown output format %q: use jsonl, json or csv", s)
}

// Record is one line of JSON Lines output, and one element of a JSON
// document's records.
type Record struct {
	Schema       string    `json:"schema"`
	Kind         Kind      `json:"kind"`
	Agent        string    `json:"agent"`
	AgentVersion string    `json:"agent_version"`
	RunID        string    `json:"run_id"`
	ObservedAt   time.Time `json:"observed_at"`
	Data         any       `json:"data"`
}

// Run is the data of the run record: what was asked for. Flags never carry a
// secret: the commands take secrets only from files and the environment.
type Run struct {
	Command   string              `json:"command"`
	Flags     map[string]string   `json:"flags,omitempty"`
	Targets   []string            `json:"targets,omitempty"`
	Resolved  map[string][]string `json:"resolved,omitempty"`
	Hostname  string              `json:"hostname,omitempty"`
	StartedAt time.Time           `json:"started_at"`
	Notes     []string            `json:"notes,omitempty"`
}

// ErrorData is the data of an error record.
type ErrorData struct {
	Target string `json:"target,omitempty"`
	Stage  string `json:"stage,omitempty"`
	Reason string `json:"reason"`
}

// Summary is the data of the summary record.
type Summary struct {
	Records         map[Kind]int `json:"records"`
	Endpoints       int          `json:"endpoints"`
	Errors          int          `json:"errors"`
	Warnings        []string     `json:"warnings,omitempty"`
	Partial         bool         `json:"partial"`
	DurationSeconds float64      `json:"duration_seconds"`
	FinishedAt      time.Time    `json:"finished_at"`
	// Scope says how much was looked at, so an empty result reads as "saw
	// nothing", not "found nothing wrong".
	Scope string `json:"scope,omitempty"`
}

// Endpoint is one CSV row: a host, port and protocol the run observed. A
// command derives endpoints from the records it writes; fields it does not
// know stay empty.
type Endpoint struct {
	Kind                          Kind
	Host                          string
	Address                       string
	Port                          int
	Transport                     string
	Protocol                      string
	ProtocolVersion               string
	CipherSuite                   string
	KeyExchange                   string
	CertificateSubject            string
	CertificateIssuer             string
	CertificateNotAfter           string
	CertificateKeyAlgorithm       string
	CertificateKeySize            int
	CertificateSignatureAlgorithm string
	CertificateFingerprintSHA256  string
	Source                        string
}

// CSVHeader is the CSV output's header row.
var CSVHeader = []string{
	"kind", "host", "address", "port", "transport", "protocol", "protocol_version",
	"cipher_suite", "key_exchange", "certificate_subject", "certificate_issuer",
	"certificate_not_after", "certificate_key_algorithm", "certificate_key_size",
	"certificate_signature_algorithm", "certificate_fingerprint_sha256", "source",
}

func (e Endpoint) row() []string {
	itoa := func(n int) string {
		if n == 0 {
			return ""
		}
		return fmt.Sprint(n)
	}
	return []string{
		string(e.Kind), e.Host, e.Address, itoa(e.Port), e.Transport, e.Protocol, e.ProtocolVersion,
		e.CipherSuite, e.KeyExchange, e.CertificateSubject, e.CertificateIssuer,
		e.CertificateNotAfter, e.CertificateKeyAlgorithm, itoa(e.CertificateKeySize),
		e.CertificateSignatureAlgorithm, e.CertificateFingerprintSHA256, e.Source,
	}
}

// Options configure a Writer.
type Options struct {
	// Path is the output file; "" or "-" is standard output.
	Path   string
	Format Format
	// Agent and AgentVersion stamp every record.
	Agent        string
	AgentVersion string
	// Quiet suppresses the human summary.
	Quiet bool

	// Stdout and Stderr default to the process's; tests replace them.
	Stdout io.Writer
	Stderr io.Writer
	// Now defaults to time.Now; tests pin it.
	Now func() time.Time
}

// Writer writes one run's records. It is safe for concurrent use: a scan
// reports hosts from several goroutines.
type Writer struct {
	opts  Options
	runID string
	start time.Time

	mu        sync.Mutex
	closed    bool
	out       io.Writer
	buf       *bufio.Writer
	file      *os.File // the temporary file, renamed to opts.Path on Close
	csv       *csv.Writer
	run       *Record
	records   []Record // json format only
	counts    map[Kind]int
	endpoints int
	errors    int
	warnings  []string
	seenRows  map[string]bool
}

// Open starts a run: it opens the output and writes the run record.
func Open(opts Options, run Run) (*Writer, error) {
	if opts.Format == "" {
		opts.Format = FormatJSONL
	}
	if _, err := ParseFormat(string(opts.Format)); err != nil {
		return nil, err
	}
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	w := &Writer{
		opts:     opts,
		runID:    uuid.NewString(),
		start:    opts.Now().UTC(),
		counts:   map[Kind]int{},
		seenRows: map[string]bool{},
	}
	if opts.Path == "" || opts.Path == "-" {
		w.out = opts.Stdout
	} else {
		dir, base := filepath.Split(opts.Path)
		if dir == "" {
			dir = "."
		}
		f, err := os.CreateTemp(dir, "."+base+".partial-*")
		if err != nil {
			return nil, fmt.Errorf("cannot create the output file in %s: %w", dir, err)
		}
		// CreateTemp already makes the file 0600 on Unix; Chmod states it, and
		// on Windows it only clears the read-only bit.
		if err := f.Chmod(0o600); err != nil {
			_ = f.Close()
			_ = os.Remove(f.Name())
			return nil, fmt.Errorf("cannot restrict the output file's permissions: %w", err)
		}
		w.file = f
		w.out = f
	}
	w.buf = bufio.NewWriter(w.out)
	if opts.Format == FormatCSV {
		w.csv = csv.NewWriter(w.buf)
		if err := w.csv.Write(CSVHeader); err != nil {
			w.abort()
			return nil, err
		}
	}
	if run.StartedAt.IsZero() {
		run.StartedAt = w.start
	}
	if run.Hostname == "" {
		run.Hostname, _ = os.Hostname()
	}
	rec := w.record(KindRun, run)
	w.run = &rec
	if err := w.emit(rec); err != nil {
		w.abort()
		return nil, err
	}
	return w, nil
}

// RunID is the run's identifier, stamped on every record.
func (w *Writer) RunID() string { return w.runID }

func (w *Writer) record(kind Kind, data any) Record {
	return Record{
		Schema: Schema, Kind: kind, Agent: w.opts.Agent, AgentVersion: w.opts.AgentVersion,
		RunID: w.runID, ObservedAt: w.opts.Now().UTC(), Data: data,
	}
}

// emit writes a record in the stream formats; json keeps it for Close. The
// caller holds mu (or is Open).
func (w *Writer) emit(rec Record) error {
	w.counts[rec.Kind]++
	switch w.opts.Format {
	case FormatJSONL:
		line, err := json.Marshal(rec)
		if err != nil {
			return fmt.Errorf("cannot encode a %s record: %w", rec.Kind, err)
		}
		if _, err := w.buf.Write(append(line, '\n')); err != nil {
			return err
		}
		// Standard output streams record by record; a file is renamed into
		// place at the end, so buffering it costs nothing.
		if w.file == nil {
			return w.buf.Flush()
		}
	case FormatJSON:
		if rec.Kind != KindRun && rec.Kind != KindSummary {
			w.records = append(w.records, rec)
		}
	}
	return nil
}

// Write records one observation, with the endpoints it shows for the CSV.
func (w *Writer) Write(kind Kind, data any, endpoints ...Endpoint) error {
	if kind == KindRun || kind == KindSummary || kind == KindError {
		return fmt.Errorf("agentoutput: %s records are written by Open, Close and Error", kind)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return errors.New("agentoutput: write after close")
	}
	if err := w.emit(w.record(kind, data)); err != nil {
		return err
	}
	return w.writeEndpoints(kind, endpoints)
}

// writeEndpoints adds CSV rows, once each: a passive capture sees the same
// handshake many times, and a spreadsheet wants the endpoint once.
func (w *Writer) writeEndpoints(kind Kind, endpoints []Endpoint) error {
	for _, e := range endpoints {
		if e.Kind == "" {
			e.Kind = kind
		}
		row := e.row()
		key := strings.Join(row, "\x00")
		if w.seenRows[key] {
			continue
		}
		w.seenRows[key] = true
		w.endpoints++
		if w.csv != nil {
			if err := w.csv.Write(row); err != nil {
				return err
			}
		}
	}
	return nil
}

// Error records something that failed. It marks the run partial.
func (w *Writer) Error(target, stage, reason string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return errors.New("agentoutput: write after close")
	}
	w.errors++
	return w.emit(w.record(KindError, ErrorData{Target: target, Stage: stage, Reason: reason}))
}

// Warn adds a line to the summary's warnings without failing anything.
func (w *Writer) Warn(format string, args ...any) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.warnings = append(w.warnings, fmt.Sprintf(format, args...))
}

// Close writes the summary, puts the file in place and prints the human
// summary. partial marks the result partial even when no error record was
// written (a collector warning, a section that did not complete). It returns
// the summary it wrote.
func (w *Writer) Close(partial bool, scope string) (Summary, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return Summary{}, errors.New("agentoutput: closed twice")
	}
	w.closed = true
	now := w.opts.Now().UTC()
	sum := Summary{
		Records:         map[Kind]int{},
		Endpoints:       w.endpoints,
		Errors:          w.errors,
		Warnings:        w.warnings,
		Partial:         partial || w.errors > 0,
		DurationSeconds: now.Sub(w.start).Seconds(),
		FinishedAt:      now,
		Scope:           scope,
	}
	for k, n := range w.counts {
		sum.Records[k] = n
	}
	sumRec := w.record(KindSummary, sum)
	err := w.emit(sumRec)
	if err == nil {
		switch w.opts.Format {
		case FormatJSON:
			records := w.records
			if records == nil {
				records = []Record{}
			}
			doc := struct {
				Run     Record   `json:"run"`
				Records []Record `json:"records"`
				Summary Record   `json:"summary"`
			}{*w.run, records, sumRec}
			enc := json.NewEncoder(w.buf)
			enc.SetIndent("", "  ")
			err = enc.Encode(doc)
		case FormatCSV:
			w.csv.Flush()
			err = w.csv.Error()
		}
	}
	if err == nil {
		err = w.buf.Flush()
	}
	if w.file != nil {
		if cerr := w.file.Close(); err == nil {
			err = cerr
		}
		if err == nil {
			err = os.Rename(w.file.Name(), w.opts.Path)
		}
		if err != nil {
			_ = os.Remove(w.file.Name())
		}
	}
	if !w.opts.Quiet {
		w.printSummary(sum, err)
	}
	return sum, err
}

// abort discards a run that could not start.
func (w *Writer) abort() {
	if w.file != nil {
		_ = w.file.Close()
		_ = os.Remove(w.file.Name())
	}
}

func (w *Writer) printSummary(sum Summary, writeErr error) {
	var kinds []string
	for k, n := range sum.Records {
		if k == KindRun || k == KindSummary {
			continue
		}
		kinds = append(kinds, fmt.Sprintf("%s %d", k, n))
	}
	sort.Strings(kinds)
	if len(kinds) == 0 {
		kinds = []string{"no observations"}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s; %d endpoint(s); %d error(s); %.1fs\n",
		w.opts.Agent, strings.Join(kinds, ", "), sum.Endpoints, sum.Errors, sum.DurationSeconds)
	if sum.Scope != "" {
		fmt.Fprintf(&b, "  looked at: %s\n", sum.Scope)
	}
	for _, warn := range sum.Warnings {
		fmt.Fprintf(&b, "  warning: %s\n", warn)
	}
	switch {
	case writeErr != nil:
		fmt.Fprintf(&b, "  output NOT written: %v\n", writeErr)
	case w.file != nil:
		fmt.Fprintf(&b, "  output: %s (%s)\n", w.opts.Path, w.opts.Format)
	}
	if sum.Partial {
		b.WriteString("  the result is partial: see the error records\n")
	}
	b.WriteString("  observations only; nothing was assessed or uploaded\n")
	// The summary is advisory: a closed standard error must not fail a run
	// whose output was written.
	_, _ = io.WriteString(w.opts.Stderr, b.String())
}

// ExitCode maps a run's outcome onto the standalone exit status: 0 complete,
// 1 the run could not do its work, 2 partial.
func ExitCode(sum Summary, err error, nothingWorked bool) int {
	switch {
	case err != nil || nothingWorked:
		return 1
	case sum.Partial:
		return 2
	}
	return 0
}
