package hostcrypto

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
)

// Pass 1, known locations: each platform's table of where certificates,
// keys, keystores, SSH material and configuration live (oslinux.go,
// osdarwin.go, oswindows.go), visited through the Target and nothing else.
//
// What a file yields depends on the mode, and the rule is the contract's:
//
//   - LOCAL: every file is read and handed to its parser in memory.
//   - REMOTE: only what Identity.Public allows is read (certificates, SSH
//     public key lines). A private key, a keystore, a keytab, a keyring is
//     recorded from Stat and Identify alone: where it is, who can read it,
//     what its markers say, and Unknown (or a note) for the rest. Describing
//     such a file on the host by a command that prints only public material is
//     the next slice's: see locRemoteKeyProbe and locRemoteKeystoreProbe.
//
// Configuration files found here are not read here: pass 2 (pass_config.go)
// reads each through collection.readConfig and follows what it names.
//
// Records are not put in the registry as they are found. A file is parsed
// once, its records are held by real path (locState.visited), and every later
// sighting of the same file (a configuration naming it, a link to it) is
// merged into those records: the strongest FoundBy, the union of UsedBy, and
// the role a configuration gives a key. Pass 2 then hands them all to the
// registry (locFlush), which de-duplicates against every other pass.

// locKind is what a table entry holds, which decides how its files are read.
type locKind int

const (
	// locMaterial: anything; each file is dispatched by what Identify says.
	locMaterial locKind = iota
	// locTrust: a trust store. Its certificates (and a Java cacerts' entries)
	// are trust anchors.
	locTrust
	// locSSHHost: ssh_host_*_key and their .pub halves.
	locSSHHost
	// locAuthorizedKeys: authorized_keys files.
	locAuthorizedKeys
	// locKnownHosts: known_hosts files, summarised only.
	locKnownHosts
	// locGnuPG: a GnuPG home or a system keyring directory.
	locGnuPG
	// locNSS: a directory holding an NSS database.
	locNSS
	// locConfig: a configuration file for pass 2.
	locConfig
)

// locEntry is one row of a platform's table.
type locEntry struct {
	// Path is a file or, with Dir, a directory. Any component may hold the
	// wildcards * ? [ ]. Unix tables use "/", Windows tables "\".
	Path string
	Dir  bool
	// Depth is how far below a directory entry to look; 0 is its own files.
	Depth int
	// Names keeps only files whose base name matches one of these patterns.
	Names []string
	Kind  locKind
	// Product is the configuration parser (locConfig). The value
	// locBackendProduct means "a crypto-policies back-end, chosen by the
	// file's name".
	Product string
	// BaseUp: a configuration's relative paths resolve against its directory,
	// this many levels up (Apache's ServerRoot is the parent of conf/).
	BaseUp int
	// Role is given to every private key found under the entry.
	Role string
	// Account names the account an authorized_keys file grants: a fixed name,
	// "*" for the path component the entry's first "*" matched (a home
	// directory), or "@base" for the file's own name.
	Account string
	// SkipLinks passes over symbolic links: /etc/ssl/certs holds a link per
	// trust anchor, each a copy of what the bundle already says.
	SkipLinks bool
	// Section is where a failure to look is recorded. Empty: by Kind.
	Section string
	// Home marks the per-user tables, run only when the operator opts in.
	Home bool
}

// locBackendProduct marks a table entry of crypto-policies back-ends.
const locBackendProduct = "crypto-policies/"

// section is where an entry's failures are recorded.
func (e locEntry) section() string {
	if e.Home {
		return SectionHomeDirectories
	}
	if e.Section != "" {
		return e.Section
	}
	switch e.Kind {
	case locTrust:
		return SectionCertificates
	case locSSHHost, locAuthorizedKeys, locKnownHosts:
		return SectionSSH
	case locGnuPG, locNSS:
		return SectionKeystores
	case locConfig:
		return SectionConfigs
	}
	return SectionPrivateKeys
}

// locTables returns a platform's system table and its home-directory table.
// root prefixes every Unix path (tests build a host under a temporary
// directory; production passes ""); win are a Windows host's roots (C: and the
// default names when zero).
func locTables(platform, root string, win locWinRoots) (system, home []locEntry) {
	switch platform {
	case "linux":
		return locLinuxTable(root), locLinuxHomeTable(root)
	case "darwin":
		return locDarwinTable(root), locDarwinHomeTable(root)
	case "windows":
		if win.Drive == "" {
			win = locDefaultWinRoots("C:")
		}
		return locWindowsTable(win), locWindowsHomeTable(win)
	}
	return nil, nil
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

// locState is what passes 1 and 2 share. Passes run one after another, so it
// needs no lock; the registry and report it feeds have their own.
type locState struct {
	// pre holds pass 1's batched Stat and Identify answers
	// (BatchTarget), by path; nil outside pass 1.
	pre map[string]PathInfo

	root     string
	platform string
	style    locStyle
	// win are a Windows host's roots, asked for once per collection.
	win locWinRoots

	// visited holds the records of every file parsed, by real path, in
	// first-seen order (order), until locFlush hands them to the registry.
	visited map[string]*locProduced
	order   []string
	// nss remembers the NSS directories already described.
	nss map[string]bool

	// configs is the queue of configuration files pass 2 reads; cfgDone
	// holds what each produced, by product and real path, and included the
	// files already read as another file's include.
	configs  []locConfigFile
	cfgDone  map[string][]CryptoConfig
	included map[string]bool

	// tally counts, per section, what was looked at and what could not be.
	tally map[string]*locCount
	// unidentified counts remote files in known locations Identify could not
	// name (bare DER, an unknown binary), by section.
	unidentified map[string]int
	// remoteNotes are the once-per-run explanations of what remote mode does
	// not read.
	remoteNotes map[string]bool
	// noPerms counts, per section, files visited whose permissions could not
	// be read.
	noPerms map[string]int
}

type locCount struct{ ok, bad int }

// locProduced is what one file yielded.
type locProduced struct {
	certs  []Certificate
	keys   []PrivateKey
	stores []Keystore
	auth   []AuthorizedKeysFile
	known  []KnownHostsFile
}

// each calls fn with every record's Location.
func (p *locProduced) each(fn func(*Location)) {
	for i := range p.certs {
		fn(&p.certs[i].Location)
	}
	for i := range p.keys {
		fn(&p.keys[i].Location)
	}
	for i := range p.stores {
		fn(&p.stores[i].Location)
	}
	for i := range p.auth {
		fn(&p.auth[i].Location)
	}
	for i := range p.known {
		fn(&p.known[i].Location)
	}
}

// locConfigFile is one configuration file waiting for pass 2.
type locConfigFile struct {
	Path    string
	Product string
	// Base is the directory relative paths in it resolve against.
	Base    string
	Info    FileInfo
	FoundBy string
	UsedBy  []Usage
}

func newLocState(root, platform string) *locState {
	return &locState{
		root:         root,
		platform:     platform,
		style:        locStyle(platform == "windows"),
		visited:      map[string]*locProduced{},
		nss:          map[string]bool{},
		cfgDone:      map[string][]CryptoConfig{},
		included:     map[string]bool{},
		tally:        map[string]*locCount{},
		unidentified: map[string]int{},
		remoteNotes:  map[string]bool{},
		noPerms:      map[string]int{},
	}
}

// locStat is Stat through pass 1's batched answers.
func (c *collection) locStat(ctx context.Context, p string) (FileInfo, error) {
	if r, ok := c.locSt().pre[p]; ok {
		return r.Info, r.StatErr
	}
	return c.target.Stat(ctx, p)
}

// locIdentify is Identify through pass 1's batched answers.
func (c *collection) locIdentify(ctx context.Context, p string) (Identity, error) {
	if r, ok := c.locSt().pre[p]; ok {
		return r.Identity, r.IdentifyErr
	}
	return c.target.Identify(ctx, p)
}

// locPrefetch asks a remote BatchTarget for the Stat and Identify answers
// of paths pass 1 is about to visit, in one host program per batch rather
// than two per path. Paths already answered are not asked again. On a local
// target, or one without the interface, it does nothing and the single
// calls are made as before.
func (c *collection) locPrefetch(ctx context.Context, paths []string) {
	st := c.locSt()
	bt, ok := c.target.(BatchTarget)
	if !ok || c.target.Local() || st.pre == nil {
		return
	}
	var want []string
	seen := map[string]bool{}
	for _, p := range paths {
		if _, done := st.pre[p]; done || seen[p] || c.locExcluded(p) {
			continue
		}
		seen[p] = true
		want = append(want, p)
	}
	if len(want) < 2 {
		return // one path: the single calls cost no more
	}
	got, _ := bt.StatIdentifyMany(ctx, want)
	for _, r := range got {
		st.pre[r.Path] = r
	}
}

// locSt returns the shared state, creating it for production (no root
// prefix) the first time.
func (c *collection) locSt() *locState {
	if c.loc == nil {
		c.loc = newLocState("", c.opts.Platform)
	}
	return c.loc
}

func (st *locState) count(section string, ok bool) {
	t := st.tally[section]
	if t == nil {
		t = &locCount{}
		st.tally[section] = t
	}
	if ok {
		t.ok++
	} else {
		t.bad++
	}
}

// locRemoteNote records, once per run, a sentence about what remote mode
// leaves out, so a reader sees why a field is empty, and marks the section
// partial: the answer is not the whole one.
func (c *collection) locRemoteNote(section, msg string) {
	st := c.locSt()
	if st.remoteNotes[section+"\x00"+msg] {
		return
	}
	st.remoteNotes[section+"\x00"+msg] = true
	c.partial(section, errors.New(msg))
}

// ---------------------------------------------------------------------------
// Paths in either style
// ---------------------------------------------------------------------------

// locStyle is a host's path style: true for Windows. The collector runs on one
// platform and may describe another, so path handling never uses the agent's
// own (path/filepath); it uses this.
type locStyle bool

func (w locStyle) sep() string {
	if w {
		return `\`
	}
	return "/"
}

// clean puts a path in the host's separators.
func (w locStyle) clean(p string) string {
	if w {
		return strings.ReplaceAll(p, "/", `\`)
	}
	return p
}

// isAbs: "/x" on Unix; "C:\x" or a UNC "\\server\share" on Windows.
func (w locStyle) isAbs(p string) bool {
	if !w {
		return strings.HasPrefix(p, "/")
	}
	if strings.HasPrefix(p, `\\`) {
		return true
	}
	return len(p) >= 3 && cfgIsLetter(p[0]) && p[1] == ':' && p[2] == '\\'
}

// split returns a path's root ("/", "C:\" or "\\") and its components.
func (w locStyle) split(p string) (string, []string) {
	root, win := "", bool(w)
	switch {
	case !win && strings.HasPrefix(p, "/"):
		root, p = "/", p[1:]
	case win && strings.HasPrefix(p, `\\`):
		root, p = `\\`, p[2:]
	case win && len(p) >= 2 && p[1] == ':':
		root, p = p[:2]+`\`, strings.TrimPrefix(p[2:], `\`)
	}
	var comps []string
	for _, s := range strings.Split(p, w.sep()) {
		if s != "" {
			comps = append(comps, s)
		}
	}
	return root, comps
}

// join builds root + components.
func (w locStyle) join(root string, comps ...string) string {
	return root + strings.Join(comps, w.sep())
}

// dir is the directory part of a path.
func (w locStyle) dir(p string) string {
	root, comps := w.split(p)
	if len(comps) == 0 {
		return root
	}
	return w.join(root, comps[:len(comps)-1]...)
}

// up is dir applied n times.
func (w locStyle) up(p string, n int) string {
	for ; n > 0; n-- {
		p = w.dir(p)
	}
	return p
}

// resolve makes a configuration's path absolute against base. ".." is
// folded the way the host would on Unix; Windows paths are left as written.
func (w locStyle) resolve(base, p string) string {
	p = w.clean(p)
	if !w.isAbs(p) {
		p = strings.TrimSuffix(base, w.sep()) + w.sep() + p
	}
	if !w {
		p = path.Clean(p)
	}
	return p
}

// matchComp matches one path component against one pattern component; on
// Windows without regard to case, as the filesystem compares.
func (w locStyle) matchComp(pattern, name string) bool {
	if w {
		pattern, name = strings.ToLower(pattern), strings.ToLower(name)
	}
	ok, err := path.Match(pattern, name)
	return err == nil && ok
}

// under reports whether p is prefix or below it.
func (w locStyle) under(p, prefix string) bool {
	if prefix == "" {
		return false
	}
	if w {
		p, prefix = strings.ToLower(w.clean(p)), strings.ToLower(w.clean(prefix))
	}
	prefix = strings.TrimSuffix(prefix, w.sep())
	return p == prefix || strings.HasPrefix(p, prefix+w.sep())
}

func locHasMeta(s string) bool { return strings.ContainsAny(s, "*?[") }

// excluded reports whether the operator excluded p.
func (c *collection) locExcluded(p string) bool {
	st := c.locSt()
	for _, ex := range c.opts.ExcludePaths {
		if st.style.under(p, ex) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------------

// locList lists root through the Target within the run's bounds and records
// what the listing could not see.
func (c *collection) locList(ctx context.Context, section, root string, depth int, names []string) []FileInfo {
	st := c.locSt()
	if c.locExcluded(root) {
		return nil
	}
	left := c.budget.remaining()
	if left == 0 {
		c.limit(section, "max_files", fmt.Sprintf("stopped after %d files", c.opts.maxFiles()))
		return nil
	}
	if r, ok := st.pre[root]; ok && errors.Is(r.StatErr, ErrNotExist) {
		// Pass 1's batch found no such root: the listing would answer
		// ErrNotExist, which is nothing to record.
		return nil
	}
	files, err := c.target.List(ctx, root, ListOptions{
		MaxDepth:     depth,
		MaxFiles:     left,
		MaxSizeBytes: c.opts.maxFileBytes(),
		Exclude:      c.opts.ExcludePaths,
		Names:        names,
	})
	var lerr *ListError
	switch {
	case err == nil:
		st.count(section, true)
	case errors.As(err, &lerr):
		st.count(section, true)
		if lerr.DeniedCount > 0 {
			c.partial(section, fmt.Errorf("%s: %d directories could not be read", root, lerr.DeniedCount))
		}
		if lerr.Unreadable > 0 {
			c.partial(section, fmt.Errorf("%s: %d entries could not be read", root, lerr.Unreadable))
		}
		if lerr.OverSize > 0 {
			c.limit(section, "max_file_bytes", fmt.Sprintf("skipped files over %d bytes", c.opts.maxFileBytes()))
		}
		if lerr.Truncated {
			c.limit(section, "max_files", fmt.Sprintf("stopped after %d files", c.opts.maxFiles()))
		}
	case errors.Is(err, ErrNotExist):
		return nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		c.locTimeUp(ctx, section)
	default:
		st.count(section, false)
		c.partial(section, fmt.Errorf("%s: %w", root, err))
	}
	return files
}

// locListRoot is the directory locFiles lists for dirPat: dirPat itself, or
// the last fixed directory above its first wildcard.
func (st *locState) locListRoot(dirPat string) string {
	w := st.style
	root, comps := w.split(dirPat)
	for i, s := range comps {
		if locHasMeta(s) {
			return w.join(root, comps[:i]...)
		}
	}
	return dirPat
}

// locFiles returns the files under dirPat (whose components may hold
// wildcards), at most depth levels below it, whose base names match names.
//
// A Target lists files, never directories, so a wildcard directory is
// expanded by listing from the last fixed directory above it, deep enough to
// reach the files, and keeping the paths whose components match. A wildcard
// that names a symbolic link to a directory (Homebrew's opt/openjdk, a JDK's
// default-java) is not descended by a listing, so links matching it are
// followed explicitly, at most two hops.
func (c *collection) locFiles(ctx context.Context, section, dirPat string, depth int, names []string, hops int) []FileInfo {
	w := c.locSt().style
	root, comps := w.split(dirPat)
	first := -1
	for i, s := range comps {
		if locHasMeta(s) {
			first = i
			break
		}
	}
	if first < 0 {
		return c.locList(ctx, section, dirPat, depth, names)
	}
	prefix := w.join(root, comps[:first]...)
	k := len(comps) - first
	var out []FileInfo
	for _, fi := range c.locList(ctx, section, prefix, k+depth, names) {
		_, fc := w.split(fi.Path)
		if len(fc) < len(comps)+1 || len(fc) > len(comps)+1+depth {
			continue
		}
		ok := true
		for j := first; j < len(comps); j++ {
			if !w.matchComp(comps[j], fc[j]) {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, fi)
		}
	}
	if hops >= 2 {
		return out
	}
	for _, l := range c.locList(ctx, section, prefix, 0, []string{comps[first]}) {
		if !l.IsSymlink || l.LinkTarget == "" {
			continue
		}
		// Resolved through the Target, the way a remote host would, not the
		// agent's filesystem.
		t := joinLinkTarget(l.Path, l.LinkTarget)
		tfi, err := c.locStat(ctx, t)
		if err == nil {
			tfi, err = c.locFollow(ctx, t, tfi)
		}
		if err != nil || !tfi.IsDir {
			continue
		}
		c.registry.addLink(l.Path, l.LinkTarget)
		rest := append([]string(nil), comps[first+1:]...)
		tRoot, tComps := w.split(t)
		out = append(out, c.locFiles(ctx, section, w.join(tRoot, append(tComps, rest...)...), depth, names, hops+1)...)
	}
	return out
}

// locEntryFiles returns the files one table entry names. A plain file entry
// is a Stat, not a listing.
func (c *collection) locEntryFiles(ctx context.Context, e locEntry) []FileInfo {
	w := c.locSt().style
	if e.Dir {
		return c.locFiles(ctx, e.section(), e.Path, e.Depth, e.Names, 0)
	}
	if !locHasMeta(e.Path) {
		fi, err := c.locStat(ctx, e.Path)
		if err != nil {
			c.locStatErr(e.section(), e.Path, err)
			return nil
		}
		return []FileInfo{fi}
	}
	return c.locFiles(ctx, e.section(), w.dir(e.Path), 0, []string{baseName(e.Path)}, 0)
}

// locStatErr records a failed Stat of a path a table or a configuration
// names. A path that does not exist is not a failure: the table lists places
// a platform MAY keep things.
func (c *collection) locStatErr(section, p string, err error) {
	st := c.locSt()
	switch {
	case errors.Is(err, ErrNotExist):
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		c.locStoppedAll()
	default:
		st.count(section, false)
		c.partial(section, fmt.Errorf("%s: %w", p, err))
	}
}

// locFollow resolves a symbolic link to what it finally names, at most eight
// hops, teaching the registry each link on the way so a remote collection
// de-duplicates the two paths as one. It returns the target's FileInfo with
// the path the caller used.
func (c *collection) locFollow(ctx context.Context, p string, fi FileInfo) (FileInfo, error) {
	for hops := 0; fi.IsSymlink && hops < 8; hops++ {
		if fi.LinkTarget == "" {
			return fi, nil
		}
		c.registry.addLink(fi.Path, fi.LinkTarget)
		t := joinLinkTarget(fi.Path, fi.LinkTarget)
		next, err := c.locStat(ctx, t)
		if err != nil {
			return FileInfo{}, err
		}
		fi = next
	}
	fi.Path = p
	return fi, nil
}

// ---------------------------------------------------------------------------
// Pass 1
// ---------------------------------------------------------------------------

// passKnownLocations is pass 1.
func passKnownLocations(ctx context.Context, c *collection) {
	if c.stoppedBefore(ctx, locPassSections(c)...) {
		return
	}
	st := c.locSt()
	if st.platform == "windows" && st.win.Drive == "" {
		st.win = c.locWindowsRoots(ctx)
	}
	system, home := locTables(st.platform, st.root, st.win)
	if system == nil {
		for _, s := range locSections {
			c.mark(s, SectionUnsupported)
		}
		return
	}
	st.pre = map[string]PathInfo{}
	defer func() { st.pre = nil }()
	entries := system
	if c.opts.HomeDirectories {
		entries = append(append([]locEntry(nil), system...), home...)
	}
	// One batch for every plain file the tables name and every directory
	// pass 1 would list (most of which a given host does not have).
	var plain []string
	for _, e := range entries {
		switch {
		case e.Dir:
			plain = append(plain, st.locListRoot(e.Path))
		case locHasMeta(e.Path):
			plain = append(plain, st.locListRoot(st.style.dir(e.Path)))
		default:
			plain = append(plain, e.Path)
		}
	}
	c.locPrefetch(ctx, plain)
	for i, e := range system {
		if c.locTimeUp(ctx, e.section()) {
			// Every row not visited leaves its section incomplete.
			c.locRowsNotVisited(system[i:], false)
			if c.opts.HomeDirectories {
				c.locRowsNotVisited(home, true)
			}
			return
		}
		c.locRunEntry(ctx, e)
	}
	if !c.opts.HomeDirectories {
		c.skip(SectionHomeDirectories)
		return
	}
	for i, e := range home {
		e.Home = true
		if c.locTimeUp(ctx, SectionHomeDirectories) {
			c.locRowsNotVisited(home[i:], true)
			return
		}
		c.locRunEntry(ctx, e)
	}
}

// locRowsNotVisited records the time limit on the section of every row the
// pass did not reach (and on home_directories for home rows), so no section
// whose rows were not all visited can read ok.
func (c *collection) locRowsNotVisited(rows []locEntry, home bool) {
	for _, e := range rows {
		c.limit(e.section(), "max_duration", c.stopDetail())
	}
	if home && len(rows) > 0 {
		c.limit(SectionHomeDirectories, "max_duration", c.stopDetail())
	}
}

// locTimeUp is timeUp for passes 1 and 2: when time is up, what was not
// visited could have been any kind of file (a row of material, a file a
// configuration names), so every section of the two passes gets the limit,
// not only the one being read.
func (c *collection) locTimeUp(ctx context.Context, section string) bool {
	if !c.timeUp(ctx, section) {
		return false
	}
	c.locStoppedAll()
	return true
}

// locStoppedAll records the time limit on every section of passes 1 and 2.
func (c *collection) locStoppedAll() {
	for _, s := range locPassSections(c) {
		c.limit(s, "max_duration", c.stopDetail())
	}
}

// locPassSections are the sections passes 1 and 2 report on in this run.
func locPassSections(c *collection) []string {
	s := append([]string(nil), locSections...)
	if c.opts.HomeDirectories {
		s = append(s, SectionHomeDirectories)
	}
	return s
}

// locSections are the sections passes 1 and 2 report on.
var locSections = []string{SectionCertificates, SectionPrivateKeys, SectionKeystores, SectionSSH, SectionConfigs}

// locRunEntry visits one table entry.
func (c *collection) locRunEntry(ctx context.Context, e locEntry) {
	st := c.locSt()
	files := c.locEntryFiles(ctx, e)
	if e.Kind != locNSS && e.Kind != locConfig {
		var paths []string
		for _, fi := range files {
			if fi.IsDir {
				continue
			}
			if fi.IsSymlink && fi.LinkTarget != "" {
				if e.SkipLinks {
					continue
				}
				paths = append(paths, joinLinkTarget(fi.Path, fi.LinkTarget))
			}
			paths = append(paths, fi.Path)
		}
		c.locPrefetch(ctx, paths)
		// The keys among them are probed in batches too (probe_remote.go).
		var keys []string
		for _, p := range paths {
			if r, ok := st.pre[p]; ok && r.IdentifyErr == nil && (r.Identity.Class == ClassPrivateKey || r.Identity.Class == ClassMixed) {
				keys = append(keys, p)
			}
		}
		c.jobPrefetchKeyProbes(ctx, keys)
	}
	switch e.Kind {
	case locNSS:
		c.locNSSDirs(ctx, e, files)
		return
	case locConfig:
		for _, fi := range files {
			c.locAddConfig(ctx, e, fi)
		}
		return
	}
	for _, fi := range files {
		if c.locTimeUp(ctx, e.section()) {
			return
		}
		if fi.IsDir {
			continue
		}
		if fi.IsSymlink && e.SkipLinks {
			c.registry.addLink(fi.Path, fi.LinkTarget)
			continue
		}
		info := fi
		v := locVisit{
			Path: fi.Path, Kind: e.Kind, Role: e.Role, Account: c.locAccount(e, fi.Path),
			Trust: e.Kind == locTrust, FoundBy: FoundByKnownLocation, Section: e.section(), Info: &info,
		}
		res, _ := c.locVisit(ctx, v)
		st.count(v.Section, res != locDenied && res != locFailed)
	}
}

// locAccount works out the account of an authorized_keys file.
func (c *collection) locAccount(e locEntry, p string) string {
	switch e.Account {
	case "", "@base":
		if e.Account == "@base" {
			return baseName(p)
		}
		return ""
	case "*":
		w := c.locSt().style
		_, pc := w.split(e.Path)
		_, fc := w.split(p)
		for i, s := range pc {
			if strings.Contains(s, "*") && i < len(fc) {
				return fc[i]
			}
		}
		return ""
	}
	return e.Account
}

// locAddConfig queues a configuration file for pass 2.
func (c *collection) locAddConfig(ctx context.Context, e locEntry, fi FileInfo) {
	st := c.locSt()
	if fi.IsDir || c.locExcluded(fi.Path) {
		return
	}
	product := e.Product
	if product == locBackendProduct {
		product = cfgBackendKeepKey(baseName(fi.Path))
	}
	if len(ConfigKeepWords(product)) == 0 {
		// A back-end with no parser (bind, libreswan): nothing reads it.
		return
	}
	info, err := c.locFollow(ctx, fi.Path, fi)
	if err != nil {
		c.locStatErr(SectionConfigs, fi.Path, err)
		return
	}
	if info.IsDir {
		return
	}
	st.configs = append(st.configs, locConfigFile{
		Path: fi.Path, Product: product, Base: st.style.up(st.style.dir(fi.Path), e.BaseUp),
		Info: info, FoundBy: FoundByKnownLocation,
	})
}

// locNSSDirs describes each directory among files that holds an NSS
// database, from the names of its files.
func (c *collection) locNSSDirs(ctx context.Context, e locEntry, files []FileInfo) {
	st := c.locSt()
	byDir := map[string][]string{}
	var dirs []string
	for _, fi := range files {
		d := st.style.dir(fi.Path)
		if _, ok := byDir[d]; !ok {
			dirs = append(dirs, d)
		}
		byDir[d] = append(byDir[d], baseName(fi.Path))
	}
	sort.Strings(dirs)
	for _, d := range dirs {
		ks, ok := IdentifyNSSDatabase(byDir[d])
		if !ok {
			continue
		}
		real := c.registry.realPath(d)
		if st.nss[real] {
			continue
		}
		st.nss[real] = true
		if c.files(e.section(), 1) == 0 {
			return
		}
		fi, err := c.target.Stat(ctx, d)
		if err != nil {
			c.locStatErr(e.section(), d, err)
			continue
		}
		ks.Location = c.locLocation(fi, d, FoundByKnownLocation, nil)
		ks.Unknown = locUnknownPlatformStore
		prod := &locProduced{stores: []Keystore{ks}}
		st.visited[real] = prod
		st.order = append(st.order, real)
		st.count(e.section(), true)
	}
}

// ---------------------------------------------------------------------------
// Visiting one file
// ---------------------------------------------------------------------------

// locVisit asks for one file to be visited.
type locVisit struct {
	Path    string
	Kind    locKind
	Role    string
	Account string
	Trust   bool
	FoundBy string
	UsedBy  []Usage
	// Section is where a failure to read is recorded.
	Section string
	// Info is the file as a listing saw it; nil means Stat it.
	Info *FileInfo
	// Charged: the caller has already charged this file to the run's file
	// budget (the sweep charges what it lists), so the visit does not again.
	Charged bool
}

// locResult is how a visit went.
type locResult int

const (
	locRead    locResult = iota // visited (whatever it held)
	locMissing                  // no such file, or a link to nothing
	locDenied                   // the account may not read it
	locFailed                   // another error
	locIsDir                    // a directory (the caller may list it)
	locNotFile                  // excluded, or not a regular file
	locStopped                  // a bound stopped the run
)

// locVisit visits one file: once per real path per run. A second sighting
// merges its FoundBy, UsedBy and role into the records of the first.
func (c *collection) locVisit(ctx context.Context, v locVisit) (locResult, FileInfo) {
	st := c.locSt()
	if c.locExcluded(v.Path) {
		return locNotFile, FileInfo{}
	}
	if c.locTimeUp(ctx, v.Section) {
		return locStopped, FileInfo{}
	}
	fi, err := c.locInfo(ctx, v)
	if err != nil {
		return c.locErrResult(v, err), FileInfo{}
	}
	fi, err = c.locFollow(ctx, v.Path, fi)
	if err != nil {
		return c.locErrResult(v, err), FileInfo{}
	}
	if fi.IsDir {
		return locIsDir, fi
	}
	if fi.WorldReadable == nil && fi.Mode == 0 {
		// Who can read it is not known: the section says so.
		st.noPerms[v.Section]++
	}
	real := c.registry.realPath(v.Path)
	if prod, ok := st.visited[real]; ok {
		locTouch(prod, v)
		return locRead, fi
	}
	if !v.Charged && c.files(v.Section, 1) == 0 {
		return locStopped, fi
	}
	prod := &locProduced{}
	st.visited[real] = prod
	st.order = append(st.order, real)
	res := c.locDispatch(ctx, v, fi, prod)
	return res, fi
}

// locInfo is the fullest description of v's path that is known: the batched
// Stat answer when it carries permissions (a Windows listing does not: its
// ACL is in the batch, not the listing), else the caller's (a listing's),
// else a Stat. A visit never uses a record without permissions while one
// with them is at hand.
func (c *collection) locInfo(ctx context.Context, v locVisit) (FileInfo, error) {
	st := c.locSt()
	if r, ok := st.pre[v.Path]; ok && r.StatErr == nil && locHasPerms(r.Info) {
		return r.Info, nil
	}
	if v.Info != nil && (locHasPerms(*v.Info) || v.Info.IsSymlink || v.Info.IsDir) {
		return *v.Info, nil
	}
	fi, err := c.locStat(ctx, v.Path)
	if err != nil {
		if v.Info != nil && !errors.Is(err, ErrNotExist) {
			return *v.Info, nil
		}
		return FileInfo{}, err
	}
	return fi, nil
}

// locHasPerms reports whether fi says who can read the file.
func locHasPerms(fi FileInfo) bool { return fi.WorldReadable != nil || fi.Mode != 0 }

// locErrResult turns a Target error into a result, recording what must be.
func (c *collection) locErrResult(v locVisit, err error) locResult {
	switch {
	case errors.Is(err, ErrNotExist):
		return locMissing
	case errors.Is(err, ErrPermission):
		c.partial(v.Section, fmt.Errorf("%s: %w", v.Path, ErrPermission))
		return locDenied
	case errors.Is(err, errNotRegular):
		return locNotFile
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		c.locStoppedAll()
		return locStopped
	}
	c.partial(v.Section, fmt.Errorf("%s: %w", v.Path, err))
	return locFailed
}

// locKeyLeaves names the certificates of a keystore's private-key entries
// (by fingerprint, and by alias): a trust store's trusted entries are
// anchors, a key's own certificate chain is not.
func locKeyLeaves(ks Keystore) map[string]bool {
	m := map[string]bool{}
	for _, e := range ks.Entries {
		if e.Kind != "private_key" {
			continue
		}
		if e.CertificateFingerprint != "" {
			m[e.CertificateFingerprint] = true
		}
		if e.Alias != "" {
			m["alias\x00"+e.Alias] = true
		}
	}
	return m
}

// locTouch merges a further sighting into a file's records. A sighting as a
// trust store makes the file's certificates anchors whichever sighting came
// first (a CA directory a table row saw, then SSLCACertificatePath named).
func locTouch(p *locProduced, v locVisit) {
	p.each(func(l *Location) { mergeLocation(l, Location{FoundBy: v.FoundBy, UsedBy: v.UsedBy}) })
	if v.Trust {
		leaves := map[string]bool{}
		for _, ks := range p.stores {
			for k := range locKeyLeaves(ks) {
				leaves[k] = true
			}
		}
		for i := range p.certs {
			c := p.certs[i]
			if leaves[c.FingerprintSHA256] || (c.Location.Container != "" && leaves["alias\x00"+c.Location.Alias]) {
				continue
			}
			p.certs[i] = ksTrustAnchor(c)
		}
	}
	if v.Role != "" {
		for i := range p.keys {
			if p.keys[i].Role == "" {
				p.keys[i].Role = v.Role
			}
		}
	}
}

// locLocation builds an item's Location from what Stat said. UsedBy is a copy:
// records of one file must not share a slice the registry appends to.
func (c *collection) locLocation(fi FileInfo, p, foundBy string, used []Usage) Location {
	l := Location{
		Path: p, Owner: fi.Owner, Group: fi.Group,
		WorldReadable: fi.WorldReadable, GroupReadable: fi.GroupReadable,
		SizeBytes: fi.Size, ModifiedAt: fi.ModifiedAt, FoundBy: foundBy,
		UsedBy: append([]Usage(nil), used...),
	}
	if !bool(c.locSt().style) && fi.Mode != 0 {
		l.Mode = fmt.Sprintf("%04o", fi.Mode&0o7777)
	}
	return l
}

// locCopy returns a Location whose UsedBy is its own.
func locCopy(l Location) Location {
	l.UsedBy = append([]Usage(nil), l.UsedBy...)
	return l
}

// locDispatch identifies a file and hands it to its parser.
func (c *collection) locDispatch(ctx context.Context, v locVisit, fi FileInfo, prod *locProduced) locResult {
	loc := c.locLocation(fi, v.Path, v.FoundBy, v.UsedBy)
	id, err := c.locIdentify(ctx, v.Path)
	if err != nil {
		return c.locErrResult(v, err)
	}
	f := &locFile{v: v, fi: fi, loc: loc, id: id, prod: prod}
	f.tooBig = fi.Size > c.opts.maxFileBytes()
	if f.tooBig {
		c.limit(v.Section, "max_file_bytes", fmt.Sprintf("did not read files over %d bytes", c.opts.maxFileBytes()))
	}
	base := strings.ToLower(baseName(v.Path))

	switch v.Kind {
	case locAuthorizedKeys:
		return c.locAuthorizedKeys(ctx, f)
	case locKnownHosts:
		return c.locKnownHosts(ctx, f)
	case locGnuPG:
		if strings.HasSuffix(base, ".key") || strings.HasSuffix(base, ".gpg") || strings.HasSuffix(base, ".kbx") ||
			strings.HasSuffix(base, ".asc") || id.Class == ClassPGP {
			return c.locGnuPGFile(ctx, f, base)
		}
	}

	switch id.Class {
	case ClassCertificate, ClassMixed, ClassPrivateKey:
		return c.locPEMOrKey(ctx, f)
	case ClassKeystore:
		return c.locKeystoreFile(ctx, f)
	case ClassPGP:
		return c.locGnuPGFile(ctx, f, base)
	case ClassPublicKey:
		if v.Kind == locSSHHost || (strings.HasPrefix(base, "ssh_host_") && strings.HasSuffix(base, ".pub")) {
			return c.locHostPublicKey(ctx, f)
		}
		return locRead
	case ClassUnknown:
		return c.locUnknown(ctx, f)
	}
	// Text, a request, a revocation list, DH parameters: visited, and no
	// section lists them.
	return locRead
}

// locFile is one file being dispatched.
type locFile struct {
	v      locVisit
	fi     FileInfo
	loc    Location
	id     Identity
	prod   *locProduced
	tooBig bool
}

// readable reports whether this file's bytes may be asked for: always on a
// local target, only public files remotely, never past the size bound.
func (c *collection) locReadable(f *locFile) bool {
	return !f.tooBig && (c.target.Local() || f.id.Public())
}

// locRead reads a file the caller has decided may be read. A local private
// file's bytes are the caller's to clear.
func (c *collection) locRead(ctx context.Context, f *locFile) ([]byte, bool) {
	var b []byte
	var err error
	unreadable := 0
	if pr, ok := c.target.(PublicReader); ok && !c.target.Local() {
		b, unreadable, err = pr.ReadPublic(ctx, f.v.Path)
	} else {
		b, err = c.target.ReadFile(ctx, f.v.Path)
	}
	if unreadable > 0 {
		what := "certificates"
		if unreadable == 1 {
			what = "certificate"
		}
		c.note(f.v.Section, fmt.Errorf("%s: %d %s in this file could not be read", f.v.Path, unreadable, what))
	}
	if err == nil {
		return b, true
	}
	switch {
	case errors.Is(err, ErrFileTooLarge):
		c.limit(f.v.Section, "max_file_bytes", fmt.Sprintf("did not read files over %d bytes", c.opts.maxFileBytes()))
	case errors.Is(err, ErrNoHostParser):
		c.partial(SectionCertificates, fmt.Errorf("%s: %w", f.v.Path, ErrNoHostParser))
	default:
		c.locErrResult(f.v, err)
	}
	return nil, false
}

// locPEMOrKey handles certificates, private keys and files holding both.
func (c *collection) locPEMOrKey(ctx context.Context, f *locFile) locResult {
	if !c.locReadable(f) {
		// Remote (or too large): a private key, or a certificate beside one.
		if k, ok := c.locKeyFromMarkers(ctx, f); ok {
			f.prod.keys = append(f.prod.keys, k)
		}
		if f.id.Class == ClassMixed || f.id.Class == ClassCertificate {
			c.partial(SectionCertificates, fmt.Errorf("%s: the certificates in it are not read (%s)", f.v.Path, c.locWhyNot(f)))
		}
		return locRead
	}
	b, ok := c.locRead(ctx, f)
	if !ok {
		return locFailed
	}
	defer clear(b)
	if bytesHasPrefix(b, magicPuTTY) {
		k, ok := ParsePuTTYKey(b)
		if !ok {
			c.note(SectionPrivateKeys, fmt.Errorf("%s: not a PuTTY key file this collector reads", f.v.Path))
			return locRead
		}
		c.locAddKey(f, k)
		return locRead
	}
	if bytesHasPrefix(b, magicSSH1) {
		c.locAddKey(f, locSSH1Key())
		return locRead
	}
	pc := ParsePEMFile(b, PEMLimits{MaxBlocks: c.opts.maxRecordsPerSection()})
	for _, cert := range pc.Certificates {
		cert.Location = locCopy(f.loc)
		if f.v.Trust {
			cert = ksTrustAnchor(cert)
		}
		f.prod.certs = append(f.prod.certs, cert)
	}
	for _, k := range pc.PrivateKeys {
		c.locAddKey(f, k)
	}
	if pc.Truncated {
		c.limit(f.v.Section, "max_records", fmt.Sprintf("read the first %d blocks of a file", c.opts.maxRecordsPerSection()))
	}
	if pc.Malformed > 0 {
		c.note(f.v.Section, fmt.Errorf("%s: %d blocks did not parse", f.v.Path, pc.Malformed))
	}
	return locRead
}

// locAddKey records a key found in a file, with its location and role.
func (c *collection) locAddKey(f *locFile, k PrivateKey) {
	k.Location = locCopy(f.loc)
	if k.Role == "" {
		k.Role = f.v.Role
	}
	if k.Protection == "" {
		k.Protection = KeyProtectionFile
	}
	f.prod.keys = append(f.prod.keys, k)
}

// locWhyNot says in a few words why a file was not read.
func (c *collection) locWhyNot(f *locFile) string {
	if f.tooBig {
		return "over the read bound"
	}
	return "not read over a remote connection"
}

// locRemoteKeyProbe describes a remote private key by a command on the host
// that prints only public material (probe_remote.go: ssh-keygen -y, openssl
// pkey -pubout). It is given the description the markers allow and returns
// it completed (algorithm, size, public key hash, encrypted or not) or with
// Unknown saying why not; false when the host could not be asked at all, and
// the markers' description stands. Location and Role are the caller's.
var locRemoteKeyProbe = jobProbeRemoteKey

// locRemoteKeystoreProbe is the same for keystores (openssl pkcs12 -nokeys,
// keytool -list); tryDefaults is the operator's default-password opt-in.
var locRemoteKeystoreProbe = jobProbeRemoteKeystore

// locKeyFromMarkers describes a private key that is not read, from its PEM
// label or magic number: the format always, the algorithm where the label
// names it, and whether it is encrypted where the label decides that (PKCS#8
// says it in the label; the traditional formats say it in a header the
// markers do not carry, so Encrypted stays nil).
func (c *collection) locKeyFromMarkers(ctx context.Context, f *locFile) (PrivateKey, bool) {
	k, ok := c.locKeyFromMarkersOnly(f)
	if !ok || c.target.Local() || locRemoteKeyProbe == nil ||
		k.Format == KeyFormatPuTTY || k.Format == KeyFormatSSH1 {
		return k, ok
	}
	if probed, ok := locRemoteKeyProbe(ctx, c, f.v.Path, f.id, k); ok {
		probed.Location, probed.Role = k.Location, k.Role
		if probed.Protection == "" {
			probed.Protection = KeyProtectionFile
		}
		return probed, true
	}
	return k, true
}

// locKeyFromMarkersOnly is locKeyFromMarkers without the probe.
func (c *collection) locKeyFromMarkersOnly(f *locFile) (PrivateKey, bool) {
	k := PrivateKey{Location: locCopy(f.loc), Role: f.v.Role, Protection: KeyProtectionFile}
	why := "remote: the key file is not read; size and public key need a command on the host"
	if f.tooBig {
		why = "the file is over the read bound; size and public key not read"
	}
	switch {
	case bytesHasPrefix(f.id.Magic, magicPuTTY):
		k.Format = KeyFormatPuTTY
	case bytesHasPrefix(f.id.Magic, magicSSH1):
		k = locSSH1Key()
		k.Location, k.Role = locCopy(f.loc), f.v.Role
		return k, true
	default:
		label := ""
		for _, l := range f.id.PEMLabels {
			if classifyPEMLabel(l) == pemPrivate {
				label = l
				break
			}
		}
		switch label {
		case "RSA PRIVATE KEY":
			k.Format, k.Algorithm = KeyFormatPKCS1, "RSA"
		case "EC PRIVATE KEY":
			k.Format, k.Algorithm = KeyFormatSEC1, "ECDSA"
		case "DSA PRIVATE KEY":
			k.Format, k.Algorithm = KeyFormatDSA, "DSA"
		case "PRIVATE KEY":
			k.Format, k.Encrypted = KeyFormatPKCS8, cfgBoolPtr(false)
		case "ENCRYPTED PRIVATE KEY":
			k.Format, k.Encrypted = KeyFormatPKCS8, cfgBoolPtr(true)
		case "OPENSSH PRIVATE KEY":
			k.Format = KeyFormatOpenSSH
		default:
			// Not a key format this package reads (an OpenVPN static key, a
			// label it does not know): locally it yields no key either.
			return PrivateKey{}, false
		}
	}
	k.Unknown = why
	return k, true
}

// locSSH1Key describes a legacy SSH-1 key file, which is only ever RSA.
func locSSH1Key() PrivateKey {
	return PrivateKey{Format: KeyFormatSSH1, Algorithm: "RSA", Protection: KeyProtectionFile,
		Unknown: "legacy SSH-1 key file; not parsed"}
}

func bytesHasPrefix(b, p []byte) bool { return len(b) >= len(p) && string(b[:len(p)]) == string(p) }

// locKeystoreFile handles a keystore file.
func (c *collection) locKeystoreFile(ctx context.Context, f *locFile) locResult {
	typ := f.id.KeystoreType
	if typ == KeystoreNSS {
		c.locNSSDirs(ctx, locEntry{Kind: locNSS, Section: f.v.Section}, []FileInfo{f.fi})
		return locRead
	}
	if typ == KeystoreKeychain {
		ks, ok := IdentifyKeychain(f.id.Magic)
		if !ok {
			ks = Keystore{Type: KeystoreKeychain, Opened: OpenedNot}
		}
		ks.Location = locCopy(f.loc)
		ks.Unknown = locUnknownPlatformStore
		f.prod.stores = append(f.prod.stores, ks)
		return locRead
	}
	if !c.locReadable(f) {
		if !c.target.Local() && locRemoteKeystoreProbe != nil {
			if kc, ok := locRemoteKeystoreProbe(ctx, c.target, f.v.Path, typ, c.opts.DefaultKeystorePasswords); ok {
				c.locAddKeystore(f, kc)
				return locRead
			}
		}
		f.prod.stores = append(f.prod.stores, Keystore{Location: locCopy(f.loc), Type: typ, Opened: OpenedNot, Unknown: c.locStoreWhyNot(f)})
		return locRead
	}
	b, ok := c.locRead(ctx, f)
	if !ok {
		return locFailed
	}
	defer clear(b)
	kc, err := locParseKeystore(typ, b, c.opts.DefaultKeystorePasswords)
	if err != nil {
		c.note(SectionKeystores, fmt.Errorf("%s: %s keystore did not parse in full", f.v.Path, typ))
	}
	c.locAddKeystore(f, kc)
	return locRead
}

// locUnknownPlatformStore is a keychain or NSS database's Unknown: the file is
// a platform store's, whose contents its own commands read.
const locUnknownPlatformStore = "contents are read from the platform store, not from the file"

// locStoreWhyNot is a keystore's Unknown when its file is not read.
func (c *collection) locStoreWhyNot(f *locFile) string {
	if f.tooBig {
		return "the file is over the read bound; entries not read"
	}
	return "remote: the file is not read; entries need a command on the host"
}

// locParseKeystore runs the parser for a keystore type.
func locParseKeystore(typ string, b []byte, tryDefaults bool) (KeystoreContents, error) {
	switch typ {
	case KeystoreJKS, KeystoreJCEKS:
		return ParseJKS(b, tryDefaults)
	case KeystorePKCS12:
		return ParsePKCS12(b, tryDefaults)
	case KeystoreBCFKS:
		return ParseBCFKS(b)
	case KeystoreBKS, KeystoreUBER:
		return ParseBKS(b)
	case KeystoreKeytab:
		return ParseKeytab(b)
	}
	return KeystoreContents{Keystore: Keystore{Type: typ, Opened: OpenedNot}}, fmt.Errorf("unknown keystore type")
}

// locAddKeystore records a keystore and the certificates inside it.
func (c *collection) locAddKeystore(f *locFile, kc KeystoreContents) {
	ks := kc.Keystore
	if ks.Type == "" {
		ks.Type = f.id.KeystoreType
	}
	if ks.Opened == "" {
		ks.Opened = OpenedNot
	}
	ks.Location = locCopy(f.loc)
	f.prod.stores = append(f.prod.stores, ks)
	leaves := locKeyLeaves(ks)
	for _, cert := range kc.Certificates {
		l := locCopy(f.loc)
		l.Container, l.Alias, l.Path = f.v.Path, cert.Location.Alias, ""
		cert.Location = l
		if f.v.Trust && !leaves[cert.FingerprintSHA256] && !leaves["alias\x00"+cert.Location.Alias] {
			cert = ksTrustAnchor(cert)
		}
		f.prod.certs = append(f.prod.certs, cert)
	}
	if kc.Truncated {
		c.limit(SectionKeystores, "max_records", fmt.Sprintf("listed the first %d entries of a keystore", DefaultMaxKeystoreEntries))
	}
	if kc.DefaultsNotTried != "" {
		c.note(SectionKeystores, fmt.Errorf("%s: default passwords not tried: %s", f.v.Path, kc.DefaultsNotTried))
	}
}

// locGnuPGFile handles a GnuPG home's files and OpenPGP keyrings.
func (c *collection) locGnuPGFile(ctx context.Context, f *locFile, base string) locResult {
	local := c.target.Local()
	switch {
	case strings.HasSuffix(base, ".key") && f.id.Class != ClassPGP:
		// private-keys-v1.d: never parsed; the first token says how the key
		// is protected, and that is all that is read.
		k := PrivateKey{Location: locCopy(f.loc), Role: "pgp", Format: KeyFormatPGP, Protection: KeyProtectionFile}
		if !local || f.tooBig {
			k.Unknown = "remote: the key file is not read; protection unknown"
			if f.tooBig {
				k.Unknown = "the file is over the read bound; protection unknown"
			}
			f.prod.keys = append(f.prod.keys, k)
			return locRead
		}
		b, ok := c.locRead(ctx, f)
		if !ok {
			return locFailed
		}
		defer clear(b)
		switch ClassifyGnuPGPrivateKeyFile(b) {
		case GnuPGKeyProtected:
			k.Encrypted = cfgBoolPtr(true)
		case GnuPGKeyUnprotected:
			k.Encrypted = cfgBoolPtr(false)
		case GnuPGKeyShadowed:
			k.Protection = KeyProtectionHSM
			k.Unknown = "a stub: the key is held on a smartcard or token"
		default:
			return locRead // not a GnuPG key file
		}
		f.prod.keys = append(f.prod.keys, k)
		return locRead
	case base == "trustdb.gpg":
		return locRead
	}
	for _, l := range f.id.PEMLabels {
		if strings.Contains(asciiUpper(l), "PRIVATE") || strings.Contains(asciiUpper(l), "SECRET") {
			f.prod.keys = append(f.prod.keys, PrivateKey{Location: locCopy(f.loc), Role: "pgp", Format: KeyFormatPGP,
				Protection: KeyProtectionFile, Unknown: "armoured OpenPGP secret key; not parsed"})
			return locRead
		}
	}
	ks := Keystore{Location: locCopy(f.loc), Type: KeystoreGnuPG, Opened: OpenedNot}
	switch {
	case base == "secring.gpg":
		ks.Protection = "GnuPG 1 secret keyring"
		ks.Unknown = "a secret keyring; not read"
	case len(f.id.PEMLabels) > 0:
		ks.Opened = OpenedWithoutPassword
		ks.Unknown = "armoured OpenPGP public keys; not listed"
	case !local || f.tooBig:
		ks.Unknown = c.locStoreWhyNot(f)
	default:
		b, ok := c.locRead(ctx, f)
		if !ok {
			return locFailed
		}
		entries, truncated := ParseOpenPGPPublicKeyring(b, DefaultMaxKeystoreEntries)
		clear(b)
		ks.Opened, ks.Entries = OpenedWithoutPassword, entries
		if !truncated {
			ks.EntryCount = ksIntPtr(len(entries))
		} else {
			c.note(SectionKeystores, fmt.Errorf("%s: keyring listed in part", f.v.Path))
		}
	}
	f.prod.stores = append(f.prod.stores, ks)
	return locRead
}

// locHostPublicKey reads an SSH host key's public half.
func (c *collection) locHostPublicKey(ctx context.Context, f *locFile) locResult {
	if !c.locReadable(f) {
		return locRead
	}
	b, ok := c.locRead(ctx, f)
	if !ok {
		return locFailed
	}
	if k, ok := ParseSSHPublicKeyFile(b); ok {
		c.registry.addHostPublicKey(k)
	}
	return locRead
}

// locUnknown handles a file whose markers say nothing definite: bare DER, an
// unknown binary. Locally it is parsed in memory; remotely it cannot be told
// apart from a private key and is counted.
func (c *collection) locUnknown(ctx context.Context, f *locFile) locResult {
	if !c.target.Local() {
		if len(f.id.Magic) > 0 && !isPrintableText(f.id.Magic) {
			c.locSt().unidentified[f.v.Section]++
		}
		return locRead
	}
	if f.tooBig || len(f.id.Magic) == 0 || f.id.Magic[0] != 0x30 {
		return locRead
	}
	b, ok := c.locRead(ctx, f)
	if !ok {
		return locFailed
	}
	defer clear(b)
	if cert, err := ParseCertificateDER(b); err == nil {
		cert.Location = locCopy(f.loc)
		if f.v.Trust {
			cert = ksTrustAnchor(cert)
		}
		f.prod.certs = append(f.prod.certs, cert)
		return locRead
	}
	if k, ok := ParsePrivateKeyDER(b); ok {
		c.locAddKey(f, k)
		return locRead
	}
	if kc, err := ParsePKCS12(b, c.opts.DefaultKeystorePasswords); err == nil {
		c.locAddKeystore(f, kc)
	}
	return locRead
}

// locAuthorizedKeys reads an authorized_keys file. Remotely only "type blob"
// crosses, so whether an entry is restricted is not known (nil).
func (c *collection) locAuthorizedKeys(ctx context.Context, f *locFile) locResult {
	a := AuthorizedKeysFile{Location: locCopy(f.loc), Account: f.v.Account}
	if f.fi.Size == 0 {
		f.prod.auth = append(f.prod.auth, a)
		return locRead
	}
	if !c.locReadable(f) {
		c.partial(SectionSSH, fmt.Errorf("%s: authorized_keys %s", f.v.Path, c.locWhyNot(f)))
		return locRead
	}
	b, ok := c.locRead(ctx, f)
	if !ok {
		return locFailed
	}
	keys, malformed, truncated := ParseAuthorizedKeys(b, c.opts.maxRecordsPerSection())
	if !c.target.Local() {
		for i := range keys {
			keys[i].Restricted, keys[i].CertificateAuthority = nil, nil
		}
		// Not an error, but not the whole answer: who may log in is known,
		// with what restrictions is not.
		c.locRemoteNote(SectionSSH, "remote: authorized_keys options do not cross; restrictions and cert-authority markers are not known")
	}
	a.Keys = keys
	if malformed > 0 {
		c.note(SectionSSH, fmt.Errorf("%s: %d lines did not parse", f.v.Path, malformed))
	}
	if truncated {
		c.limit(SectionSSH, "max_records", fmt.Sprintf("read the first %d keys of a file", c.opts.maxRecordsPerSection()))
	}
	f.prod.auth = append(f.prod.auth, a)
	return locRead
}

// locKnownHosts summarises a known_hosts file. Its lines begin with host
// names, so it is not public and is not read remotely: Identify calls it a
// public-key file (its lines hold key blobs), but what a remote public read
// returns is the blobs alone, without the host field that says whether an
// entry is hashed, and without the lines a marker (@revoked,
// @cert-authority) leads. Neither the count nor the hashing could be stated
// soundly from that, so remotely both are nil and the section says why.
func (c *collection) locKnownHosts(ctx context.Context, f *locFile) locResult {
	k := KnownHostsFile{Location: locCopy(f.loc)}
	if f.fi.Size == 0 {
		k.Entries, k.Hashed = ksIntPtr(0), cfgBoolPtr(false)
		f.prod.known = append(f.prod.known, k)
		return locRead
	}
	if !c.target.Local() {
		f.prod.known = append(f.prod.known, k)
		c.locRemoteNote(SectionSSH, "remote: known_hosts files are not read (their lines name other hosts); entries and hashing are not known")
		return locRead
	}
	if !c.locReadable(f) {
		// Recorded with its location and nil counts: it exists, and who can
		// read it is known; what it holds is not.
		c.partial(SectionSSH, fmt.Errorf("%s: known_hosts %s", f.v.Path, c.locWhyNot(f)))
		f.prod.known = append(f.prod.known, k)
		return locRead
	}
	b, ok := c.locRead(ctx, f)
	if !ok {
		return locFailed
	}
	n, hashed := SummariseKnownHosts(b)
	clear(b)
	k.Entries, k.Hashed = ksIntPtr(n), cfgBoolPtr(hashed)
	f.prod.known = append(f.prod.known, k)
	return locRead
}

// ---------------------------------------------------------------------------
// Flush and outcomes
// ---------------------------------------------------------------------------

// locFlushRecords hands every visited file's records to the registry and
// forgets them. Pass 3 and the sweep call it after their own visits.
func (c *collection) locFlushRecords() {
	st := c.locSt()
	for _, real := range st.order {
		p := st.visited[real]
		for _, x := range p.certs {
			c.registry.addCertificate(x)
		}
		for _, x := range p.keys {
			c.registry.addPrivateKey(x)
		}
		for _, x := range p.stores {
			c.registry.addKeystore(x)
		}
		for _, x := range p.auth {
			c.registry.addAuthorizedKeys(x)
		}
		for _, x := range p.known {
			c.registry.addKnownHosts(x)
		}
	}
	st.visited, st.order = map[string]*locProduced{}, nil
	secs := make([]string, 0, len(st.noPerms))
	for s := range st.noPerms {
		secs = append(secs, s)
	}
	sort.Strings(secs)
	for _, s := range secs {
		c.partial(s, fmt.Errorf("the permissions of %d files could not be read", st.noPerms[s]))
	}
	st.noPerms = map[string]int{}
}

// locFlush hands every record of passes 1 and 2 to the registry and decides
// their sections' outcomes. A section ends failed when it could look at
// nothing it tried, partial when something was recorded as missing from it,
// and ok otherwise.
func (c *collection) locFlush() {
	st := c.locSt()
	c.locFlushRecords()

	secs := make([]string, 0, len(st.unidentified))
	for s := range st.unidentified {
		secs = append(secs, s)
	}
	sort.Strings(secs)
	for _, s := range secs {
		c.partial(s, fmt.Errorf("remote: %d files in known locations could not be identified without reading them (bare DER or an unknown binary)", st.unidentified[s]))
	}

	sections := append([]string(nil), locSections...)
	if c.opts.HomeDirectories {
		sections = append(sections, SectionHomeDirectories)
	}
	for _, s := range sections {
		t := st.tally[s]
		if t != nil && t.bad > 0 && t.ok == 0 && !c.stopping(nil) {
			c.mark(s, SectionFailed)
			continue
		}
		c.mark(s, SectionOK)
	}
}
