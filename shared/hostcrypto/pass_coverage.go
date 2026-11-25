package hostcrypto

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Coverage: which directories one collection saw completely (Report.Coverage).
//
// It exists because a section's state is too coarse to retire an item: an
// unprivileged agent always reports certificates, private_keys, ssh and
// processes partial (/etc/ssl/private is unreadable, other users' processes
// invisible), so with a section rule a deleted key file would never be
// retired and its finding never close. A covered directory lets the
// platform retire a file-based item that sat directly in it and is absent
// now, whatever the sections say.
//
// A false "covered" retires an item that still exists, so every rule here
// errs toward "not covered":
//
//   - covDir does its OWN depth-0 listing of the directory (it never trusts a
//     listing made for another purpose), with no name filter and no size
//     bound, and gives up on any listing error, truncation or excess entries.
//   - Every regular file in that listing is handled: identified (through the
//     batch on a remote target), and visited through pass 1's dispatcher
//     when it is something the Report records. A file the dispatcher read
//     only in part, or whose records came out empty although its markers say
//     it holds something, makes the directory uncovered. A file over the
//     read bound or that the account may not read is recorded in
//     SkippedFiles with the reason, and the directory stays covered: the
//     platform keeps items at a skipped path.
//   - A remote file the markers cannot place (bare DER, an unknown binary)
//     makes the directory uncovered: only reading it could tell.
//   - An excluded directory, a directory with an excluded file, a home
//     directory without the opt-in, a top-level directory (/etc, C:\ProgramData),
//     and anything the deadline or the file budget cut, is not covered.
//   - Symbolic links are not visited: the item a link names lives in its
//     target's directory.
//   - Coverage is committed only when the records it vouches for are handed
//     to the registry (locFlushRecords), and dropped whole when the registry
//     had to drop any record at its bound (registry.finish).

// covMaxDirs bounds the directories one collection covers.
const covMaxDirs = 5000

// Entry bounds per directory: pass 1's crypto directories, and the parents
// of files a configuration or a process named.
const (
	covMaxEntriesKnown     = 4096
	covMaxEntriesNeighbour = 512
)

// covListAnySize is the size bound coverage lists with: every file, however
// large, is listed (a file over the read bound is then named in
// SkippedFiles), in a number every host's tools take.
const covListAnySize = 1 << 40

// The coverage limit's names: one section-less bound.
const (
	covLimitSection = "coverage"
	covLimitDirs    = "max_directories"
)

// covKnownFiles is what the caller already knows of a directory's files:
// their identities (the sweep identified them by content) and which are
// already charged to the file budget.
type covKnownFiles struct {
	ids     map[string]Identity
	charged map[string]bool
}

// covState is the coverage part of locState.
type covState struct {
	tried     map[string]bool
	pending   []string
	skipped   []SkippedFile
	committed int
}

// sweepCov is what the local sweep learned, for coverage.
func (st *locState) sweepCov() *covKnownFiles {
	if st.sweepKnown == nil {
		st.sweepKnown = &covKnownFiles{ids: map[string]Identity{}, charged: map[string]bool{}}
	}
	return st.sweepKnown
}

func (st *locState) cov() *covState {
	if st.coverage == nil {
		st.coverage = &covState{tried: map[string]bool{}}
	}
	return st.coverage
}

// covRecordable reports whether a file of this identity holds something the
// Report records under its path, and so must come out of its visit with a
// record. Text, requests, revocation lists, parameters and bare public keys
// (a host key's public half is recorded by fingerprint, not path) do not.
func (c *collection) covRecordable(id Identity) bool {
	switch id.Class {
	case ClassCertificate, ClassMixed, ClassPrivateKey, ClassKeystore, ClassPGP:
		return true
	case ClassUnknown:
		// Locally a DER structure is parsed; anything else is nothing.
		return c.target.Local() && len(id.Magic) > 0 && id.Magic[0] == 0x30
	}
	return false
}

// covUnplaceable reports a file whose markers cannot say what it is on this
// target: remotely, a binary of no known format.
func (c *collection) covUnplaceable(id Identity) bool {
	return !c.target.Local() && id.Class == ClassUnknown && len(id.Magic) > 0 && !isPrintableText(id.Magic)
}

// covHome reports whether dir is a home directory or under one.
func (c *collection) covHome(dir string) bool {
	st := c.locSt()
	w := st.style
	d := w.clean(dir)
	if bool(w) {
		l := strings.ToLower(d)
		return len(l) > 3 && l[1] == ':' && (strings.HasPrefix(l[2:], `\users\`) || l[2:] == `\users`)
	}
	for _, h := range []string{"/home", "/root", "/Users", "/var/root", "/private/var/root"} {
		if d == h || strings.HasPrefix(d, h+"/") {
			return true
		}
	}
	return false
}

// covTopLevel reports a directory too general to cover: the filesystem root
// or one component below it (/etc, /usr, C:\ProgramData).
func (c *collection) covTopLevel(dir string) bool {
	_, comps := c.locSt().style.split(dir)
	n := 0
	for _, s := range comps {
		if s != "" {
			n++
		}
	}
	return n < 2
}

// covDir tries to cover one directory. foundBy is what a file first found
// here is recorded as; section is where its failures go; maxEntries bounds
// the listing. It returns whether the directory is (now) pending coverage.
func (c *collection) covDir(ctx context.Context, dir, foundBy, section string, maxEntries int, known *covKnownFiles) bool {
	if known == nil {
		known = &covKnownFiles{}
	}
	st := c.locSt()
	cs := st.cov()
	dir = st.style.clean(dir)
	if dir == "" || cs.tried[dir] {
		return false
	}
	cs.tried[dir] = true
	if c.covTopLevel(dir) || c.locExcluded(dir) || (c.covHome(dir) && !c.opts.HomeDirectories) {
		return false
	}
	if len(cs.pending)+cs.committed >= covMaxDirs {
		c.limit(covLimitSection, covLimitDirs, fmt.Sprintf("covered the first %d directories", covMaxDirs))
		return false
	}
	if c.timeUp(ctx, section) {
		return false
	}
	if r, ok := st.pre[dir]; ok && r.StatErr != nil {
		return false // the batch found no such directory (or could not stat it)
	}
	files, err := c.target.List(ctx, dir, ListOptions{MaxDepth: 0, MaxFiles: maxEntries + 1, MaxSizeBytes: covListAnySize, Exclude: c.opts.ExcludePaths})
	if err != nil || len(files) > maxEntries {
		return false
	}
	var regular []FileInfo
	for _, fi := range files {
		switch {
		case fi.IsDir || fi.IsSymlink:
			continue
		case st.style.dir(fi.Path) != dir && st.style.clean(st.style.dir(fi.Path)) != dir:
			return false // not a direct entry: the listing is not what was asked
		}
		regular = append(regular, fi)
	}
	// An excluded file in the directory was not looked at.
	for _, ex := range c.opts.ExcludePaths {
		if st.style.clean(st.style.dir(ex)) == dir {
			return false
		}
	}
	// Remote: every file's Stat and Identify in one batch (BatchTarget); a
	// target without the batch answers them one by one.
	if !c.target.Local() {
		if st.pre == nil {
			st.pre = map[string]PathInfo{}
			defer func() { st.pre = nil }()
		}
		paths := make([]string, 0, len(regular))
		for _, fi := range regular {
			paths = append(paths, fi.Path)
		}
		c.locPrefetch(ctx, paths)
	}
	var skipped []SkippedFile
	for _, fi := range regular {
		if c.timeUp(ctx, section) {
			return false
		}
		if c.locExcluded(fi.Path) {
			return false
		}
		if fi.Size > c.opts.maxFileBytes() {
			// Not read, and its markers past the read window are not known
			// either: skipped, with the reason, so an item at this path is
			// not taken for gone.
			skipped = append(skipped, SkippedFile{Path: fi.Path, Reason: fmt.Sprintf("larger than the read bound (%d bytes)", c.opts.maxFileBytes())})
			continue
		}
		real := c.registry.realPath(fi.Path)
		prod, seen := st.visited[real]
		if !seen {
			id, ok := known.ids[fi.Path]
			var err error
			if !ok {
				id, err = c.locIdentify(ctx, fi.Path)
			}
			switch {
			case errors.Is(err, ErrNotExist):
				continue // gone since the listing: nothing to vouch for
			case errors.Is(err, ErrPermission):
				skipped = append(skipped, SkippedFile{Path: fi.Path, Reason: "permission denied"})
				continue
			case errors.Is(err, errNotRegular):
				continue
			case err != nil:
				return false
			}
			if c.covUnplaceable(id) {
				return false
			}
			if !c.covRecordable(id) {
				if !known.charged[fi.Path] && c.files(section, 1) == 0 {
					return false
				}
				continue
			}
			info := fi
			res, _ := c.locVisit(ctx, locVisit{Path: fi.Path, Kind: locMaterial, FoundBy: foundBy, Section: section, Info: &info, Charged: known.charged[fi.Path]})
			switch res {
			case locRead:
			case locMissing:
				continue
			case locDenied:
				skipped = append(skipped, SkippedFile{Path: fi.Path, Reason: "permission denied"})
				continue
			default:
				return false
			}
			prod = st.visited[real]
			if prod == nil {
				return false
			}
		}
		switch {
		case prod.res == locDenied:
			skipped = append(skipped, SkippedFile{Path: fi.Path, Reason: "permission denied"})
			continue
		case prod.res != locRead:
			return false
		case prod.tooBig:
			skipped = append(skipped, SkippedFile{Path: fi.Path, Reason: fmt.Sprintf("larger than the read bound (%d bytes)", c.opts.maxFileBytes())})
		case prod.incomplete:
			return false
		case c.covRecordable(prod.id) && prod.records() == 0:
			return false
		case c.covUnplaceable(prod.id):
			return false
		}
	}
	cs.pending = append(cs.pending, dir)
	cs.skipped = append(cs.skipped, skipped...)
	return true
}

// covCommit moves pending coverage into the Report: its records have just
// been handed to the registry.
func (c *collection) covCommit() {
	cs := c.locSt().cov()
	if len(cs.pending) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	cv := &c.report.Coverage
	cv.Directories = append(cv.Directories, cs.pending...)
	cv.SkippedFiles = append(cv.SkippedFiles, cs.skipped...)
	sort.Strings(cv.Directories)
	sort.Slice(cv.SkippedFiles, func(i, j int) bool { return cv.SkippedFiles[i].Path < cv.SkippedFiles[j].Path })
	cs.committed += len(cs.pending)
	cs.pending, cs.skipped = nil, nil
}

// covNeighbour covers the directory of a file a configuration or a process
// named, when that directory is small.
func (c *collection) covNeighbour(ctx context.Context, file, section string) {
	c.covDir(ctx, c.locSt().style.dir(file), FoundByNeighbour, section, covMaxEntriesNeighbour, nil)
}

// covKnownCandidates are the directories pass 1 may cover for one table row:
// the row's directory and the directories its files were listed in. Rows of
// configuration and NSS databases are not candidates (their directories are
// general, or hold one database), nor rows whose path is a single file.
func covKnownCandidates(e locEntry, files []FileInfo, style locStyle) []string {
	if !e.Dir || e.Kind == locConfig || e.Kind == locNSS {
		return nil
	}
	var out []string
	if !locHasMeta(e.Path) {
		out = append(out, e.Path)
	}
	for _, fi := range files {
		if fi.IsDir {
			out = append(out, fi.Path)
			continue
		}
		out = append(out, style.dir(fi.Path))
	}
	return out
}

// covKnown covers pass 1's candidate directories, in order, once each.
func (c *collection) covKnown(ctx context.Context, dirs []string) {
	for _, d := range dirs {
		if c.locTimeUp(ctx, SectionCertificates) {
			return
		}
		c.covDir(ctx, d, FoundByKnownLocation, SectionCertificates, covMaxEntriesKnown, nil)
	}
}
