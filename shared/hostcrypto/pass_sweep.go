package hostcrypto

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Pass 4, the sweep: a bounded walk of the configured roots.
//
// LOCAL: every file is identified by content, so a private key called
// backup.txt is found. REMOTE: identifying every file would be one command per
// file over the connection, so files are first classified by NAME
// ([ClassifyNamed] with no content) and only the candidates (a name that
// classifies, or one of the interesting extensions) are identified on the
// host. A remote sweep therefore misses the key called backup.txt, which is
// what the design says the remote sweep is: by name and size.
//
// sweep is the engine and returns hits; passSweep (below) dispatches each
// through pass 1's dispatcher. A file is charged to the budget once, when it
// is listed: what was listed can be visited.

// sweepMaxDepth bounds how deep the sweep descends below a root.
const sweepMaxDepth = 32

// sweepHit is one file the sweep thinks worth a parser.
type sweepHit struct {
	Info     FileInfo
	Identity Identity
}

// sweepExtensions are the names worth a look even when content alone does not
// say (bare DER, an empty or unreadable start) and, remotely, the only names
// identified at all besides the ones ClassifyNamed recognises.
var sweepExtensions = map[string]bool{
	".pem": true, ".key": true, ".crt": true, ".cer": true, ".der": true,
	".p12": true, ".pfx": true, ".jks": true, ".jceks": true, ".bcfks": true,
	".bks": true, ".keystore": true, ".truststore": true, ".kdb": true,
	".ppk": true, ".gpg": true, ".asc": true, ".keytab": true, ".kt": true,
	".pub": true,
}

// sweepNames are extensionless names worth identifying remotely: the
// default names of SSH keys. ssh_host_*_key is matched by pattern.
var sweepNames = map[string]bool{
	"id_rsa": true, "id_dsa": true, "id_ecdsa": true, "id_ed25519": true, "id_xmss": true,
	"id_ecdsa_sk": true, "id_ed25519_sk": true, "identity": true,
}

func interestingName(path string) bool {
	base := strings.ToLower(baseName(path))
	if sweepExtensions[extOf(base)] || sweepNames[base] {
		return true
	}
	return strings.HasPrefix(base, "ssh_host_") && strings.HasSuffix(base, "_key")
}

// sweep walks roots within the run's budget and returns the hits, sorted by
// path. It marks SectionSweep: skipped when there are no roots; ok when every
// root was walked in full; partial when a root was cut short (a bound,
// unreadable directories or files) or failed while another succeeded; failed
// when every root failed. A root that does not exist was looked at and holds
// nothing, which is not a failure.
func sweep(ctx context.Context, c *collection, roots []string) []sweepHit {
	if len(roots) == 0 {
		c.skip(SectionSweep)
		return nil
	}
	local := c.target.Local()
	if !local {
		// Said as a limit, so the section reads partial: a remote sweep
		// cannot find the key called backup.txt.
		c.limit(SectionSweep, "remote_by_name", "remote: files are identified by name and size, not by content")
	}
	var hits []sweepHit
	failed, partial := 0, false
	unreadable := 0

	for _, root := range roots {
		if c.timeUp(ctx, SectionSweep) {
			partial = true
			break
		}
		left := c.budget.remaining()
		if left == 0 {
			c.limit(SectionSweep, "max_files", fmt.Sprintf("stopped after %d files", c.opts.maxFiles()))
			partial = true
			break
		}
		files, err := c.target.List(ctx, root, ListOptions{
			MaxDepth:     sweepMaxDepth,
			MaxFiles:     left,
			MaxSizeBytes: c.opts.maxFileBytes(),
			Exclude:      c.opts.ExcludePaths,
		})
		var lerr *ListError
		switch {
		case err == nil:
		case errors.As(err, &lerr):
			partial = true
			if lerr.DeniedCount > 0 {
				c.note(SectionSweep, fmt.Errorf("%s: %d directories could not be read", root, lerr.DeniedCount))
			}
			if lerr.Truncated {
				c.limit(SectionSweep, "max_files", fmt.Sprintf("stopped after %d files", c.opts.maxFiles()))
			}
			if lerr.OverSize > 0 {
				c.limit(SectionSweep, "max_file_bytes", fmt.Sprintf("skipped files over %d bytes", c.opts.maxFileBytes()))
			}
			if lerr.Unreadable > 0 {
				c.limit(SectionSweep, "unreadable", fmt.Sprintf("%d entries could not be read", lerr.Unreadable))
			}
		case errors.Is(err, ErrNotExist):
			continue
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			c.timeUp(ctx, SectionSweep)
			partial = true
		default:
			failed++
			c.note(SectionSweep, fmt.Errorf("%s: %w", root, err))
			continue
		}
		if granted := c.files(SectionSweep, len(files)); granted < len(files) {
			files = files[:granted]
			partial = true
		}

		// Remote: the candidates' Identify and Stat in one host program per
		// batch (BatchTarget), not two per file.
		pre := map[string]PathInfo{}
		if bt, ok := c.target.(BatchTarget); ok && !local {
			var want []string
			for _, fi := range files {
				if !fi.IsSymlink && !fi.IsDir && (ClassifyNamed(fi.Path, nil, nil).Class != ClassUnknown || interestingName(fi.Path)) {
					want = append(want, fi.Path)
				}
			}
			if len(want) > 1 {
				got, _ := bt.StatIdentifyMany(ctx, want)
				for _, r := range got {
					pre[r.Path] = r
				}
			}
		}
		for _, fi := range files {
			if fi.IsSymlink || fi.IsDir {
				// A link is the file it points at, which a pass reaches by
				// its own path; following it here could leave the root. It
				// is remembered, so the registry knows the two are one.
				c.registry.addLink(fi.Path, fi.LinkTarget)
				continue
			}
			if ctx.Err() != nil {
				c.timeUp(ctx, SectionSweep)
				partial = true
				break
			}
			var id Identity
			var ok, readErr bool
			if r, have := pre[fi.Path]; have && r.IdentifyErr == nil {
				id = r.Identity
				ok = !((id.Class == ClassText || id.Class == ClassUnknown) && !interestingName(fi.Path))
			} else {
				id, ok, readErr = sweepIdentify(ctx, c.target, local, fi.Path)
			}
			if readErr {
				unreadable++
			}
			if !ok {
				continue
			}
			if fi.WorldReadable == nil {
				// A remote Windows listing carries no ACL (one Get-Acl per
				// file is too slow): Stat each HIT, not each file.
				if r, have := pre[fi.Path]; have && r.StatErr == nil {
					fi = r.Info
				} else if st, serr := c.target.Stat(ctx, fi.Path); serr == nil {
					fi = st
				}
			}
			hits = append(hits, sweepHit{Info: fi, Identity: id})
		}
	}

	if unreadable > 0 {
		partial = true
		c.note(SectionSweep, fmt.Errorf("%d files could not be identified", unreadable))
	}
	switch {
	case failed == len(roots):
		c.mark(SectionSweep, SectionFailed)
	case failed > 0 || partial:
		c.mark(SectionSweep, SectionPartial)
	default:
		c.mark(SectionSweep, SectionOK)
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].Info.Path < hits[j].Info.Path })
	return hits
}

// sweepIdentify decides whether one file is a hit. It returns the identity,
// whether to keep it, and whether identification failed (unreadable).
func sweepIdentify(ctx context.Context, t Target, local bool, path string) (Identity, bool, bool) {
	if !local {
		byName := ClassifyNamed(path, nil, nil)
		if byName.Class == ClassUnknown && !interestingName(path) {
			return Identity{}, false, false
		}
	}
	id, err := t.Identify(ctx, path)
	if err != nil {
		return Identity{}, false, true
	}
	if (id.Class == ClassText || id.Class == ClassUnknown) && !interestingName(path) {
		return id, false, false
	}
	return id, true, false
}

// passSweep is pass 4: each sweep hit is visited through pass 1's
// dispatcher (locVisit) with FoundBy sweep, so a file the sweep finds gets
// the same record, and meets the same remote rules, as one found anywhere
// else; then the records go to the registry, which merges a hit some
// earlier pass already found.
func passSweep(ctx context.Context, c *collection) {
	if len(c.opts.SweepRoots) > 0 && c.stoppedBefore(ctx, SectionSweep) {
		return
	}
	hits := sweep(ctx, c, c.opts.SweepRoots)
	if !c.target.Local() {
		// A remote sweep's key files are probed in batches, not one host
		// program each (probe_remote.go); a hit that is no key answers
		// NOTKEY at once.
		paths := make([]string, 0, len(hits))
		for _, h := range hits {
			paths = append(paths, h.Info.Path)
		}
		// The hits' Stat and Identify are batched as pass 1's are
		// (locPrefetch), and their keys probed in batches.
		st := c.locSt()
		if st.pre == nil {
			st.pre = map[string]PathInfo{}
			defer func() { st.pre = nil }()
		}
		c.locPrefetch(ctx, paths)
		c.jobPrefetchKeyProbes(ctx, paths)
	}
	for _, h := range hits {
		if c.timeUp(ctx, SectionSweep) {
			break
		}
		info := h.Info
		c.locVisit(ctx, locVisit{Path: info.Path, Kind: locMaterial, FoundBy: FoundBySweep, Section: SectionSweep, Info: &info, Charged: true})
	}
	c.locFlushRecords()
}
