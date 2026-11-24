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
// This file is the engine. It returns hits; dispatching them to the parsers
// is the next slice's.

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

func interestingName(path string) bool {
	return sweepExtensions[extOf(strings.ToLower(baseName(path)))]
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

		for _, fi := range files {
			if fi.IsSymlink || fi.IsDir {
				// A link is the file it points at, which a pass reaches by
				// its own path; following it here could leave the root.
				continue
			}
			if ctx.Err() != nil {
				c.timeUp(ctx, SectionSweep)
				partial = true
				break
			}
			id, ok, readErr := sweepIdentify(ctx, c.target, local, fi.Path)
			if readErr {
				unreadable++
			}
			if !ok {
				continue
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
