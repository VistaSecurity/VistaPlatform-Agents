package hostcrypto

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Pass 2, follow the configuration: every configuration file pass 1 found is
// read through collection.readConfig (the ONE way configuration is read; a
// test holds this file and pass_known.go to it), parsed by its product's
// parser with includes resolved through readConfig too, and recorded as
// CryptoConfig. Then every file it names (a certificate, a key, a keystore, a
// trust store, DH parameters, a revocation list) is visited wherever it is,
// and gets the configuration as its UsedBy (the file holding the directive,
// the root that includes it, the product and the block) and FoundBy
// "config".
//
// Every reference ends with a Status: found, missing, unreadable (Errors
// says why), or not_followed. A missing file is a fact about the host, not a
// failure to look, so it is recorded on the reference and not in Errors.
//
// References that cannot be resolved to one file are not guessed at: a path
// with a variable ($ssl_server_name), an OpenSSH % token or a ~ (each user's
// home) is not followed.

// passFollowConfiguration is pass 2. It ends by handing every record of
// passes 1 and 2 to the registry.
func passFollowConfiguration(ctx context.Context, c *collection) {
	st := c.locSt()
	defer c.locFlush()
	// When time is already up, pass 1's records still go to the registry
	// (the deferred flush), and pass 2's sections say they were cut.
	if c.stoppedBefore(ctx, locPassSections(c)...) {
		return
	}
	for i := 0; i < len(st.configs); i++ {
		if c.locTimeUp(ctx, SectionConfigs) {
			return
		}
		c.locReadConfig(ctx, st.configs[i])
	}
}

// locCfgKey identifies one configuration file read for one product.
func (c *collection) locCfgKey(product, p string) string {
	return product + "\x00" + c.registry.realPath(p)
}

// locSource is one file of a configuration as the parser saw it: the root,
// or a file one of its includes read. It is how a reference is credited to
// the file that holds its directive.
type locSource struct {
	path string
	text []byte
}

// locIncl is what the resolver learned: every file read, in order, and the
// Status of each include pattern.
type locIncl struct {
	sources []locSource
	status  map[string]string
}

// locReadConfig reads, parses and records one configuration file, after
// following what it names, so its references carry their Status.
func (c *collection) locReadConfig(ctx context.Context, cf locConfigFile) {
	st := c.locSt()
	key := c.locCfgKey(cf.Product, cf.Path)
	if done, ok := st.cfgDone[key]; ok {
		// Read already: this sighting adds its FoundBy and UsedBy only.
		for _, cfg := range done {
			mergeLocation(&cfg.Location, Location{FoundBy: cf.FoundBy, UsedBy: cf.UsedBy})
			c.registry.addConfig(cfg)
		}
		return
	}
	if st.included[key] {
		// Read as another file's include, and recorded as part of it.
		return
	}
	if c.files(SectionConfigs, 1) == 0 {
		return
	}
	text, err := c.readConfig(ctx, cf.Path, cf.Product)
	if err != nil {
		c.locConfigErr(cf.Path, err)
		return
	}
	st.count(SectionConfigs, true)

	inc := &locIncl{sources: []locSource{{path: cf.Path, text: text}}, status: map[string]string{}}
	var cfgs []CryptoConfig
	if strings.HasPrefix(cf.Product, locBackendProduct) {
		cfgs = ParseCryptoPolicyBackend(baseName(cf.Path), text)
	} else if parse := ConfigParserFor(cf.Product); parse != nil {
		cfgs = parse(text, c.locResolver(ctx, cf, inc))
	}
	loc := c.locLocation(cf.Info, cf.Path, cf.FoundBy, cf.UsedBy)
	for i := range cfgs {
		for j := range cfgs[i].References {
			if c.locTimeUp(ctx, SectionConfigs) {
				break
			}
			cfgs[i].References[j].Status = c.locFollowRef(ctx, cf, cfgs[i], cfgs[i].References[j], inc)
		}
		cfgs[i].Location = locCopy(loc)
		c.registry.addConfig(cfgs[i])
	}
	st.cfgDone[key] = cfgs
}

// locConfigErr records a configuration file that could not be read for a
// reason other than its absence.
func (c *collection) locConfigErr(p string, err error) {
	st := c.locSt()
	switch {
	case errors.Is(err, ErrNotExist):
		// Gone between pass 1's Stat and this read.
	case errors.Is(err, ErrFileTooLarge):
		c.limit(SectionConfigs, "max_file_bytes", fmt.Sprintf("did not read configuration over %d bytes", c.opts.maxFileBytes()))
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		c.locStoppedAll()
	default:
		st.count(SectionConfigs, false)
		c.partial(SectionConfigs, fmt.Errorf("%s: %w", p, err))
	}
}

// locResolver returns the IncludeResolver for one root configuration file:
// a pattern is resolved against the file's base directory, expanded through
// the Target (a directory includes its files, as Apache reads it), and each
// file read through readConfig with the root's product, within the parser's
// byte budget and the run's file budget. Each file read joins inc.sources;
// each pattern's outcome is inc.status[pattern].
func (c *collection) locResolver(ctx context.Context, cf locConfigFile, inc *locIncl) IncludeResolver {
	st := c.locSt()
	return func(pattern string, maxBytes int64) []IncludedFile {
		paths, status := c.locIncludePaths(ctx, cf, pattern)
		var out []IncludedFile
		var used int64
		failed := false
		for _, p := range paths {
			if c.locTimeUp(ctx, SectionConfigs) || c.files(SectionConfigs, 1) == 0 {
				break
			}
			text, err := c.readConfig(ctx, p, cf.Product)
			if err != nil {
				if !errors.Is(err, ErrNotExist) {
					failed = true
					c.locConfigErr(p, err)
				}
				continue
			}
			if used+int64(len(text)) > maxBytes {
				c.limit(SectionConfigs, "max_file_bytes", "stopped following includes at the 16 MiB budget of one file")
				break
			}
			used += int64(len(text))
			st.included[c.locCfgKey(cf.Product, p)] = true
			inc.sources = append(inc.sources, locSource{path: p, text: text})
			out = append(out, IncludedFile{Path: p, Text: text})
		}
		switch {
		case status != "":
		case len(out) > 0:
			status = RefFound
		case failed:
			status = RefUnreadable
		default:
			status = RefMissing
		}
		if have := inc.status[pattern]; have != RefFound {
			inc.status[pattern] = status
		}
		return out
	}
}

// locIncludePaths turns an include pattern into the files to read, sorted
// as the products read a glob. A status is returned only when the pattern
// is not followed at all.
func (c *collection) locIncludePaths(ctx context.Context, cf locConfigFile, pattern string) ([]string, string) {
	st := c.locSt()
	p, ok := c.locResolvePath(cf, pattern)
	if !ok {
		return nil, RefNotFollowed
	}
	if c.locExcluded(p) {
		return nil, RefNotFollowed
	}
	var files []FileInfo
	if locHasMeta(p) {
		files = c.locFiles(ctx, SectionConfigs, st.style.dir(p), 0, []string{baseName(p)}, 0)
	} else {
		fi, err := c.target.Stat(ctx, p)
		switch {
		case err != nil:
			// Let the read say what is wrong with it (missing, denied).
			return []string{p}, ""
		case fi.IsDir:
			files = c.locList(ctx, SectionConfigs, p, 0, nil)
		default:
			return []string{p}, ""
		}
	}
	out := make([]string, 0, len(files))
	for _, fi := range files {
		out = append(out, fi.Path)
	}
	sort.Strings(out)
	return out, ""
}

// locResolvePath makes a path a configuration names absolute, against the
// configuration's base directory; on Unix an absolute path takes the run's
// root prefix (empty in production). It refuses what is not one path: a
// variable, an OpenSSH % token, a ~.
func (c *collection) locResolvePath(cf locConfigFile, p string) (string, bool) {
	st := c.locSt()
	p = strings.TrimSpace(p)
	if p == "" || strings.ContainsAny(p, "$%~{") {
		return "", false
	}
	p = st.style.clean(p)
	if bool(st.style) && strings.HasPrefix(strings.ToUpper(p), locProgramDataToken) {
		// OpenSSH for Windows writes its own paths as __PROGRAMDATA__\ssh\...
		pd := st.win.ProgramData
		if pd == "" {
			pd = locDefaultWinRoots("C:").ProgramData
		}
		p = pd + p[len(locProgramDataToken):]
	}
	if st.style.isAbs(p) {
		if !st.style {
			return st.style.resolve("/", st.root+p), true
		}
		return p, true
	}
	return st.style.resolve(cf.Base, p), true
}

// locProgramDataToken is how OpenSSH for Windows' sshd_config names
// %ProgramData% (its shipped HostKey lines use it).
const locProgramDataToken = "__PROGRAMDATA__"

// locRefRole is the role a configuration gives the key it names, where the
// product makes it certain.
func locRefRole(product string) string {
	switch product {
	case "sshd":
		return "ssh_host_key"
	case "ssh":
		return "ssh_user_key"
	case "nginx", "apache", "haproxy", "postfix":
		return "tls"
	}
	return ""
}

// locRefSection is the section a referenced file's failures belong to.
func locRefSection(kind string) string {
	switch kind {
	case "private_key":
		return SectionPrivateKeys
	case "keystore":
		return SectionKeystores
	}
	return SectionCertificates
}

// locRefSource is the file of a configuration that holds a reference's
// directive: the first source (the root, then each include in the order it
// was read) with a line naming both the directive's keyword and the path (or,
// for a path the parser rebuilt against a base, the path's file name). The
// root when none does.
func locRefSource(inc *locIncl, ref ConfigReference) string {
	fields := strings.Fields(ref.Directive)
	word := ""
	if len(fields) > 0 {
		word = strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(fields[len(fields)-1], "-D"), "."))
	}
	for _, try := range []string{ref.Path, baseName(ref.Path)} {
		if try == "" {
			continue
		}
		for _, s := range inc.sources {
			for _, line := range strings.Split(string(s.text), "\n") {
				if strings.Contains(line, try) && strings.Contains(strings.ToLower(line), word) {
					return s.path
				}
			}
		}
	}
	return inc.sources[0].path
}

// locFollowRef visits one file a configuration names and returns its
// Status.
func (c *collection) locFollowRef(ctx context.Context, cf locConfigFile, cfg CryptoConfig, ref ConfigReference, inc *locIncl) string {
	st := c.locSt()
	src := locRefSource(inc, ref)
	u := Usage{Kind: "config", ConfigPath: src, Directive: ref.Directive, Product: cfg.Product, Context: cfg.Context}
	if src != cf.Path {
		u.RootConfigPath = cf.Path
	}
	usage := []Usage{u}
	if ref.Kind == "include" {
		// The parsers follow their own includes through the resolver. A JVM
		// option naming a security properties file is the one include that
		// is another product's configuration.
		if cf.Product == "java-options" {
			p, ok := c.locResolvePath(cf, ref.Path)
			if !ok || c.locExcluded(p) {
				return RefNotFollowed
			}
			return c.locQueueConfig(ctx, p, "java", usage)
		}
		for _, k := range []string{ref.Path, strings.TrimSuffix(ref.Path, "/") + "/*"} {
			if s, ok := inc.status[k]; ok {
				return s
			}
		}
		return ""
	}
	p, ok := c.locResolvePath(cf, ref.Path)
	if !ok || c.locExcluded(p) {
		return RefNotFollowed
	}
	kind := locMaterial
	if ref.Kind == "trust_store" {
		kind = locTrust
	}
	v := locVisit{Path: p, Kind: kind, Trust: kind == locTrust,
		FoundBy: FoundByConfig, UsedBy: usage, Section: locRefSection(ref.Kind)}
	if ref.Kind == "private_key" {
		v.Role = locRefRole(cf.Product)
	}
	res, fi := c.locVisit(ctx, v)
	switch res {
	case locMissing:
		return RefMissing
	case locDenied, locFailed:
		return RefUnreadable
	case locStopped:
		return ""
	case locIsDir:
		// A CA directory (SSLCACertificatePath), HAProxy's "crt <dir>".
		for _, f := range c.locList(ctx, v.Section, fi.Path, 0, nil) {
			if f.IsDir {
				continue
			}
			sub := v
			info := f
			sub.Path, sub.Info = f.Path, &info
			c.locVisit(ctx, sub)
		}
	}
	st.count(v.Section, true)
	return RefFound
}

// locQueueConfig adds a configuration another configuration names, and
// returns the reference's Status.
func (c *collection) locQueueConfig(ctx context.Context, p, product string, usage []Usage) string {
	st := c.locSt()
	fi, err := c.target.Stat(ctx, p)
	if err == nil {
		fi, err = c.locFollow(ctx, p, fi)
	}
	if err != nil {
		if errors.Is(err, ErrNotExist) {
			return RefMissing
		}
		c.locConfigErr(p, err)
		return RefUnreadable
	}
	st.configs = append(st.configs, locConfigFile{
		Path: p, Product: product, Base: st.style.dir(p), Info: fi, FoundBy: FoundByConfig, UsedBy: usage,
	})
	return RefFound
}
