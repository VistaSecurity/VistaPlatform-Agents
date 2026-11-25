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
// and gets the configuration as its UsedBy and FoundBy "config".
//
// A named file that does not exist is recorded as an error of the configs
// section naming the configuration, the directive and the path; one the
// account may not read makes the item's section partial. Nothing a
// configuration names is dropped without a word.
//
// References that cannot be resolved to one file are not guessed at: a path
// with a variable ($ssl_server_name), an OpenSSH % token or a ~ (each user's
// home) is recorded as not followed.

// passFollowConfiguration is pass 2. It ends by handing every record of
// passes 1 and 2 to the registry.
func passFollowConfiguration(ctx context.Context, c *collection) {
	st := c.locSt()
	defer c.locFlush()
	for i := 0; i < len(st.configs); i++ {
		if c.timeUp(ctx, SectionConfigs) {
			return
		}
		c.locReadConfig(ctx, st.configs[i])
	}
}

// locCfgKey identifies one configuration file read for one product.
func (c *collection) locCfgKey(product, p string) string {
	return product + "\x00" + c.registry.realPath(p)
}

// locReadConfig reads, parses and records one configuration file, then
// follows what it names.
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

	var cfgs []CryptoConfig
	if strings.HasPrefix(cf.Product, locBackendProduct) {
		cfgs = ParseCryptoPolicyBackend(baseName(cf.Path), text)
	} else if parse := ConfigParserFor(cf.Product); parse != nil {
		cfgs = parse(text, c.locResolver(ctx, cf))
	}
	loc := c.locLocation(cf.Info, cf.Path, cf.FoundBy, cf.UsedBy)
	for i := range cfgs {
		cfgs[i].Location = locCopy(loc)
		c.registry.addConfig(cfgs[i])
	}
	st.cfgDone[key] = cfgs
	for _, cfg := range cfgs {
		for _, ref := range cfg.References {
			if c.timeUp(ctx, SectionConfigs) {
				return
			}
			c.locFollowRef(ctx, cf, ref)
		}
	}
}

// locConfigErr records a configuration file that could not be read.
func (c *collection) locConfigErr(p string, err error) {
	st := c.locSt()
	switch {
	case errors.Is(err, ErrNotExist):
		// Gone between pass 1's Stat and this read.
	case errors.Is(err, ErrFileTooLarge):
		c.limit(SectionConfigs, "max_file_bytes", fmt.Sprintf("did not read configuration over %d bytes", c.opts.maxFileBytes()))
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		c.timeUp(context.Background(), SectionConfigs)
	default:
		st.count(SectionConfigs, false)
		c.partial(SectionConfigs, fmt.Errorf("%s: %w", p, err))
	}
}

// locResolver returns the IncludeResolver for one root configuration file:
// a pattern is resolved against the file's base directory, expanded through
// the Target (a directory includes its files, as Apache reads it), and each
// file read through readConfig with the root's product, within the parser's
// byte budget and the run's file budget.
func (c *collection) locResolver(ctx context.Context, cf locConfigFile) IncludeResolver {
	st := c.locSt()
	return func(pattern string, maxBytes int64) []IncludedFile {
		var out []IncludedFile
		var used int64
		for _, p := range c.locIncludePaths(ctx, cf, pattern) {
			if c.timeUp(ctx, SectionConfigs) || c.files(SectionConfigs, 1) == 0 {
				break
			}
			text, err := c.readConfig(ctx, p, cf.Product)
			if err != nil {
				if errors.Is(err, ErrNotExist) {
					c.note(SectionConfigs, fmt.Errorf("%s: include %s does not exist", cf.Path, p))
					continue
				}
				c.locConfigErr(p, err)
				continue
			}
			if used+int64(len(text)) > maxBytes {
				c.limit(SectionConfigs, "max_file_bytes", "stopped following includes at the 16 MiB budget of one file")
				break
			}
			used += int64(len(text))
			st.included[c.locCfgKey(cf.Product, p)] = true
			out = append(out, IncludedFile{Path: p, Text: text})
		}
		return out
	}
}

// locIncludePaths turns an include pattern into the files to read, sorted
// as the products read a glob.
func (c *collection) locIncludePaths(ctx context.Context, cf locConfigFile, pattern string) []string {
	st := c.locSt()
	p, ok := c.locResolvePath(cf, pattern)
	if !ok {
		c.note(SectionConfigs, fmt.Errorf("%s: include not followed: the path holds a variable or a per-user part", cf.Path))
		return nil
	}
	var files []FileInfo
	if locHasMeta(p) {
		files = c.locFiles(ctx, SectionConfigs, st.style.dir(p), 0, []string{baseName(p)}, 0)
	} else {
		fi, err := c.target.Stat(ctx, p)
		switch {
		case err != nil:
			// Let the read say what is wrong with it (missing, denied).
			return []string{p}
		case fi.IsDir:
			files = c.locList(ctx, SectionConfigs, p, 0, nil)
		default:
			return []string{p}
		}
	}
	out := make([]string, 0, len(files))
	for _, fi := range files {
		out = append(out, fi.Path)
	}
	sort.Strings(out)
	return out
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
		drive := st.root
		if drive == "" {
			drive = "C:"
		}
		p = drive + `\ProgramData` + p[len(locProgramDataToken):]
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

// locFollowRef visits one file a configuration names.
func (c *collection) locFollowRef(ctx context.Context, cf locConfigFile, ref ConfigReference) {
	st := c.locSt()
	usage := []Usage{{Kind: "config", ConfigPath: cf.Path, Directive: ref.Directive}}
	if ref.Kind == "include" {
		// The parsers follow their own includes through the resolver. A JVM
		// option naming a security properties file is the one include that
		// is another product's configuration.
		if cf.Product == "java-options" {
			if p, ok := c.locResolvePath(cf, ref.Path); ok {
				c.locQueueConfig(ctx, cf, ref, p, "java", usage)
			}
		}
		return
	}
	p, ok := c.locResolvePath(cf, ref.Path)
	if !ok {
		c.note(SectionConfigs, fmt.Errorf("%s: %s not followed: the path holds a variable or a per-user part", cf.Path, ref.Directive))
		return
	}
	kind := locMaterial
	if ref.Kind == "trust_store" {
		kind = locTrust
	}
	v := locVisit{Path: p, Kind: kind, Role: locRefRole(cf.Product), Trust: kind == locTrust,
		FoundBy: FoundByConfig, UsedBy: usage, Section: locRefSection(ref.Kind)}
	if ref.Kind != "private_key" {
		v.Role = ""
	}
	res, fi := c.locVisit(ctx, v)
	switch res {
	case locMissing:
		c.note(SectionConfigs, fmt.Errorf("%s: %s names %s, which does not exist", cf.Path, ref.Directive, p))
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
	case locRead:
		st.count(v.Section, true)
	}
}

// locQueueConfig adds a configuration another configuration names.
func (c *collection) locQueueConfig(ctx context.Context, cf locConfigFile, ref ConfigReference, p, product string, usage []Usage) {
	st := c.locSt()
	fi, err := c.target.Stat(ctx, p)
	if err == nil {
		fi, err = c.locFollow(ctx, p, fi)
	}
	if err != nil {
		if errors.Is(err, ErrNotExist) {
			c.note(SectionConfigs, fmt.Errorf("%s: %s names %s, which does not exist", cf.Path, ref.Directive, p))
			return
		}
		c.locConfigErr(p, err)
		return
	}
	st.configs = append(st.configs, locConfigFile{
		Path: p, Product: product, Base: st.style.dir(p), Info: fi, FoundBy: FoundByConfig, UsedBy: usage,
	})
}
