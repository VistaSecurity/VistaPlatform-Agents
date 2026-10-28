#!/usr/bin/env node
// Generates the asset-class taxonomy from standards/asset-classes.yaml.
//
// Outputs:
//   shared/assetclass/classes_gen.go                     (whole file)
//   shared/assetclass/attribute_schemas_gen.json         (whole file)
//   shared/assetclass/cloud_types_gen.go                 (whole file)
//
// Run via `make generate`; `make generate-check` runs `--check` and fails on
// drift.
import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';
import yaml from 'yaml';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');

const KEY = /^[a-z][a-z0-9_]*$/;
const ATTR = /^[a-z][a-z0-9_]*$/;
const ICON = /^[A-Z][A-Za-z0-9]*$/;

// Attribute names that belong to asset_identifiers, not to assets.attributes.
// An identifier is stored once, unique across assets, with its own source,
// confidence and first/last-seen (ADR-0002 D3). Declaring the same value as a
// class attribute gives it a second home in a jsonb blob with no rule for
// which one wins — which is the reconciliation bug of ADR-0002 D4 built in at
// the schema level. The nine identifier kinds are rejected by name, and so are
// the spellings that mean the same thing: `resource_id` shipped in the first
// draft of the registry and is exactly `cloud_resource_id`.
//
// This list is names, not concepts: `account_id` is NOT here, because a cloud
// account is context (ADR-0002 D2 names it as a cloud_resource attribute) and
// is not an identifier kind.
const RESERVED_ATTRIBUTE_NAMES = new Set([
  // the ten kinds themselves
  'agent_id', 'sensor_id', 'cloud_resource_id', 'serial_number', 'cmdb_sys_id',
  'ssh_host_key_fingerprint', 'mac_address', 'fqdn', 'hostname', 'ip_address',
  'name',
  // spellings of the same thing
  'resource_id', 'cloud_instance_id', 'serial', 'sys_id', 'ssh_host_key',
  'mac', 'macs', 'mac_addresses', 'fqdns', 'hostnames', 'ip', 'ips',
  'ip_addresses', 'display_name', 'service_name',
]);

function fail(msg) {
  console.error(`asset-classes: ${msg}`);
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Load + validate
// ---------------------------------------------------------------------------

function load() {
  const registryPath = path.join(root, 'standards', 'asset-classes.yaml');
  const reg = yaml.parse(fs.readFileSync(registryPath, 'utf8'));

  const identifierKinds = reg.identifier_kinds || [];
  const cyclonedxTypes = reg.cyclonedx_types || [];
  const legacyTypes = reg.legacy_asset_types || [];
  const attrTypes = reg.attribute_types || [];
  for (const [name, list] of Object.entries({
    identifier_kinds: identifierKinds,
    cyclonedx_types: cyclonedxTypes,
    legacy_asset_types: legacyTypes,
    attribute_types: attrTypes,
  })) {
    if (!Array.isArray(list) || list.length === 0) fail(`${name}: must be a non-empty list`);
    if (new Set(list).size !== list.length) fail(`${name}: duplicate entries`);
  }

  const classes = reg.classes || [];
  if (!classes.length) fail('no classes defined');

  const byKey = new Map();
  for (const c of classes) {
    if (!KEY.test(c.key || '')) fail(`bad class key: ${JSON.stringify(c.key)}`);
    if (byKey.has(c.key)) fail(`duplicate class key: ${c.key}`);
    if (!c.label) fail(`${c.key}: label required`);
    if (!c.description) fail(`${c.key}: description required`);
    if (!ICON.test(c.icon || '')) {
      fail(`${c.key}: icon must be a PascalCase lucide-react export name, got ${JSON.stringify(c.icon)}`);
    }
    if (!cyclonedxTypes.includes(c.cyclonedx_type)) {
      fail(`${c.key}: invalid cyclonedx_type: ${c.cyclonedx_type}`);
    }
    if (!legacyTypes.includes(c.legacy_asset_type)) {
      fail(`${c.key}: invalid legacy_asset_type: ${c.legacy_asset_type}`);
    }
    if (c.cmdb_ci_type !== null && c.cmdb_ci_type !== undefined) {
      if (typeof c.cmdb_ci_type !== 'string' || !c.cmdb_ci_type.trim()) {
        fail(`${c.key}: cmdb_ci_type must be a non-empty string or null`);
      }
    }
    if (!('identifier_precedence' in c) || !Array.isArray(c.identifier_precedence)) {
      fail(`${c.key}: identifier_precedence must be a list (empty means dependent identity)`);
    }
    const seenKind = new Set();
    for (const kind of c.identifier_precedence) {
      if (!identifierKinds.includes(kind)) fail(`${c.key}: unknown identifier kind: ${kind}`);
      if (seenKind.has(kind)) fail(`${c.key}: identifier kind listed twice: ${kind}`);
      seenKind.add(kind);
    }
    if ('crypto_bearing' in c && typeof c.crypto_bearing !== 'boolean') {
      fail(`${c.key}: crypto_bearing must be true or false`);
    }
    validateSchema(c, attrTypes);
    byKey.set(c.key, c);
  }

  // Parents must exist, must not be self, and the chain must terminate.
  for (const c of classes) {
    const parent = c.parent ?? null;
    if (parent === null) continue;
    if (typeof parent !== 'string') fail(`${c.key}: parent must be a class key or null`);
    if (parent === c.key) fail(`${c.key}: is its own parent`);
    if (!byKey.has(parent)) fail(`${c.key}: parent ${parent} is not a declared class`);
  }

  // Derive paths; a cycle shows up as a walk that never reaches a root.
  const pathOf = new Map();
  for (const c of classes) {
    const chain = [];
    const seen = new Set();
    let cur = c;
    while (cur) {
      if (seen.has(cur.key)) fail(`cycle in the class tree at ${cur.key}`);
      seen.add(cur.key);
      chain.unshift(cur.key);
      cur = cur.parent ? byKey.get(cur.parent) : null;
    }
    pathOf.set(c.key, chain.join('.'));
  }

  // A parent must be declared before its children so every consumer can build
  // the tree in one pass (and so the SQL insert order is FK-safe if 0.2 adds a
  // self-referencing foreign key).
  const declared = new Set();
  for (const c of classes) {
    if (c.parent && !declared.has(c.parent)) {
      fail(`${c.key}: declared before its parent ${c.parent}`);
    }
    declared.add(c.key);
  }

  // Effective attribute schemas: own properties merged over every ancestor's.
  // A child redeclaring an ancestor's property is a mistake, not an override —
  // the two would disagree about the type of one jsonb key.
  const effective = new Map();
  for (const c of classes) {
    const props = {};
    const owner = {};
    const chain = pathOf.get(c.key).split('.');
    for (const key of chain) {
      const anc = byKey.get(key);
      for (const [name, def] of Object.entries(anc.attribute_schema.properties || {})) {
        if (name in props) {
          fail(`${key}: attribute "${name}" redeclares the one inherited from ${owner[name]}`);
        }
        props[name] = def;
        owner[name] = key;
      }
    }
    effective.set(c.key, {
      type: 'object',
      additionalProperties: false,
      properties: props,
    });
  }

  // One attribute NAME is one query field. §4.2 makes `attr.` flat and global —
  // `attr.model` is one field, not one per class — because a query is a
  // predicate over `assets`, whose `attributes` jsonb holds whichever class's
  // keys the row carries. So two unrelated classes declaring one name with two
  // types would be one field with two types, and both catalogues that fold this
  // namespace (shared/query/catalog/registrycatalog and the TypeScript
  // RegistryCatalog) have no correct behaviour available: typing one class's
  // data by another class's schema is the silent wrong answer, and dropping the
  // attribute makes the vocabulary change shape on an unreviewed YAML edit.
  //
  // The Go catalogue therefore PANICS, saying "a registry bug that
  // `make generate` should never emit and `make audit` would catch". This is
  // what makes that sentence true.
  const attrOwner = new Map();
  for (const c of classes) {
    for (const [name, def] of Object.entries(effective.get(c.key).properties)) {
      const sig = JSON.stringify({ type: def.type, enum: def.enum ?? null, items: def.items ?? null });
      const prev = attrOwner.get(name);
      if (prev === undefined) {
        attrOwner.set(name, { cls: c.key, sig });
        continue;
      }
      if (prev.sig !== sig) {
        fail(
          `attribute "${name}" is declared as ${prev.sig} by "${prev.cls}" and as ${sig} by ` +
          `"${c.key}"; one attribute name is one query field (attr.${name}), so it cannot be two`,
        );
      }
    }
  }

  // Provider type → class (asset-inventory ADR-0009 D2): the ONE mapping,
  // keyed on the provider's own type strings, with the collectors' spellings
  // as aliases. Only cloud_resource classes may carry it; every type string
  // and every alias names exactly one class.
  const PROVIDERS = new Set(['aws', 'azure', 'gcp']);
  const cloudTypes = [];
  const genericAliases = [];
  const spelled = new Map();
  const claim = (spelling, owner) => {
    const k = String(spelling).trim().toLowerCase();
    if (!k) fail(`${owner}: empty provider-type spelling`);
    if (spelled.has(k)) fail(`provider-type spelling "${spelling}" claimed by ${spelled.get(k)} and ${owner}`);
    spelled.set(k, owner);
  };
  for (const c of classes) {
    const pts = c.provider_types ?? [];
    const gen = c.resource_type_aliases ?? [];
    if ((pts.length || gen.length) && !pathOf.get(c.key).startsWith('cloud_resource.')) {
      fail(`${c.key}: provider_types / resource_type_aliases belong to cloud_resource classes only`);
    }
    if (!Array.isArray(pts) || !Array.isArray(gen)) fail(`${c.key}: provider_types and resource_type_aliases must be lists`);
    for (const pt of pts) {
      if (!pt || typeof pt.type !== 'string' || !pt.type.trim()) fail(`${c.key}: provider_types entry needs a type`);
      if (!PROVIDERS.has(pt.provider)) fail(`${c.key}: ${pt.type}: provider must be one of ${[...PROVIDERS].join(', ')}`);
      claim(pt.type, c.key);
      const aliases = pt.aliases ?? [];
      for (const a of aliases) claim(a, c.key);
      cloudTypes.push({ type: pt.type, provider: pt.provider, cls: c.key, aliases: aliases.map(String) });
    }
    for (const a of gen) {
      claim(a, c.key);
      genericAliases.push({ alias: String(a), cls: c.key });
    }
  }

  const rows = classes.map((c) => ({
    key: c.key,
    parent: c.parent ?? '',
    path: pathOf.get(c.key),
    label: c.label,
    description: c.description.trim().replace(/\s+/g, ' '),
    icon: c.icon,
    cmdbCIType: c.cmdb_ci_type ?? '',
    cyclonedxType: c.cyclonedx_type,
    identifierPrecedence: c.identifier_precedence,
    legacyAssetType: c.legacy_asset_type,
    cryptoBearing: c.crypto_bearing === true,
    schema: effective.get(c.key),
  }));

  return { reg, rows, identifierKinds, cyclonedxTypes, legacyTypes, cloudTypes, genericAliases };
}

// The provider-type mapping for Go (asset-inventory ADR-0009 D2).
function emitCloudTypesGo(cloudTypes, genericAliases) {
  const entries = cloudTypes.map((t) =>
    `\t{Type: ${goStr(t.type)}, Provider: ${goStr(t.provider)}, Class: Key${goName(t.cls)}, Aliases: ${goStrSlice(t.aliases)}},`,
  ).join('\n');
  const gw = Math.max(0, ...genericAliases.map((g) => goStr(g.alias).length)) + 1;
  const generic = genericAliases
    .map((g) => `\t${goStr(g.alias)}:${' '.repeat(gw - goStr(g.alias).length)}Key${goName(g.cls)},`)
    .join('\n');
  return `// ${HEADER_LINES.join('\n// ')}

package assetclass

// CloudProviderType is one provider resource type and the class it is: the
// provider's own type string (AWS::EC2::Instance,
// Microsoft.Compute/virtualMachines, compute.googleapis.com/Instance), and
// the spellings the collectors use for it (asset-inventory ADR-0009 D2).
type CloudProviderType struct {
	Type     string
	Provider string
	Class    Key
	Aliases  []string
}

// cloudProviderTypes is every provider type the registry maps, in registry
// order.
var cloudProviderTypes = []CloudProviderType{
${entries}
}

// cloudGenericAliases are provider-neutral resource-type spellings
// ("bucket", "function") and the class each names.
var cloudGenericAliases = map[string]Key{
${generic}
}
`;
}

function validateSchema(c, attrTypes) {
  const s = c.attribute_schema;
  if (!s || typeof s !== 'object') fail(`${c.key}: attribute_schema required`);
  if (s.type !== 'object') fail(`${c.key}: attribute_schema.type must be "object"`);
  if (!s.properties || typeof s.properties !== 'object') {
    fail(`${c.key}: attribute_schema.properties must be a map (use {} for none)`);
  }
  for (const [name, def] of Object.entries(s.properties)) {
    if (!ATTR.test(name)) fail(`${c.key}: bad attribute name: ${name}`);
    if (RESERVED_ATTRIBUTE_NAMES.has(name)) {
      fail(
        `${c.key}.${name}: reserved — that value is an identifier, not a class attribute. ` +
        'Identifiers live in asset_identifiers under one of the nine kinds of ADR-0002 D3.',
      );
    }
    if (!attrTypes.includes(def?.type)) fail(`${c.key}.${name}: invalid type: ${def?.type}`);
    if (!def.description) fail(`${c.key}.${name}: description required`);
    if (def.type === 'array') {
      if (!def.items || !attrTypes.includes(def.items.type)) {
        fail(`${c.key}.${name}: array attributes need items.type`);
      }
    }
    if (def.enum !== undefined) {
      if (!Array.isArray(def.enum) || !def.enum.length) fail(`${c.key}.${name}: enum must be a non-empty list`);
      if (def.type !== 'string') fail(`${c.key}.${name}: enum is only supported on string attributes`);
    }
  }
}

// ---------------------------------------------------------------------------
// Emitters
// ---------------------------------------------------------------------------

const HEADER_LINES = [
  'Code generated by scripts/generate-asset-classes.mjs from',
  'standards/asset-classes.yaml. DO NOT EDIT — edit the YAML and run',
  '`make generate`.',
];

function goName(key) {
  return key.split('_').map((p) => p[0].toUpperCase() + p.slice(1)).join('');
}

function goStr(s) {
  return JSON.stringify(String(s ?? ''));
}

// An empty precedence list is a STATEMENT — "this class has no independent
// identity" (ADR-0002 D3) — so it is emitted as an empty slice, never nil. The
// seed SQL writes ARRAY[]::text[] and the TS writes [], and a nil here would
// have marshalled the same fact as JSON `null` in Go alone: three mirrors of
// one registry disagreeing about the value the ADR gives meaning to.
function goStrSlice(values) {
  if (!values.length) return '[]string{}';
  return `[]string{${values.map(goStr).join(', ')}}`;
}

function emitGo(rows, identifierKinds, cyclonedxTypes, legacyTypes) {
  const width = Math.max(...rows.map((r) => goName(r.key).length)) + 1;
  const consts = rows
    .map((r) => `\tKey${goName(r.key)}${' '.repeat(width - goName(r.key).length)}Key = ${goStr(r.key)}`)
    .join('\n');

  const entries = rows.map((r) => `	{
		Key:                  ${goStr(r.key)},
		Parent:               ${goStr(r.parent)},
		Path:                 ${goStr(r.path)},
		Label:                ${goStr(r.label)},
		Icon:                 ${goStr(r.icon)},
		CMDBCIType:           ${goStr(r.cmdbCIType)},
		CycloneDXType:        ${goStr(r.cyclonedxType)},
		IdentifierPrecedence: ${goStrSlice(r.identifierPrecedence)},
		LegacyAssetType:      ${goStr(r.legacyAssetType)},${r.cryptoBearing ? '\n\t\tCryptoBearing:        true,' : ''}
	},`).join('\n');

  return `// ${HEADER_LINES.join('\n// ')}
package assetclass

import "strings"

// Key is an asset class key. It is an alias rather than a defined type so the
// constants below drop straight into the string columns and JSON fields that
// carry a class ("assets.class_key", the OpenAPI AssetClassKey enum, the
// asset_classes registry rows) with no conversion at every call site.
type Key = string

// Class keys. The top level is fixed (ADR-0002 D2); tenants may add leaf
// subclasses at runtime, which never appear here.
const (
${consts}
)

// IdentifierKinds is the allowed set of identifier kinds, in the default
// precedence order of ADR-0002 D3. A class may drop and reorder kinds; it may
// not invent one.
var IdentifierKinds = ${goStrSlice(identifierKinds)}

// CycloneDXTypes is the allowed set of Class.CycloneDXType values. "service" is
// not a CycloneDX component type — a class carrying it is emitted into the
// CycloneDX "services" array rather than "components".
var CycloneDXTypes = ${goStrSlice(cyclonedxTypes)}

// LegacyAssetTypes is the allowed set of Class.LegacyAssetType values: the four
// values of the public.asset_type enum this taxonomy replaces.
var LegacyAssetTypes = ${goStrSlice(legacyTypes)}

// Class is one node of the fixed class hierarchy.
type Class struct {
	// Key is the stable identifier, unique across the platform hierarchy.
	Key Key \`json:"key"\`
	// Parent is the parent class key, empty for a top-level class.
	Parent Key \`json:"parent,omitempty"\`
	// Path is the materialised dot-separated ancestor chain ending in Key,
	// e.g. "hardware.computer.server". Prefix matching on Path is how a facet
	// selects a whole branch.
	Path string \`json:"path"\`
	// Label is the human-facing name.
	Label string \`json:"label"\`
	// Icon is a lucide-react export name (PascalCase).
	Icon string \`json:"icon"\`
	// CMDBCIType is the default ServiceNow class for the CMDB sync. Empty
	// means no confident default: resolve to the nearest ancestor that has
	// one, or let the sync profile map it. Empty is deliberately not the same
	// as a guess.
	CMDBCIType string \`json:"cmdb_ci_type,omitempty"\`
	// CycloneDXType is the component type used when the class is emitted into
	// an xBOM.
	CycloneDXType string \`json:"cyclonedx_type"\`
	// IdentifierPrecedence is the ordered subset of IdentifierKinds the
	// identification engine tries for this class, highest confidence first.
	// Empty means the class has no independent identity and is matched by
	// dependent identity instead (ADR-0002 D3) — an empty slice, never nil,
	// so the fact marshals as [] here exactly as it does in the TS mirror and
	// the seeded ARRAY[]::text[].
	IdentifierPrecedence []string \`json:"identifier_precedence"\`
	// LegacyAssetType maps the class onto the public.asset_type enum value the
	// pre-ADR-0002 model used. Reference only.
	LegacyAssetType string \`json:"legacy_asset_type"\`
	// CryptoBearing marks a class whose instances carry cryptography by their
	// nature — a key store, a VPN gateway, a TLS-terminating edge. An instance
	// with no crypto measured reads "Not assessed", never "No crypto
	// observed": having seen none on such a thing is a gap in what we
	// measured, not an answer about it (shared/cryptosurface).
	CryptoBearing bool \`json:"crypto_bearing,omitempty"\`
}

// All is the fixed class hierarchy, in registry order. A parent always
// precedes its children.
var All = []Class{
${entries}
}

var byKey = func() map[string]Class {
	m := make(map[string]Class, len(All))
	for _, c := range All {
		m[c.Key] = c
	}
	return m
}()

// Get returns the class with this key. The second result is false for an
// unknown key and for tenant subclasses, which are runtime rows and are not
// part of the generated hierarchy.
func Get(key string) (Class, bool) {
	c, ok := byKey[key]
	return c, ok
}

// IsAncestor reports whether ancestor is key itself or one of its ancestors.
// It is the Path prefix test the facets use, done on whole segments so
// "hardware" never matches a hypothetical "hardware_x".
func IsAncestor(ancestor, key string) bool {
	if ancestor == "" || key == "" {
		return false
	}
	if ancestor == key {
		_, ok := byKey[key]
		return ok
	}
	c, ok := byKey[key]
	if !ok {
		return false
	}
	a, ok := byKey[ancestor]
	if !ok {
		return false
	}
	return strings.HasPrefix(c.Path, a.Path+".")
}

// Children returns the direct children of a class, in registry order. A leaf
// class returns an empty slice, as does an unknown key.
func Children(key string) []Class {
	out := make([]Class, 0, 4)
	for _, c := range All {
		if c.Parent == key && c.Parent != "" {
			out = append(out, c)
		}
	}
	return out
}

// Roots returns the top-level classes, in registry order.
func Roots() []Class {
	out := make([]Class, 0, 8)
	for _, c := range All {
		if c.Parent == "" {
			out = append(out, c)
		}
	}
	return out
}
`;
}

function emitSchemasJSON(rows) {
  const obj = {
    _comment: HEADER_LINES.join(' '),
    schemas: Object.fromEntries(rows.map((r) => [r.key, r.schema])),
  };
  return JSON.stringify(obj, null, 2) + '\n';
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

async function main() {
  const checkOnly = process.argv.includes('--check');
  const { rows, identifierKinds, cyclonedxTypes, legacyTypes, cloudTypes, genericAliases } = load();
  const outputs = [
    [path.join(root, 'shared', 'assetclass', 'classes_gen.go'),
      emitGo(rows, identifierKinds, cyclonedxTypes, legacyTypes)],
    [path.join(root, 'shared', 'assetclass', 'attribute_schemas_gen.json'), emitSchemasJSON(rows)],
    [path.join(root, 'shared', 'assetclass', 'cloud_types_gen.go'), emitCloudTypesGo(cloudTypes, genericAliases)],
  ];

  if (checkOnly) {
    const stale = [];
    for (const [p, content] of outputs) {
      const current = fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : '';
      if (current !== content) stale.push(path.relative(root, p));
    }
    if (stale.length) {
      fail(`out of date — run \`make generate\`:\n  ${stale.join('\n  ')}`);
    }
    console.log(`asset-classes check OK (${rows.length} classes, ${outputs.length} artefacts)`);
    return;
  }

  for (const [p, content] of outputs) {
    await fs.ensureDir(path.dirname(p));
    await fs.writeFile(p, content);
    console.log(`Generated: ${path.relative(root, p)}`);
  }
  console.log(`  ${rows.length} classes`);
}

main().catch((e) => fail(e.stack || e.message));
