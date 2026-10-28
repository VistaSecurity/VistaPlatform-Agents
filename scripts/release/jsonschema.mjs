// A JSON Schema 2020-12 validator for the subset of keywords this
// repository's schemas use, with no dependencies: the release job validates
// its own metadata before signing it, and a validator that needs `npm install`
// in a job that holds signing authority is one more thing to trust.
//
// Fails closed: compiling a schema that uses a keyword outside SUPPORTED (or
// a $ref that is not a local "#/$defs/<name>") throws, so a schema edit can
// never be silently half-enforced. `format` is checked for "date-time" only;
// any other format throws.
//
//   import { compile } from './jsonschema.mjs';
//   const validate = compile(schema);
//   const errors = validate(doc);   // [] or [{ path, message }]

export class SchemaError extends Error {}

const ANNOTATIONS = new Set(['$schema', '$id', '$comment', 'title', 'description', 'examples', 'default']);
export const SUPPORTED = new Set([
  ...ANNOTATIONS, '$defs', '$ref',
  'type', 'const', 'enum',
  'properties', 'required', 'additionalProperties',
  'items', 'minItems', 'maxItems', 'uniqueItems', 'contains',
  'minLength', 'maxLength', 'pattern', 'format',
  'minimum', 'maximum',
  'allOf', 'anyOf', 'oneOf', 'not', 'if', 'then', 'else',
]);

const DATE_TIME = /^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:([0-5]\d|60)(\.\d+)?(Z|[+-]([01]\d|2[0-3]):[0-5]\d)$/i;

export function deepEqual(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null || typeof a !== 'object') return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) return a.length === b.length && a.every((x, i) => deepEqual(x, b[i]));
  const ka = Object.keys(a).sort();
  const kb = Object.keys(b).sort();
  return deepEqual(ka, kb) && ka.every((k) => deepEqual(a[k], b[k]));
}

function typeOf(v) {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  if (typeof v === 'number') return Number.isInteger(v) ? 'integer' : 'number';
  return typeof v;
}

function typeMatches(v, t) {
  const actual = typeOf(v);
  return actual === t || (t === 'number' && actual === 'integer');
}

function isSchemaObject(s) {
  return s !== null && typeof s === 'object' && !Array.isArray(s);
}

// Walk the whole schema once, refusing what this validator does not enforce.
function audit(schema, root, where) {
  if (typeof schema === 'boolean') return;
  if (!isSchemaObject(schema)) throw new SchemaError(`${where}: a schema must be an object or a boolean`);
  for (const k of Object.keys(schema)) {
    if (!SUPPORTED.has(k)) throw new SchemaError(`${where}: unsupported keyword "${k}"`);
  }
  if ('$ref' in schema) {
    const m = /^#\/\$defs\/([A-Za-z0-9_-]+)$/.exec(schema.$ref);
    if (!m) throw new SchemaError(`${where}: only local "#/$defs/<name>" references are supported, got ${schema.$ref}`);
    if (!root.$defs || !(m[1] in root.$defs)) throw new SchemaError(`${where}: $ref to missing definition ${m[1]}`);
  }
  if ('format' in schema && schema.format !== 'date-time') throw new SchemaError(`${where}: unsupported format "${schema.format}"`);
  if ('pattern' in schema) {
    try { new RegExp(schema.pattern, 'u'); } catch (e) { throw new SchemaError(`${where}: bad pattern: ${e.message}`); }
  }
  for (const k of ['$defs', 'properties']) {
    if (k in schema) for (const [n, s] of Object.entries(schema[k])) audit(s, root, `${where}/${k}/${n}`);
  }
  for (const k of ['items', 'additionalProperties', 'contains', 'not', 'if', 'then', 'else']) {
    if (k in schema && typeof schema[k] !== 'boolean') audit(schema[k], root, `${where}/${k}`);
  }
  for (const k of ['allOf', 'anyOf', 'oneOf']) {
    if (k in schema) {
      if (!Array.isArray(schema[k]) || schema[k].length === 0) throw new SchemaError(`${where}/${k}: must be a non-empty array`);
      schema[k].forEach((s, i) => audit(s, root, `${where}/${k}/${i}`));
    }
  }
}

export function compile(root) {
  audit(root, root, '#');
  const run = (schema, value, path, errors) => {
    if (schema === true) return;
    if (schema === false) { errors.push({ path, message: 'no value is allowed here' }); return; }
    const err = (message) => errors.push({ path, message });
    if ('$ref' in schema) run(root.$defs[schema.$ref.slice('#/$defs/'.length)], value, path, errors);
    if ('type' in schema) {
      const types = [].concat(schema.type);
      if (!types.some((t) => typeMatches(value, t))) { err(`must be ${types.join(' or ')}, got ${typeOf(value)}`); return; }
    }
    if ('const' in schema && !deepEqual(value, schema.const)) err(`must equal ${JSON.stringify(schema.const)}`);
    if ('enum' in schema && !schema.enum.some((e) => deepEqual(value, e))) err(`must be one of ${JSON.stringify(schema.enum)}, got ${JSON.stringify(value)}`);
    if (typeof value === 'string') {
      const len = [...value].length;
      if ('minLength' in schema && len < schema.minLength) err(`shorter than ${schema.minLength}`);
      if ('maxLength' in schema && len > schema.maxLength) err(`longer than ${schema.maxLength}`);
      if ('pattern' in schema && !new RegExp(schema.pattern, 'u').test(value)) err(`does not match ${schema.pattern}: ${JSON.stringify(value)}`);
      if (schema.format === 'date-time' && (!DATE_TIME.test(value) || Number.isNaN(Date.parse(value)))) err(`not an RFC 3339 date-time: ${JSON.stringify(value)}`);
    }
    if (typeof value === 'number') {
      if ('minimum' in schema && value < schema.minimum) err(`less than ${schema.minimum}`);
      if ('maximum' in schema && value > schema.maximum) err(`greater than ${schema.maximum}`);
    }
    if (Array.isArray(value)) {
      if ('minItems' in schema && value.length < schema.minItems) err(`fewer than ${schema.minItems} item(s)`);
      if ('maxItems' in schema && value.length > schema.maxItems) err(`more than ${schema.maxItems} item(s)`);
      if (schema.uniqueItems && value.some((v, i) => value.findIndex((w) => deepEqual(v, w)) !== i)) err('items are not unique');
      if ('items' in schema) value.forEach((v, i) => run(schema.items, v, `${path}/${i}`, errors));
      if ('contains' in schema && !value.some((v) => ok(schema.contains, v))) err('contains no matching item');
    }
    if (isSchemaObject(value)) {
      for (const r of schema.required || []) if (!Object.prototype.hasOwnProperty.call(value, r)) err(`missing required property "${r}"`);
      const props = schema.properties || {};
      for (const [k, v] of Object.entries(value)) {
        if (Object.prototype.hasOwnProperty.call(props, k)) run(props[k], v, `${path}/${k}`, errors);
        else if ('additionalProperties' in schema) {
          if (schema.additionalProperties === false) errors.push({ path: `${path}/${k}`, message: 'property is not allowed' });
          else run(schema.additionalProperties, v, `${path}/${k}`, errors);
        }
      }
    }
    for (const s of schema.allOf || []) run(s, value, path, errors);
    if ('anyOf' in schema && !schema.anyOf.some((s) => ok(s, value))) err('matches none of anyOf');
    if ('oneOf' in schema) {
      const n = schema.oneOf.filter((s) => ok(s, value)).length;
      if (n !== 1) {
        // Report the closest branch's errors so a failure says why.
        const branchErrors = schema.oneOf.map((s) => { const e = []; run(s, value, path, e); return e; });
        const best = branchErrors.reduce((a, b) => (b.length < a.length ? b : a));
        err(`must match exactly one of oneOf, matched ${n}`);
        if (n === 0) errors.push(...best);
      }
    }
    if ('not' in schema && ok(schema.not, value)) err('matches a schema it must not match');
    if ('if' in schema) {
      if (ok(schema.if, value)) { if ('then' in schema) run(schema.then, value, path, errors); }
      else if ('else' in schema) run(schema.else, value, path, errors);
    }
  };
  const ok = (schema, value) => { const e = []; run(schema, value, '', e); return e.length === 0; };
  return (doc) => {
    const errors = [];
    run(root, doc, '', errors);
    return errors.map((e) => ({ path: e.path || '/', message: e.message }));
  };
}
