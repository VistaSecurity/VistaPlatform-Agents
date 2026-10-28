#!/usr/bin/env node
// Workflow trust guard: a static check of every GitHub Actions workflow in
// this repository against the rules that keep untrusted pull requests away
// from anything privileged.
//
//   node scripts/check-workflows.mjs [repo-root]     # default: this script's ../
//
// Exit 0: every rule holds. Exit 1: at least one violation (listed). Exit 2:
// a file could not be verified (unsupported YAML, unreadable). 2 is a failure
// too: a guard that cannot read a file must not report it clean.
//
// Rules, for every file under .github/workflows/ (and composite actions under
// .github/actions/):
//
//   runner          `runs-on` names a GitHub-hosted runner label from
//                   HOSTED_LABELS, directly, as a list of such labels, or via
//                   `${{ matrix.<key> }}` whose every value is one. Anything
//                   else (a runner group, an expression from inputs or vars,
//                   the word self-hosted anywhere outside a comment) fails.
//                   Self-hosted runners execute pull-request code on machines
//                   that hold credentials; public CI never uses them.
//   pin             every `uses:` names a local path, a docker image by
//                   sha256 digest, or owner/repo[/path]@<40-hex commit SHA>
//                   with the version in a trailing comment. A tag or branch
//                   can be moved to new code by whoever controls the action.
//   trigger         no `pull_request_target` and no `workflow_run`: both run
//                   with the base repository's privileges in reach of
//                   untrusted code or artefacts.
//   permissions     every workflow declares top-level `permissions:`. In a
//                   workflow triggered by a pull-request event, every
//                   permission (top-level and per job) is `read` or `none`.
//   secrets         a pull-request workflow names no secret other than
//                   GITHUB_TOKEN and never passes `secrets: inherit`.
//   cache           no actions/cache anywhere, setup-go and setup-node say
//                   `cache: false` / `package-manager-cache: false`, no setup
//                   action enables a cache. A cache written by one run is
//                   restored by another: the route by which a pull request
//                   poisons a trusted build.
//   checkout        actions/checkout says `persist-credentials: false`, so
//                   the job token is not left in .git/config for later steps.
//
// Zero dependencies on purpose (Node >= 20): a guard that needs `npm install`
// first can be defeated by the install. It therefore carries its own reader
// for the YAML subset workflows use, and fails closed (exit 2) on anything
// outside it: anchors, aliases, tags, several documents.
//
// This is a static check of the files a pull request proposes, so a pull
// request can also edit this script. CODEOWNERS sends changes to .github/ and
// scripts/ to the owner for review; that review, the repository's Actions
// policy and the organisation's runner-group policy are the enforcement this
// script backs up, not replaces.

import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// GitHub-hosted runner labels this repository may ask for. A label outside
// the list fails even if GitHub hosts it: adding one is a reviewed change.
export const HOSTED_LABELS = new Set([
  'ubuntu-latest', 'ubuntu-24.04', 'ubuntu-22.04',
  'ubuntu-24.04-arm', 'ubuntu-22.04-arm',
  'macos-latest', 'macos-15', 'macos-15-intel', 'macos-14', 'macos-13',
  'windows-latest', 'windows-2025', 'windows-2022', 'windows-11-arm',
]);

export const FORBIDDEN_TRIGGERS = ['pull_request_target', 'workflow_run'];

// Events whose workflow runs code a pull request proposed.
export const PULL_REQUEST_TRIGGERS = ['pull_request', 'pull_request_review', 'pull_request_review_comment'];

const SETUP_ACTIONS_DEFAULT_CACHE_ON = new Map([
  ['actions/setup-go', 'cache'],
  ['actions/setup-node', 'package-manager-cache'],
]);

export class YamlSubsetError extends Error {
  constructor(message, line) {
    super(line ? `line ${line}: ${message}` : message);
    this.line = line;
  }
}

// ---------------------------------------------------------------------------
// YAML subset reader. Scalars stay strings (no type resolution), so `on` stays
// "on" and `false` stays "false", which is what a workflow's keys and inputs
// need. Supported: block mappings and sequences, flow [..] and {..} (also over
// several lines), plain/single/double-quoted scalars (also folded over several
// lines), literal and folded block scalars with chomping indicators.
// ---------------------------------------------------------------------------

// Remove a trailing comment. A quote opens a quoted scalar only where a scalar
// can start (line start, after `: `, `- `, `[`, `{` or `,`), so the
// apostrophe in `run: echo don't` is text, not a quote.
export function stripComment(line) {
  let quote = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote === "'") {
      if (c === "'") {
        if (line[i + 1] === "'") { i++; continue; }
        quote = null;
      }
      continue;
    }
    if (quote === '"') {
      if (c === '\\') { i++; continue; }
      if (c === '"') quote = null;
      continue;
    }
    if (c === '#' && (i === 0 || line[i - 1] === ' ' || line[i - 1] === '\t')) {
      return line.slice(0, i).replace(/\s+$/, '');
    }
    if (c === "'" || c === '"') {
      const before = line.slice(0, i).replace(/\s+$/, '');
      const prev = before[before.length - 1];
      if (before === '' || prev === ':' || prev === '-' || prev === '[' || prev === '{' || prev === ',') {
        quote = c;
      }
    }
  }
  return line.replace(/\s+$/, '');
}

function indentOf(line) {
  let n = 0;
  while (n < line.length && line[n] === ' ') n++;
  if (line[n] === '\t') return -1;
  return n;
}

function isSeqItem(content) {
  return content === '-' || content.startsWith('- ');
}

// Index of the `:` that separates a mapping key from its value, or -1.
function mappingColon(content) {
  let i = 0;
  if (content[0] === '"' || content[0] === "'") {
    const end = closingQuote(content, 0);
    if (end < 0) return -1;
    i = end + 1;
    while (content[i] === ' ') i++;
    if (content[i] === ':' && (i + 1 === content.length || content[i + 1] === ' ')) return i;
    return -1;
  }
  if (content[0] === '[' || content[0] === '{') return -1;
  for (; i < content.length; i++) {
    if (content.startsWith('${{', i)) {
      const end = content.indexOf('}}', i + 3);
      if (end < 0) return -1;
      i = end + 1;
      continue;
    }
    if (content[i] === ':' && (i + 1 === content.length || content[i + 1] === ' ')) return i;
  }
  return -1;
}

function closingQuote(s, start) {
  const q = s[start];
  for (let i = start + 1; i < s.length; i++) {
    if (q === "'" && s[i] === "'") {
      if (s[i + 1] === "'") { i++; continue; }
      return i;
    }
    if (q === '"') {
      if (s[i] === '\\') { i++; continue; }
      if (s[i] === '"') return i;
    }
  }
  return -1;
}

function unquote(s, lineNo) {
  const q = s[0];
  const end = closingQuote(s, 0);
  if (end !== s.length - 1) throw new YamlSubsetError(`unterminated or trailing text after quoted scalar: ${s}`, lineNo);
  const body = s.slice(1, -1);
  if (q === "'") return body.replace(/''/g, "'");
  return body.replace(/\\(x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|.)/g, (_, e) => {
    switch (e[0]) {
      case 'n': return '\n';
      case 't': return '\t';
      case 'r': return '\r';
      case '0': return '\0';
      case ' ': return ' ';
      case '/': return '/';
      case '\\': return '\\';
      case '"': return '"';
      case 'x': case 'u': case 'U': return String.fromCodePoint(parseInt(e.slice(1), 16));
      default: throw new YamlSubsetError(`unsupported escape \\${e}`, lineNo);
    }
  });
}

function checkScalarStart(s, lineNo) {
  if (/^[&*!]/.test(s)) throw new YamlSubsetError(`anchors, aliases and tags are not supported: ${s}`, lineNo);
  if (s.startsWith('? ') || s === '?') throw new YamlSubsetError('complex mapping keys are not supported', lineNo);
}

// Parse a flow collection ([..] or {..}) that starts at s[0].
function parseFlow(s, lineNo) {
  let i = 0;
  const skip = () => { while (i < s.length && /\s/.test(s[i])) i++; };
  const scalar = (stops) => {
    skip();
    if (s[i] === '"' || s[i] === "'") {
      const end = closingQuote(s, i);
      if (end < 0) throw new YamlSubsetError('unterminated quoted scalar in flow collection', lineNo);
      const v = unquote(s.slice(i, end + 1), lineNo);
      i = end + 1;
      return v;
    }
    let start = i;
    while (i < s.length) {
      if (s.startsWith('${{', i)) {
        const end = s.indexOf('}}', i + 3);
        if (end < 0) throw new YamlSubsetError('unterminated ${{ in flow collection', lineNo);
        i = end + 2;
        continue;
      }
      if (stops.includes(s[i])) break;
      if (s[i] === ':' && stops.includes(':') && (s[i + 1] === ' ' || s[i + 1] === ',' || s[i + 1] === '}' || i + 1 === s.length)) break;
      i++;
    }
    const v = s.slice(start, i).trim();
    checkScalarStart(v, lineNo);
    return v;
  };
  const value = (stops) => {
    skip();
    if (s[i] === '[') return seq();
    if (s[i] === '{') return map();
    return scalar(stops);
  };
  const seq = () => {
    i++;
    const out = [];
    skip();
    if (s[i] === ']') { i++; return out; }
    for (;;) {
      out.push(value([',', ']']));
      skip();
      if (s[i] === ',') { i++; skip(); if (s[i] === ']') { i++; return out; } continue; }
      if (s[i] === ']') { i++; return out; }
      throw new YamlSubsetError(`malformed flow sequence near: ${s.slice(i, i + 20)}`, lineNo);
    }
  };
  const map = () => {
    i++;
    const out = {};
    skip();
    if (s[i] === '}') { i++; return out; }
    for (;;) {
      const k = scalar([',', '}', ':']);
      skip();
      let v = null;
      if (s[i] === ':') { i++; v = value([',', '}']); skip(); }
      if (Object.prototype.hasOwnProperty.call(out, k)) throw new YamlSubsetError(`duplicate key ${k}`, lineNo);
      out[k] = v === '' ? null : v;
      if (s[i] === ',') { i++; skip(); if (s[i] === '}') { i++; return out; } continue; }
      if (s[i] === '}') { i++; return out; }
      throw new YamlSubsetError(`malformed flow mapping near: ${s.slice(i, i + 20)}`, lineNo);
    }
  };
  const v = value([]);
  skip();
  if (i !== s.length) throw new YamlSubsetError(`trailing text after flow collection: ${s.slice(i)}`, lineNo);
  return v;
}

function flowBalanced(s) {
  let depth = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    // A quote opens a scalar only where one can start, so the apostrophe in
    // `{ description: this site's }` is text.
    const prev = s.slice(0, i).replace(/\s+$/, '').slice(-1);
    if ((c === '"' || c === "'") && (prev === '' || '[{,:'.includes(prev))) {
      const end = closingQuote(s, i);
      if (end < 0) return false;
      i = end;
      continue;
    }
    if (s.startsWith('${{', i)) {
      const end = s.indexOf('}}', i + 3);
      if (end < 0) return false;
      i = end + 1;
      continue;
    }
    if (c === '[' || c === '{') depth++;
    if (c === ']' || c === '}') depth--;
  }
  return depth === 0;
}

export function parseYaml(text) {
  const raw = text.replace(/\r\n/g, '\n').split('\n');
  let pos = 0;

  // The next significant line at or after pos, or null.
  const peek = () => {
    while (pos < raw.length) {
      const stripped = stripComment(raw[pos]);
      if (stripped.trim() === '') { pos++; continue; }
      const indent = indentOf(stripped);
      if (indent < 0) throw new YamlSubsetError('tab indentation', pos + 1);
      return { indent, content: stripped.slice(indent), lineNo: pos + 1 };
    }
    return null;
  };

  // Lines are consumed by advancing pos; a sequence item's inline mapping is
  // handled by re-reading the same line with an override.
  let override = null;
  const current = () => {
    if (override) return override;
    return peek();
  };
  const advance = () => {
    if (override) { override = null; pos++; return; }
    pos++;
  };

  const blockScalar = (header, parentIndent, lineNo) => {
    const m = /^([|>])([+-]?)([1-9]?)([+-]?)$/.exec(header);
    if (!m) throw new YamlSubsetError(`unsupported block scalar header ${header}`, lineNo);
    const style = m[1];
    const chomp = m[2] || m[4];
    advance();
    const lines = [];
    let contentIndent = m[3] ? parentIndent + Number(m[3]) : -1;
    while (pos < raw.length) {
      const l = raw[pos];
      if (l.trim() === '') { lines.push(''); pos++; continue; }
      const ind = indentOf(l);
      if (contentIndent < 0) {
        if (ind <= parentIndent) break;
        contentIndent = ind;
      }
      if (ind < contentIndent) break;
      lines.push(l.slice(contentIndent));
      pos++;
    }
    let trailing = 0;
    while (lines.length && lines[lines.length - 1] === '') { lines.pop(); trailing++; }
    let body;
    if (style === '|') {
      body = lines.join('\n');
    } else {
      body = '';
      let breaks = 0;
      let prevMore = false;
      let started = false;
      for (const l of lines) {
        if (l === '') { breaks++; continue; }
        const more = l[0] === ' ' || l[0] === '\t';
        if (!started) {
          body += '\n'.repeat(breaks);
          started = true;
        } else if (!more && !prevMore) {
          body += breaks === 0 ? ' ' : '\n'.repeat(breaks);
        } else {
          body += '\n'.repeat(breaks + 1);
        }
        body += l;
        prevMore = more;
        breaks = 0;
      }
    }
    if (lines.length === 0) return chomp === '+' ? '\n'.repeat(trailing) : '';
    if (chomp === '-') return body;
    if (chomp === '+') return body + '\n' + '\n'.repeat(trailing);
    return body + '\n';
  };

  // A value written after `key:` or `- ` on the line at lineNo. parentIndent
  // is the column of the key (or of the dash).
  const inlineValue = (text, parentIndent, lineNo) => {
    checkScalarStart(text, lineNo);
    if (text[0] === '|' || text[0] === '>') return blockScalar(text, parentIndent, lineNo);
    if (text[0] === '[' || text[0] === '{') {
      let acc = text;
      advance();
      while (!flowBalanced(acc)) {
        if (pos >= raw.length) throw new YamlSubsetError('unterminated flow collection', lineNo);
        acc += ' ' + stripComment(raw[pos]).trim();
        pos++;
      }
      return parseFlow(acc, lineNo);
    }
    if (text[0] === '"' || text[0] === "'") {
      let acc = text;
      advance();
      while (closingQuote(acc, 0) < 0) {
        if (pos >= raw.length) throw new YamlSubsetError('unterminated quoted scalar', lineNo);
        const next = raw[pos].trim();
        acc += next === '' ? '\n' : (acc.endsWith('\n') ? '' : ' ') + next;
        pos++;
      }
      return unquote(acc.trim(), lineNo);
    }
    // Plain scalar, possibly continued on more-indented lines.
    advance();
    let acc = text;
    for (;;) {
      const nxt = peek();
      if (!nxt || nxt.indent <= parentIndent) break;
      if (mappingColon(nxt.content) >= 0 || isSeqItem(nxt.content)) {
        throw new YamlSubsetError('unexpected indented structure after a scalar', nxt.lineNo);
      }
      acc += ' ' + nxt.content.trim();
      pos++;
    }
    return acc;
  };

  const parseNode = (indent) => {
    const line = current();
    if (!line || line.indent < indent) return null;
    if (isSeqItem(line.content)) return parseSequence(line.indent);
    if (mappingColon(line.content) >= 0) return parseMapping(line.indent);
    return inlineValue(line.content, line.indent - 1, line.lineNo);
  };

  const parseMapping = (indent) => {
    const out = {};
    for (;;) {
      const line = current();
      if (!line || line.indent < indent) return out;
      if (line.indent > indent) throw new YamlSubsetError('unexpected indentation', line.lineNo);
      if (isSeqItem(line.content)) return out;
      const colon = mappingColon(line.content);
      if (colon < 0) throw new YamlSubsetError(`expected "key: value", got: ${line.content}`, line.lineNo);
      let key = line.content.slice(0, colon).trim();
      checkScalarStart(key, line.lineNo);
      if (key[0] === '"' || key[0] === "'") key = unquote(key, line.lineNo);
      if (key === '<<') throw new YamlSubsetError('merge keys are not supported', line.lineNo);
      if (Object.prototype.hasOwnProperty.call(out, key)) throw new YamlSubsetError(`duplicate key ${key}`, line.lineNo);
      const rest = line.content.slice(colon + 1).trim();
      if (rest !== '') {
        out[key] = inlineValue(rest, indent, line.lineNo);
        continue;
      }
      advance();
      const next = current();
      if (next && next.indent > indent) out[key] = parseNode(next.indent);
      else if (next && next.indent === indent && isSeqItem(next.content)) out[key] = parseSequence(indent);
      else out[key] = null;
    }
  };

  const parseSequence = (indent) => {
    const out = [];
    for (;;) {
      const line = current();
      if (!line || line.indent !== indent || !isSeqItem(line.content)) {
        if (line && line.indent > indent) throw new YamlSubsetError('unexpected indentation', line.lineNo);
        return out;
      }
      const rest = line.content.slice(1).replace(/^ +/, '');
      const col = line.indent + (line.content.length - rest.length);
      if (rest === '') {
        advance();
        const next = current();
        out.push(next && next.indent > indent ? parseNode(next.indent) : null);
        continue;
      }
      if (isSeqItem(rest) || mappingColon(rest) >= 0) {
        override = { indent: col, content: rest, lineNo: line.lineNo };
        out.push(isSeqItem(rest) ? parseSequence(col) : parseMapping(col));
        continue;
      }
      out.push(inlineValue(rest, indent, line.lineNo));
    }
  };

  // One document; a leading `---` is allowed, a second one is not.
  const first = peek();
  if (first && /^---\s*$/.test(first.content) && first.indent === 0) pos++;
  const start = peek();
  if (!start) return null;
  const doc = parseNode(start.indent);
  const rest = peek();
  if (rest) {
    if (/^(---|\.\.\.)\s*$/.test(rest.content)) throw new YamlSubsetError('multiple YAML documents are not supported', rest.lineNo);
    throw new YamlSubsetError(`unexpected content: ${rest.content}`, rest.lineNo);
  }
  return doc;
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

const SHA_PIN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(\/[^@\s]+)?@[0-9a-f]{40}$/;
const DOCKER_PIN = /^docker:\/\/[^@\s]+@sha256:[0-9a-f]{64}$/;

function isMap(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function triggersOf(doc) {
  const on = doc.on;
  if (typeof on === 'string') return [on];
  if (Array.isArray(on)) return on.map(String);
  if (isMap(on)) return Object.keys(on);
  return [];
}

// Every `uses:` line in the raw text with its line number and trailing comment.
function usesLines(text) {
  const out = [];
  text.replace(/\r\n/g, '\n').split('\n').forEach((line, i) => {
    const m = /^\s*(?:-\s+)?uses:\s*(['"]?)([^\s'"#]+)\1\s*(#.*)?$/.exec(line);
    if (m) out.push({ ref: m[2], comment: (m[3] || '').replace(/^#\s*/, ''), lineNo: i + 1 });
  });
  return out;
}

function checkPin(ref, comment, where, add) {
  if (ref.startsWith('./')) return;
  if (ref.startsWith('docker://')) {
    if (!DOCKER_PIN.test(ref)) add('pin', `${where}: docker image "${ref}" is not pinned by sha256 digest`);
    return;
  }
  if (!SHA_PIN.test(ref)) {
    add('pin', `${where}: "${ref}" is not pinned to a full 40-character commit SHA`);
    return;
  }
  if (!/^v?\d/.test(comment)) {
    add('pin', `${where}: "${ref}" has no version comment (write "# vX.Y.Z" after the SHA)`);
  }
}

function permissionValues(perms) {
  // Returns [[scope, value]] for a permissions block; a string block becomes
  // one entry under '*'.
  if (perms === null || perms === undefined) return [];
  if (typeof perms === 'string') return [['*', perms]];
  if (isMap(perms)) return Object.entries(perms).map(([k, v]) => [k, v === null ? '' : String(v)]);
  return [['*', JSON.stringify(perms)]];
}

const READ_ONLY = new Set(['read', 'none', 'read-all']);

function checkRunsOn(job, jobId, add) {
  const ro = job['runs-on'];
  const where = `job ${jobId}`;
  const labelOk = (l) => typeof l === 'string' && HOSTED_LABELS.has(l);
  if (typeof ro === 'string') {
    const m = /^\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}$/.exec(ro);
    if (m) {
      const key = m[1];
      const matrix = job.strategy && job.strategy.matrix;
      if (!isMap(matrix)) {
        add('runner', `${where}: runs-on uses matrix.${key} but the matrix is not a literal mapping`);
        return;
      }
      const values = [];
      if (key in matrix) {
        if (!Array.isArray(matrix[key])) {
          add('runner', `${where}: matrix.${key} is not a literal list`);
          return;
        }
        values.push(...matrix[key]);
      }
      for (const inc of Array.isArray(matrix.include) ? matrix.include : []) {
        if (isMap(inc) && key in inc) values.push(inc[key]);
      }
      if (values.length === 0) add('runner', `${where}: matrix.${key} has no values`);
      for (const v of values) {
        if (!labelOk(v)) add('runner', `${where}: matrix.${key} value ${JSON.stringify(v)} is not a GitHub-hosted runner label`);
      }
      return;
    }
    if (!labelOk(ro)) add('runner', `${where}: runs-on ${JSON.stringify(ro)} is not a GitHub-hosted runner label`);
    return;
  }
  if (Array.isArray(ro) && ro.length > 0) {
    for (const l of ro) if (!labelOk(l)) add('runner', `${where}: runs-on label ${JSON.stringify(l)} is not a GitHub-hosted runner label`);
    return;
  }
  add('runner', `${where}: runs-on ${JSON.stringify(ro)} is not a GitHub-hosted runner label (runner groups and computed labels are not allowed)`);
}

function checkStep(step, where, add) {
  if (!isMap(step) || typeof step.uses !== 'string') return;
  const action = step.uses.split('@')[0].toLowerCase();
  const withs = isMap(step.with) ? step.with : {};
  if (action === 'actions/cache' || action.startsWith('actions/cache/')) {
    add('cache', `${where}: ${step.uses.split('@')[0]} is not allowed (caches cross the trust boundary between runs)`);
  }
  const required = SETUP_ACTIONS_DEFAULT_CACHE_ON.get(action);
  if (required && String(withs[required]) !== 'false') {
    add('cache', `${where}: ${action} must set "${required}: false"`);
  }
  if (action.startsWith('actions/setup-') && 'cache' in withs && String(withs.cache) !== 'false' && withs.cache !== null) {
    add('cache', `${where}: ${action} enables a cache ("cache: ${withs.cache}")`);
  }
  if (action === 'actions/checkout' && String(withs['persist-credentials']) !== 'false') {
    add('checkout', `${where}: actions/checkout must set "persist-credentials: false"`);
  }
}

// Check one workflow file's text. Returns { violations: [{rule, message}] };
// throws YamlSubsetError if the file cannot be read as the supported subset.
export function checkWorkflowText(text, { composite = false } = {}) {
  const violations = [];
  const add = (rule, message) => violations.push({ rule, message });
  const doc = parseYaml(text);
  if (!isMap(doc)) throw new YamlSubsetError('the file is not a YAML mapping');

  const code = text.replace(/\r\n/g, '\n').split('\n').map(stripComment).join('\n');
  if (/self-hosted/i.test(code)) {
    add('runner', 'the word "self-hosted" appears outside a comment');
  }

  // Pins: from the raw lines (for the version comment) ...
  const raw = usesLines(text);
  for (const u of raw) checkPin(u.ref, u.comment, `line ${u.lineNo}`, add);

  if (composite) {
    const steps = isMap(doc.runs) && Array.isArray(doc.runs.steps) ? doc.runs.steps : [];
    steps.forEach((s, i) => checkStep(s, `step ${i + 1}`, add));
    // ... and from the structure, so a uses: the line scan missed still counts.
    for (const s of steps) if (isMap(s) && typeof s.uses === 'string' && !raw.some((u) => u.ref === s.uses)) checkPin(s.uses, '', 'composite step', add);
    return { violations };
  }

  const triggers = triggersOf(doc);
  if (triggers.length === 0) add('trigger', 'no "on:" triggers found');
  for (const t of FORBIDDEN_TRIGGERS) if (triggers.includes(t)) add('trigger', `"${t}" is not allowed`);
  const prTriggered = triggers.some((t) => PULL_REQUEST_TRIGGERS.includes(t) || t === 'pull_request_target');

  if (!Object.prototype.hasOwnProperty.call(doc, 'permissions')) {
    add('permissions', 'no top-level "permissions:" (the default token scope is a repository setting, not something this file controls)');
  }
  if (prTriggered) {
    for (const [scope, v] of permissionValues(doc.permissions)) {
      if (!READ_ONLY.has(v)) add('permissions', `top-level permission ${scope}: ${v} in a workflow triggered by a pull request`);
    }
    if (/secrets\s*\[/.test(code) || [...code.matchAll(/secrets\.([A-Za-z0-9_]+)/g)].some((m) => m[1] !== 'GITHUB_TOKEN')) {
      add('secrets', 'a workflow triggered by a pull request names a secret');
    }
  }

  const jobs = isMap(doc.jobs) ? doc.jobs : null;
  if (!jobs || Object.keys(jobs).length === 0) add('jobs', 'no jobs');
  for (const [jobId, job] of Object.entries(jobs || {})) {
    if (!isMap(job)) { add('jobs', `job ${jobId} is not a mapping`); continue; }
    if (prTriggered) {
      for (const [scope, v] of permissionValues(job.permissions)) {
        if (!READ_ONLY.has(v)) add('permissions', `job ${jobId}: permission ${scope}: ${v} in a workflow triggered by a pull request`);
      }
      if (job.secrets !== undefined && job.secrets !== null) add('secrets', `job ${jobId}: passes secrets to a reusable workflow`);
    }
    if (job.secrets === 'inherit') add('secrets', `job ${jobId}: "secrets: inherit" is not allowed`);
    if (typeof job.uses === 'string') {
      if (!raw.some((u) => u.ref === job.uses)) checkPin(job.uses, '', `job ${jobId}`, add);
      continue; // a reusable-workflow call has no runner of its own
    }
    checkRunsOn(job, jobId, add);
    const steps = Array.isArray(job.steps) ? job.steps : [];
    steps.forEach((s, i) => {
      checkStep(s, `job ${jobId} step ${i + 1}`, add);
      if (isMap(s) && typeof s.uses === 'string' && !raw.some((u) => u.ref === s.uses)) checkPin(s.uses, '', `job ${jobId} step ${i + 1}`, add);
    });
  }
  return { violations };
}

function listFiles(dir, match) {
  if (!existsSync(dir)) return [];
  const out = [];
  for (const name of readdirSync(dir).sort()) {
    const p = path.join(dir, name);
    if (statSync(p).isDirectory()) out.push(...listFiles(p, match));
    else if (match(name)) out.push(p);
  }
  return out;
}

// Check every workflow and composite action under root. Returns
// { files, violations: [{file, rule, message}], errors: [{file, message}] }.
export function checkRepository(root) {
  const isYaml = (n) => /\.ya?ml$/.test(n);
  const workflows = listFiles(path.join(root, '.github', 'workflows'), isYaml);
  const actions = listFiles(path.join(root, '.github', 'actions'), (n) => n === 'action.yml' || n === 'action.yaml');
  const violations = [];
  const errors = [];
  if (workflows.length === 0) errors.push({ file: path.join(root, '.github', 'workflows'), message: 'no workflow files found (wrong root?)' });
  for (const [file, composite] of [...workflows.map((f) => [f, false]), ...actions.map((f) => [f, true])]) {
    const rel = path.relative(root, file);
    try {
      const { violations: v } = checkWorkflowText(readFileSync(file, 'utf8'), { composite });
      for (const x of v) violations.push({ file: rel, ...x });
    } catch (e) {
      errors.push({ file: rel, message: e.message });
    }
  }
  return { files: workflows.length + actions.length, violations, errors };
}

function main() {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const root = path.resolve(process.argv[2] || path.join(here, '..'));
  const { files, violations, errors } = checkRepository(root);
  for (const e of errors) console.error(`::error file=${e.file}::cannot verify: ${e.message}`);
  for (const v of violations) console.error(`::error file=${v.file}::[${v.rule}] ${v.message}`);
  if (errors.length) {
    console.error(`check-workflows: ${errors.length} file(s) could not be verified`);
    process.exit(2);
  }
  if (violations.length) {
    console.error(`check-workflows: ${violations.length} violation(s) in ${files} file(s)`);
    process.exit(1);
  }
  console.log(`check-workflows: ${files} file(s), every rule holds`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
