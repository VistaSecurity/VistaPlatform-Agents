// Deterministic archive writers: a release package is a pure function of its
// entries and the source commit's time, so two builds of one commit package
// to the same bytes and a digest identifies the content, not the run.
//
// tar.gz (ustar, gzip with no name and mtime 0) for Linux and macOS, zip
// (deflate) for Windows. Entries are written in the order given, under one
// top-level directory; owner and group are 0, every mtime is the given epoch.
// Zero dependencies; read back with tar, unzip, Python's zipfile or
// PowerShell's Expand-Archive.

import { deflateRawSync, gzipSync } from 'node:zlib';

// entries: [{ name, data: Buffer, mode: 0o755 | 0o644 }]
export function tarGz(root, entries, mtime) {
  const blocks = [header(`${root}/`, 0, 0o755, mtime, '5')];
  for (const e of entries) {
    blocks.push(header(`${root}/${e.name}`, e.data.length, e.mode, mtime, '0'));
    blocks.push(e.data);
    const pad = (512 - (e.data.length % 512)) % 512;
    if (pad) blocks.push(Buffer.alloc(pad));
  }
  blocks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(blocks), { level: 9 });
}

function splitName(name) {
  if (Buffer.byteLength(name) <= 100) return { name, prefix: '' };
  // ustar: prefix (<= 155) + '/' + name (<= 100), split at a slash.
  for (let i = name.length - 1; i > 0; i--) {
    if (name[i] !== '/') continue;
    const prefix = name.slice(0, i);
    const rest = name.slice(i + 1);
    if (Buffer.byteLength(prefix) <= 155 && Buffer.byteLength(rest) <= 100 && rest !== '') return { name: rest, prefix };
  }
  throw new Error(`path too long for ustar: ${name}`);
}

function octal(n, width) {
  const s = n.toString(8);
  if (s.length > width - 1) throw new Error(`value ${n} does not fit a ${width}-byte tar field`);
  return s.padStart(width - 1, '0') + '\0';
}

function header(fullName, size, mode, mtime, type) {
  const b = Buffer.alloc(512);
  const { name, prefix } = splitName(fullName);
  b.write(name, 0, 100, 'utf8');
  b.write(octal(mode, 8), 100, 8, 'ascii');
  b.write(octal(0, 8), 108, 8, 'ascii');
  b.write(octal(0, 8), 116, 8, 'ascii');
  b.write(octal(size, 12), 124, 12, 'ascii');
  b.write(octal(mtime, 12), 136, 12, 'ascii');
  b.fill(' ', 148, 156);
  b.write(type, 156, 1, 'ascii');
  b.write('ustar\0', 257, 6, 'ascii');
  b.write('00', 263, 2, 'ascii');
  b.write(prefix, 345, 155, 'utf8');
  let sum = 0;
  for (const x of b) sum += x;
  b.write(octal(sum, 7) + ' ', 148, 8, 'ascii');
  return b;
}

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

export function crc32(buf) {
  let c = 0xffffffff;
  for (const x of buf) c = CRC_TABLE[(c ^ x) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function dosTime(epoch) {
  const d = new Date(epoch * 1000);
  const year = Math.max(d.getUTCFullYear(), 1980);
  return {
    time: (d.getUTCHours() << 11) | (d.getUTCMinutes() << 5) | Math.floor(d.getUTCSeconds() / 2),
    date: ((year - 1980) << 9) | ((d.getUTCMonth() + 1) << 5) | d.getUTCDate(),
  };
}

export function zip(root, entries, mtime) {
  const { time, date } = dosTime(mtime);
  const locals = [];
  const centrals = [];
  let offset = 0;
  const all = [{ name: `${root}/`, data: Buffer.alloc(0), mode: 0o755, dir: true }, ...entries.map((e) => ({ ...e, name: `${root}/${e.name}` }))];
  for (const e of all) {
    const name = Buffer.from(e.name, 'utf8');
    const data = e.dir ? Buffer.alloc(0) : deflateRawSync(e.data, { level: 9 });
    const method = e.dir ? 0 : 8;
    const crc = e.dir ? 0 : crc32(e.data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0x0800, 6); // UTF-8 names
    local.writeUInt16LE(method, 8);
    local.writeUInt16LE(time, 10);
    local.writeUInt16LE(date, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(e.data.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    locals.push(local, name, data);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE((3 << 8) | 20, 4); // made by: Unix, so the mode below is read
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt16LE(time, 12);
    central.writeUInt16LE(date, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(e.data.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(0, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt16LE(0, 34);
    central.writeUInt16LE(0, 36);
    const unixMode = (e.dir ? 0o040000 : 0o100000) | e.mode;
    central.writeUInt32LE(((unixMode << 16) | (e.dir ? 0x10 : 0)) >>> 0, 38);
    central.writeUInt32LE(offset, 42);
    centrals.push(central, name);
    offset += local.length + name.length + data.length;
  }
  const cd = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(all.length, 8);
  end.writeUInt16LE(all.length, 10);
  end.writeUInt32LE(cd.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, end]);
}
