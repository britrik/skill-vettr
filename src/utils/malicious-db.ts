import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import semver from 'semver';
import { downloadPublicHttps } from './safe-fetch.js';

/** Where the OpenSSF malicious-packages dataset is fetched from (a GitHub tarball of the default branch). */
export const MALICIOUS_PACKAGES_TARBALL_URL =
  'https://codeload.github.com/ossf/malicious-packages/tar.gz/refs/heads/main';

export const DEFAULT_MALICIOUS_PACKAGES_DB_PATH = path.join(
  os.homedir(),
  '.openclaw',
  'skill-vettr',
  'malicious-packages-npm.json',
);

const INDEX_SCHEMA = 1;
const MAX_TARBALL_BYTES = 300 * 1024 * 1024;
const MAX_UNPACKED_BYTES = 4 * 1024 * 1024 * 1024;
// Some advisories list thousands of versions (one is over 1 MiB), so the per-file cap is generous.
const MAX_ADVISORY_BYTES = 64 * 1024 * 1024;
const NPM_ADVISORY_PATH = /^[^/]+\/osv\/malicious\/npm\/.+\/MAL-[^/]+\.json$/;

export interface MaliciousPackageEntry {
  /** OSV MAL- advisory ids for this package. */
  ids: string[];
  /** True when an advisory covers every version of the package. */
  all?: boolean;
  /** Exact versions listed as malicious. */
  versions?: string[];
  /** Semver ranges listed as malicious, e.g. ">=1.2.0 <1.2.3". */
  ranges?: string[];
}

export interface MaliciousPackagesIndex {
  schema: number;
  source: string;
  /** Commit of ossf/malicious-packages the index was built from. */
  commit: string;
  syncedAt: string;
  advisoryCount: number;
  packages: Record<string, MaliciousPackageEntry>;
}

export interface MaliciousMatch {
  ids: string[];
  /** 'exact': the declared or locked version is malicious. 'possible': a declared range can resolve to one. */
  certainty: 'exact' | 'possible';
}

interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
}

interface OsvAdvisory {
  id?: string;
  withdrawn?: string;
  affected?: Array<{
    package?: { name?: string; ecosystem?: string };
    versions?: string[];
    ranges?: Array<{ type?: string; events?: OsvEvent[] }>;
  }>;
}

/** Turn OSV range events into semver ranges. Returns 'all' for an open range starting at 0. */
export function osvEventsToRanges(events: OsvEvent[]): string[] | 'all' {
  const ranges: string[] = [];
  let introduced: string | undefined;
  for (const event of events) {
    if (event.introduced !== undefined) {
      introduced = event.introduced;
    } else if (introduced !== undefined && (event.fixed !== undefined || event.last_affected !== undefined)) {
      const lower = introduced === '0' ? '' : `>=${introduced} `;
      const upper = event.fixed !== undefined ? `<${event.fixed}` : `<=${event.last_affected}`;
      ranges.push(`${lower}${upper}`);
      introduced = undefined;
    }
  }
  if (introduced !== undefined) {
    if (introduced === '0') return 'all';
    ranges.push(`>=${introduced}`);
  }
  return ranges;
}

/** Add one OSV advisory to the index. Withdrawn advisories and non-npm entries are ignored. */
export function addAdvisory(packages: Record<string, MaliciousPackageEntry>, advisory: OsvAdvisory): boolean {
  if (!advisory.id || advisory.withdrawn || !Array.isArray(advisory.affected)) return false;
  let added = false;
  for (const affected of advisory.affected) {
    const name = affected.package?.name;
    if (!name || affected.package?.ecosystem !== 'npm') continue;

    const entry = (packages[name] ??= { ids: [] });
    if (!entry.ids.includes(advisory.id)) entry.ids.push(advisory.id);
    added = true;

    const versions = (affected.versions ?? []).filter((v) => typeof v === 'string');
    const ranges: string[] = [];
    let all = false;
    for (const range of affected.ranges ?? []) {
      const converted = osvEventsToRanges(range.events ?? []);
      if (converted === 'all') all = true;
      else ranges.push(...converted);
    }
    // An advisory that names a package but no versions or ranges covers the whole package.
    if (all || (versions.length === 0 && ranges.length === 0)) {
      entry.all = true;
    }
    if (versions.length > 0) entry.versions = [...new Set([...(entry.versions ?? []), ...versions])];
    if (ranges.length > 0) entry.ranges = [...new Set([...(entry.ranges ?? []), ...ranges])];
  }
  return added;
}

interface TarEntry {
  path: string;
  data: Buffer;
}

function parseOctal(field: Buffer): number {
  // GNU base-256 encoding for sizes over 8 GB.
  if ((field[0]! & 0x80) !== 0) {
    let value = 0;
    for (let i = 1; i < field.length; i++) value = value * 256 + field[i]!;
    return value;
  }
  const text = field.toString('latin1').replace(/\0.*$/s, '').trim();
  return text === '' ? 0 : parseInt(text, 8);
}

function parsePax(data: Buffer): Record<string, string> {
  const out: Record<string, string> = {};
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    if (space === -1) break;
    const length = parseInt(data.toString('utf8', offset, space), 10);
    if (!Number.isFinite(length) || length <= 0) break;
    const record = data.toString('utf8', space + 1, offset + length - 1);
    const eq = record.indexOf('=');
    if (eq > 0) out[record.slice(0, eq)] = record.slice(eq + 1);
    offset += length;
  }
  return out;
}

/**
 * Stream a .tar.gz and yield regular files whose path passes `want`. Only ustar, pax ('x'/'g')
 * and GNU long-name ('L') headers are understood, which covers GitHub's tarballs. Files over
 * `maxEntryBytes` are skipped and the unpacked stream is capped at `maxBytes`.
 */
export async function* readTarGz(
  file: string,
  want: (entryPath: string) => boolean,
  opts: { maxBytes?: number; maxEntryBytes?: number; onGlobalHeader?: (h: Record<string, string>) => void } = {},
): AsyncGenerator<TarEntry> {
  const maxBytes = opts.maxBytes ?? MAX_UNPACKED_BYTES;
  const maxEntryBytes = opts.maxEntryBytes ?? MAX_ADVISORY_BYTES;
  const stream = fs.createReadStream(file).pipe(zlib.createGunzip());

  let buffer: Buffer = Buffer.alloc(0);
  let total = 0;
  let pending: { path: string; size: number; type: string; keep: boolean } | null = null;
  let skip = 0;
  let nextPath: string | undefined;

  for await (const chunk of stream as AsyncIterable<Buffer>) {
    total += chunk.length;
    if (total > maxBytes) {
      stream.destroy();
      throw new Error(`Dataset archive expands to more than ${maxBytes} bytes`);
    }
    buffer = buffer.length === 0 ? chunk : Buffer.concat([buffer, chunk]);

    while (true) {
      if (skip > 0) {
        const n = Math.min(skip, buffer.length);
        buffer = buffer.subarray(n);
        skip -= n;
        if (skip > 0) break;
      }

      if (pending) {
        const padded = Math.ceil(pending.size / 512) * 512;
        if (!pending.keep) {
          skip = padded;
          pending = null;
          continue;
        }
        if (buffer.length < padded) break;
        const data = Buffer.from(buffer.subarray(0, pending.size));
        buffer = buffer.subarray(padded);
        const entry = pending;
        pending = null;
        if (entry.type === 'x') {
          nextPath = parsePax(data).path ?? nextPath;
        } else if (entry.type === 'g') {
          opts.onGlobalHeader?.(parsePax(data));
        } else if (entry.type === 'L') {
          nextPath = data.toString('utf8').replace(/\0+$/, '');
        } else {
          yield { path: entry.path, data };
        }
        continue;
      }

      if (buffer.length < 512) break;
      const header = buffer.subarray(0, 512);
      buffer = buffer.subarray(512);
      if (header.every((b) => b === 0)) continue;

      const type = String.fromCharCode(header[156]!) || '0';
      const size = parseOctal(header.subarray(124, 136));
      const name = header.toString('utf8', 0, 100).replace(/\0.*$/s, '');
      const prefix = header.toString('utf8', 345, 500).replace(/\0.*$/s, '');
      const isMeta = type === 'x' || type === 'g' || type === 'L';
      const entryPath = isMeta ? '' : nextPath ?? (prefix ? `${prefix}/${name}` : name);
      if (!isMeta) nextPath = undefined;

      const isFile = type === '0' || type === '\0';
      const keep = isMeta ? size <= maxEntryBytes : isFile && size <= maxEntryBytes && want(entryPath);
      pending = { path: entryPath, size, type, keep };
    }
  }
}

/** Build the npm index from a downloaded ossf/malicious-packages tarball. */
export async function buildIndexFromTarball(tarball: string): Promise<MaliciousPackagesIndex> {
  const packages: Record<string, MaliciousPackageEntry> = {};
  let commit = 'unknown';
  let advisoryCount = 0;

  const entries = readTarGz(tarball, (p) => NPM_ADVISORY_PATH.test(p), {
    onGlobalHeader: (h) => {
      if (h.comment && /^[0-9a-f]{40}$/.test(h.comment)) commit = h.comment;
    },
  });
  for await (const entry of entries) {
    let advisory: OsvAdvisory;
    try {
      advisory = JSON.parse(entry.data.toString('utf8')) as OsvAdvisory;
    } catch {
      continue;
    }
    if (addAdvisory(packages, advisory)) advisoryCount++;
  }

  if (advisoryCount === 0) {
    throw new Error('No npm advisories found in the malicious-packages archive');
  }

  return {
    schema: INDEX_SCHEMA,
    source: 'ossf/malicious-packages',
    commit,
    syncedAt: new Date().toISOString(),
    advisoryCount,
    packages,
  };
}

export interface SyncOptions {
  dbPath?: string;
  url?: string;
  /** Replaces the network download; used by tests. */
  download?: (url: string, dest: string) => Promise<void>;
}

/** Download the dataset, build the npm index and write it atomically to `dbPath`. */
export async function syncMaliciousPackages(opts: SyncOptions = {}): Promise<MaliciousPackagesIndex> {
  const dbPath = opts.dbPath ?? DEFAULT_MALICIOUS_PACKAGES_DB_PATH;
  const url = opts.url ?? MALICIOUS_PACKAGES_TARBALL_URL;
  const download =
    opts.download ??
    ((u: string, dest: string) => downloadPublicHttps(u, dest, { maxBytes: MAX_TARBALL_BYTES, timeoutMs: 600_000 }));

  const tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'vettr-malicious-'));
  try {
    const tarball = path.join(tempDir, 'malicious-packages.tar.gz');
    await download(url, tarball);
    const index = await buildIndexFromTarball(tarball);

    await fs.promises.mkdir(path.dirname(dbPath), { recursive: true, mode: 0o700 });
    const tmpPath = `${dbPath}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
    await fs.promises.writeFile(tmpPath, JSON.stringify(index), { mode: 0o600 });
    await fs.promises.rename(tmpPath, dbPath);
    return index;
  } finally {
    await fs.promises.rm(tempDir, { recursive: true, force: true });
  }
}

let cached: { path: string; mtimeMs: number; size: number; index: MaliciousPackagesIndex } | null = null;

/**
 * Read the local index. Returns null when it has not been synced yet; throws when the file exists
 * but is not a valid index. The parsed index is cached until the file changes.
 */
export async function loadMaliciousPackagesIndex(dbPath: string): Promise<MaliciousPackagesIndex | null> {
  let stat: fs.Stats;
  try {
    stat = await fs.promises.stat(dbPath);
  } catch {
    return null;
  }
  if (cached && cached.path === dbPath && cached.mtimeMs === stat.mtimeMs && cached.size === stat.size) {
    return cached.index;
  }
  const parsed = JSON.parse(await fs.promises.readFile(dbPath, 'utf8')) as Partial<MaliciousPackagesIndex>;
  if (parsed.schema !== INDEX_SCHEMA || typeof parsed.packages !== 'object' || parsed.packages === null) {
    throw new Error('Malicious-packages index has an unsupported format; run /skill:vet-sync');
  }
  const index = parsed as MaliciousPackagesIndex;
  cached = { path: dbPath, mtimeMs: stat.mtimeMs, size: stat.size, index };
  return index;
}

function affectedVersionsMatch(entry: MaliciousPackageEntry, test: (malicious: string, isRange: boolean) => boolean): boolean {
  return (
    (entry.versions ?? []).some((v) => test(v, false)) ||
    (entry.ranges ?? []).some((r) => test(r, true))
  );
}

/** Whether an exact installed version (e.g. from a lockfile) is listed as malicious. */
export function matchExactVersion(
  index: MaliciousPackagesIndex,
  name: string,
  version: string,
): MaliciousMatch | null {
  const entry = Object.hasOwn(index.packages, name) ? index.packages[name] : undefined;
  if (!entry) return null;
  if (entry.all) return { ids: entry.ids, certainty: 'exact' };
  // Lockfiles can record git/file references instead of versions; those only match literally.
  const valid = semver.valid(version, true);
  const hit = affectedVersionsMatch(entry, (m, isRange) => {
    if (!valid) return !isRange && version === m;
    if (isRange) return semver.satisfies(valid, m, { includePrerelease: true });
    return version === m || (semver.valid(m, true) !== null && semver.eq(valid, m, true));
  });
  return hit ? { ids: entry.ids, certainty: 'exact' } : null;
}

/**
 * Whether a package.json dependency spec can install a malicious version. An exact version that
 * is listed is 'exact'; a range that can resolve to a listed version, or a dist-tag such as
 * "latest", is 'possible'.
 */
export function matchDeclaredDependency(
  index: MaliciousPackagesIndex,
  name: string,
  spec: string,
): MaliciousMatch | null {
  const entry = Object.hasOwn(index.packages, name) ? index.packages[name] : undefined;
  if (!entry) return null;
  if (entry.all) return { ids: entry.ids, certainty: 'exact' };

  const exact = semver.valid(spec, true);
  if (exact) return matchExactVersion(index, name, exact);

  const range = semver.validRange(spec, { loose: true });
  if (range === null) {
    // A dist-tag (e.g. "latest") can point at any version, including a malicious one.
    return { ids: entry.ids, certainty: 'possible' };
  }
  const hit = affectedVersionsMatch(entry, (m, isRange) =>
    isRange
      ? semver.intersects(range, m, { includePrerelease: true })
      : semver.valid(m, true) !== null && semver.satisfies(m, range, { includePrerelease: true, loose: true }),
  );
  return hit ? { ids: entry.ids, certainty: 'possible' } : null;
}

/** Hours since the index was synced, or Infinity when its timestamp is unreadable. */
export function indexAgeHours(index: MaliciousPackagesIndex, now = Date.now()): number {
  const synced = Date.parse(index.syncedAt);
  return Number.isFinite(synced) ? (now - synced) / 3_600_000 : Infinity;
}
