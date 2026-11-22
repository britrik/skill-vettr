import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  MaliciousPackagesIndex,
  addAdvisory,
  buildIndexFromTarball,
  indexAgeHours,
  loadMaliciousPackagesIndex,
  matchDeclaredDependency,
  matchExactVersion,
  osvEventsToRanges,
  syncMaliciousPackages,
} from '../utils/malicious-db.js';

function index(packages: MaliciousPackagesIndex['packages']): MaliciousPackagesIndex {
  return { schema: 1, source: 'test', commit: 'abc', syncedAt: new Date().toISOString(), advisoryCount: 1, packages };
}

describe('osvEventsToRanges', () => {
  it('treats an open range from 0 as every version', () => {
    assert.equal(osvEventsToRanges([{ introduced: '0' }]), 'all');
  });

  it('converts fixed and last_affected bounds', () => {
    assert.deepEqual(osvEventsToRanges([{ introduced: '1.2.0' }, { fixed: '1.2.3' }]), ['>=1.2.0 <1.2.3']);
    assert.deepEqual(osvEventsToRanges([{ introduced: '0' }, { last_affected: '2.0.0' }]), ['<=2.0.0']);
    assert.deepEqual(osvEventsToRanges([{ introduced: '3.0.0' }]), ['>=3.0.0']);
  });
});

describe('addAdvisory', () => {
  it('ignores withdrawn and non-npm advisories', () => {
    const pkgs = {};
    assert.equal(addAdvisory(pkgs, { id: 'MAL-1', withdrawn: '2024-01-01', affected: [{ package: { name: 'a', ecosystem: 'npm' } }] }), false);
    assert.equal(addAdvisory(pkgs, { id: 'MAL-2', affected: [{ package: { name: 'b', ecosystem: 'PyPI' } }] }), false);
    assert.deepEqual(pkgs, {});
  });

  it('marks a package with no versions or ranges as fully malicious', () => {
    const pkgs: MaliciousPackagesIndex['packages'] = {};
    addAdvisory(pkgs, { id: 'MAL-3', affected: [{ package: { name: 'evil', ecosystem: 'npm' } }] });
    assert.equal(pkgs['evil']?.all, true);
  });

  it('merges several advisories for one package', () => {
    const pkgs: MaliciousPackagesIndex['packages'] = {};
    addAdvisory(pkgs, { id: 'MAL-4', affected: [{ package: { name: 'p', ecosystem: 'npm' }, versions: ['1.0.1'] }] });
    addAdvisory(pkgs, { id: 'MAL-5', affected: [{ package: { name: 'p', ecosystem: 'npm' }, versions: ['1.0.2'] }] });
    assert.deepEqual(pkgs['p'], { ids: ['MAL-4', 'MAL-5'], versions: ['1.0.1', '1.0.2'] });
  });
});

describe('matching', () => {
  const db = index({
    whole: { ids: ['MAL-10'], all: true },
    pinned: { ids: ['MAL-11'], versions: ['1.4.2'] },
    ranged: { ids: ['MAL-12'], ranges: ['>=2.0.0 <2.0.3'] },
  });

  it('flags any spec for a fully malicious package', () => {
    assert.equal(matchDeclaredDependency(db, 'whole', '^0.1.0')?.certainty, 'exact');
  });

  it('flags an exact malicious version as exact and a covering range as possible', () => {
    assert.equal(matchDeclaredDependency(db, 'pinned', '1.4.2')?.certainty, 'exact');
    assert.equal(matchDeclaredDependency(db, 'pinned', '^1.4.0')?.certainty, 'possible');
    assert.equal(matchDeclaredDependency(db, 'ranged', '~2.0.0')?.certainty, 'possible');
  });

  it('does not flag specs that cannot resolve to a malicious version', () => {
    assert.equal(matchDeclaredDependency(db, 'pinned', '1.4.1'), null);
    assert.equal(matchDeclaredDependency(db, 'pinned', '^2.0.0'), null);
    assert.equal(matchDeclaredDependency(db, 'ranged', '^2.0.3'), null);
    assert.equal(matchDeclaredDependency(db, 'unknown', '*'), null);
  });

  it('treats a dist-tag as possibly malicious', () => {
    assert.equal(matchDeclaredDependency(db, 'pinned', 'latest')?.certainty, 'possible');
  });

  it('matches exact lockfile versions', () => {
    assert.ok(matchExactVersion(db, 'ranged', '2.0.2'));
    assert.equal(matchExactVersion(db, 'ranged', '2.0.3'), null);
    assert.ok(matchExactVersion(db, 'pinned', '1.4.2'));
  });

  it('does not throw on non-semver lockfile versions', () => {
    assert.equal(matchExactVersion(db, 'pinned', 'git+https://example.com/pinned.git#abc'), null);
    assert.equal(matchExactVersion(db, 'ranged', 'file:../ranged'), null);
  });

  it('does not match inherited object keys', () => {
    assert.equal(matchDeclaredDependency(db, 'constructor', '1.0.0'), null);
    assert.equal(matchExactVersion(db, '__proto__', '1.0.0'), null);
  });

  it('reports index age', () => {
    const old = { ...db, syncedAt: new Date(Date.now() - 50 * 3_600_000).toISOString() };
    assert.ok(Math.abs(indexAgeHours(old) - 50) < 0.1);
    assert.equal(indexAgeHours({ ...db, syncedAt: 'garbage' }), Infinity);
  });
});

describe('dataset archive', () => {
  let work: string;
  let tarball: string;
  let commit: string;
  const longScopedName = `@scope/${'x'.repeat(120)}`;

  before(async () => {
    work = await fs.mkdtemp(path.join(os.tmpdir(), 'vettr-mal-test-'));
    const repo = path.join(work, 'repo');
    const write = async (rel: string, body: unknown) => {
      await fs.mkdir(path.dirname(path.join(repo, rel)), { recursive: true });
      await fs.writeFile(path.join(repo, rel), typeof body === 'string' ? body : JSON.stringify(body));
    };
    await write('osv/malicious/npm/evil-pkg/MAL-2024-0001.json', {
      id: 'MAL-2024-0001',
      affected: [{ package: { name: 'evil-pkg', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }] }] }],
    });
    await write(`osv/malicious/npm/${longScopedName}/MAL-2024-0002.json`, {
      id: 'MAL-2024-0002',
      affected: [{ package: { name: longScopedName, ecosystem: 'npm' }, versions: ['1.0.0'] }],
    });
    await write('osv/malicious/npm/broken/MAL-2024-0003.json', '{not json');
    await write('osv/malicious/pypi/py-evil/MAL-2024-0004.json', {
      id: 'MAL-2024-0004',
      affected: [{ package: { name: 'py-evil', ecosystem: 'PyPI' } }],
    });
    await write('osv/withdrawn/npm/old/MAL-2023-0001.json', {
      id: 'MAL-2023-0001',
      affected: [{ package: { name: 'old', ecosystem: 'npm' } }],
    });
    const git = (...args: string[]) =>
      execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@t', '-c', 'commit.gpgsign=false', ...args], { cwd: repo }).toString().trim();
    git('init', '-q');
    git('add', '.');
    git('commit', '-q', '-m', 'fixture');
    commit = git('rev-parse', 'HEAD');
    tarball = path.join(work, 'mp.tar.gz');
    // git archive writes the same layout GitHub's tarballs use, including the pax commit header.
    git('archive', '--format=tar.gz', '--prefix=malicious-packages-main/', '-o', tarball, 'HEAD');
  });

  after(async () => {
    await fs.rm(work, { recursive: true, force: true });
  });

  it('indexes npm MAL advisories and records the commit', async () => {
    const idx = await buildIndexFromTarball(tarball);
    assert.equal(idx.commit, commit);
    assert.equal(idx.advisoryCount, 2);
    assert.deepEqual(Object.keys(idx.packages).sort(), [longScopedName, 'evil-pkg'].sort());
    assert.equal(idx.packages['evil-pkg']?.all, true);
    assert.deepEqual(idx.packages[longScopedName]?.versions, ['1.0.0']);
  });

  it('syncs to disk and loads the result offline', async () => {
    const dbPath = path.join(work, 'nested', 'db.json');
    assert.equal(await loadMaliciousPackagesIndex(dbPath), null);
    let fetchedUrl = '';
    await syncMaliciousPackages({
      dbPath,
      download: async (url, dest) => {
        fetchedUrl = url;
        await fs.copyFile(tarball, dest);
      },
    });
    assert.match(fetchedUrl, /^https:\/\/codeload\.github\.com\/ossf\/malicious-packages\//);
    const loaded = await loadMaliciousPackagesIndex(dbPath);
    assert.equal(loaded?.commit, commit);
    assert.ok(loaded && matchExactVersion(loaded, 'evil-pkg', '9.9.9'));
    const mode = (await fs.stat(dbPath)).mode & 0o777;
    assert.equal(mode, 0o600);
  });

  it('keeps the existing index when a sync fails', async () => {
    const dbPath = path.join(work, 'keep.json');
    await syncMaliciousPackages({ dbPath, download: (_u, dest) => fs.copyFile(tarball, dest) });
    const before = await fs.readFile(dbPath, 'utf8');
    await assert.rejects(
      syncMaliciousPackages({ dbPath, download: async (_u, dest) => fs.writeFile(dest, 'not a tarball') }),
    );
    assert.equal(await fs.readFile(dbPath, 'utf8'), before);
  });

  it('rejects an index file with an unknown format', async () => {
    const dbPath = path.join(work, 'bad.json');
    await fs.writeFile(dbPath, JSON.stringify({ schema: 99, packages: {} }));
    await assert.rejects(loadMaliciousPackagesIndex(dbPath), /unsupported format/);
  });
});

describe('large advisories', () => {
  it('keeps an advisory file larger than 1 MiB', async () => {
    const work = await fs.mkdtemp(path.join(os.tmpdir(), 'vettr-mal-big-'));
    try {
      const repo = path.join(work, 'repo');
      const dir = path.join(repo, 'osv/malicious/npm/big');
      await fs.mkdir(dir, { recursive: true });
      const versions = Array.from({ length: 120_000 }, (_, i) => `1.0.${i}`);
      await fs.writeFile(path.join(dir, 'MAL-2026-0001.json'), JSON.stringify({
        id: 'MAL-2026-0001',
        affected: [{ package: { name: 'big', ecosystem: 'npm' }, versions }],
      }));
      const git = (...args: string[]) =>
        execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@t', '-c', 'commit.gpgsign=false', ...args], { cwd: repo });
      git('init', '-q');
      git('add', '.');
      git('commit', '-q', '-m', 'big');
      const tarball = path.join(work, 'big.tar.gz');
      git('archive', '--format=tar.gz', '--prefix=mp/', '-o', tarball, 'HEAD');
      const idx = await buildIndexFromTarball(tarball);
      assert.ok(idx.packages['big'] && matchExactVersion(idx, 'big', '1.0.119999'));
    } finally {
      await fs.rm(work, { recursive: true, force: true });
    }
  });
});
