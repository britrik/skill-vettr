import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { VettrEngine } from '../vettr-engine.js';
import { VettingConfig, ToolsInterface } from '../types.js';

const thisDir = path.dirname(fileURLToPath(import.meta.url));
const sourceFixturesDir = path.resolve(thisDir, '..', '..', 'test', 'fixtures');

// Copy fixtures to temp directory (which is in allowed roots) for testing
let tempFixturesDir: string;

async function copyDir(src: string, dest: string): Promise<void> {
  await fs.mkdir(dest, { recursive: true });
  const entries = await fs.readdir(src, { withFileTypes: true });
  for (const entry of entries) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);
    if (entry.isDirectory()) {
      await copyDir(srcPath, destPath);
    } else {
      await fs.copyFile(srcPath, destPath);
    }
  }
}

before(async () => {
  tempFixturesDir = await fs.mkdtemp(path.join(os.tmpdir(), 'skill-vettr-test-'));
  await copyDir(sourceFixturesDir, tempFixturesDir);
});

after(async () => {
  if (tempFixturesDir) {
    await fs.rm(tempFixturesDir, { recursive: true, force: true });
  }
});

const config: VettingConfig = {
  maxNetworkCalls: 5,
  allowedHosts: ['api.example.com'],
  blockObfuscation: true,
  requireAuthor: true,
  maxRiskScore: 50,
  checkTyposquatting: true,
  maliciousPatternsRefreshHours: 24,
  blockedAuthors: [],
  blockedPackages: [],
  typosquatTargets: ['hello-world'],
};

// Adapter that implements ToolsInterface using Node's fs module
const tools: ToolsInterface = {
  async readFile(p: string) {
    return fs.readFile(p, 'utf-8');
  },
  async writeFile(p: string, content: string) {
    await fs.writeFile(p, content, 'utf-8');
  },
  async stat(p: string) {
    const stats = await fs.stat(p);
    return {
      isDirectory: () => stats.isDirectory(),
      isFile: () => stats.isFile(),
      isSymbolicLink: () => stats.isSymbolicLink(),
    };
  },
  async lstat(p: string) {
    const stats = await fs.lstat(p);
    return {
      isDirectory: () => stats.isDirectory(),
      isFile: () => stats.isFile(),
      isSymbolicLink: () => stats.isSymbolicLink(),
    };
  },
  async realpath(p: string) {
    return fs.realpath(p);
  },
  async readdir(p: string) {
    return fs.readdir(p);
  },
  async mkdtemp(prefix: string) {
    return fs.mkdtemp(prefix);
  },
  async rm(p: string, opts?: { recursive?: boolean; force?: boolean }) {
    await fs.rm(p, opts);
  },
  async exists(p: string) {
    try {
      await fs.access(p);
      return true;
    } catch {
      return false;
    }
  },
};

async function writeHijackedDb(dir: string): Promise<string> {
  const dbPath = path.join(dir, 'hijacked-db.json');
  await fs.writeFile(dbPath, JSON.stringify({
    schema: 1,
    source: 'ossf/malicious-packages',
    commit: 'c504f23264a165b3c11afb5c71429bc8bcbf2f49',
    syncedAt: new Date().toISOString(),
    advisoryCount: 1,
    packages: { hijacked: { ids: ['MAL-2024-0002'], versions: ['1.2.3'] } },
  }));
  return dbPath;
}

describe('VettrEngine integration', () => {
  it('passes a safe skill with low risk score', async () => {
    const engine = new VettrEngine(config);
    const report = await engine.vetSkill(path.join(tempFixturesDir, 'safe-skill'), tools);

    assert.equal(report.skillName, 'hello-world');
    assert.ok(report.riskScore < 20, `Expected low risk, got ${report.riskScore}`);
    assert.ok(['SAFE', 'LOW'].includes(report.riskLevel), `Expected SAFE or LOW, got ${report.riskLevel}`);
    assert.equal(report.recommendation, 'INSTALL');
    assert.equal(report.vettrVersion, '2.1.0');
    assert.ok(report.metadata.checksumSha256);
    assert.ok(report.metadata.fileCount >= 2);
  });

  it('blocks a malicious skill with high risk score', async () => {
    const engine = new VettrEngine(config);
    const report = await engine.vetSkill(path.join(tempFixturesDir, 'malicious-skill'), tools);

    assert.ok(report.riskScore >= 50, `Expected high risk, got ${report.riskScore}`);
    assert.ok(
      ['HIGH', 'CRITICAL'].includes(report.riskLevel),
      `Expected HIGH or CRITICAL, got ${report.riskLevel}`,
    );
    assert.equal(report.recommendation, 'BLOCK');

    // Should detect multiple categories of issues
    const categories = new Set(report.findings.map((f) => f.category));
    assert.ok(categories.has('SHELL_INJECTION'), 'Should detect shell injection');
    assert.ok(categories.has('DEPENDENCY_RISK'), 'Should detect dependency risks');
    assert.ok(categories.has('PERMISSION_RISK'), 'Should detect permission risks');
  });

  it('detects typosquatting in malicious skill name', async () => {
    const engine = new VettrEngine(config);
    const report = await engine.vetSkill(path.join(tempFixturesDir, 'malicious-skill'), tools);

    const typoFindings = report.findings.filter((f) => f.category === 'TYPO_SQUATTING');
    assert.ok(typoFindings.length > 0, 'Should detect "helo-world" as typosquat of "hello-world"');
  });

  it('detects network calls', async () => {
    const engine = new VettrEngine(config);
    const report = await engine.vetSkill(path.join(tempFixturesDir, 'malicious-skill'), tools);

    assert.ok(report.metadata.networkCalls.length > 0, 'Should extract network calls');
    const disallowed = report.metadata.networkCalls.filter((c) => !c.allowed);
    assert.ok(disallowed.length > 0, 'Should flag non-whitelisted hosts');
  });

  it('reports correct metadata', async () => {
    const engine = new VettrEngine(config);
    const report = await engine.vetSkill(path.join(tempFixturesDir, 'safe-skill'), tools);

    assert.ok(report.metadata.fileCount > 0);
    assert.ok(report.metadata.totalLines > 0);
    assert.equal(typeof report.vettedAt, 'string');
    assert.ok(report.vettedAt.includes('T')); // ISO 8601
  });

  it('rejects non-directory paths', async () => {
    const engine = new VettrEngine(config);
    await assert.rejects(
      engine.vetSkill(path.join(tempFixturesDir, 'safe-skill', 'package.json'), tools),
      /directory/i,
    );
  });

  it('vettrignore excludes matching files from scan results', async () => {
    // Create a skill with a subdirectory containing shell injection patterns
    // and a .vettrignore that excludes that subdirectory
    const skillDir = path.join(tempFixturesDir, 'vettrignore-skill');
    await fs.mkdir(skillDir, { recursive: true });
    await fs.mkdir(path.join(skillDir, 'vendor'), { recursive: true });

    // Minimal SKILL.md
    await fs.writeFile(
      path.join(skillDir, 'SKILL.md'),
      '---\nname: vettrignore-test\nversion: 1.0.0\nauthor: test-author\n---\n# Test\n',
    );
    // Clean package.json
    await fs.writeFile(
      path.join(skillDir, 'package.json'),
      JSON.stringify({ name: 'vettrignore-test', version: '1.0.0' }),
    );
    // Clean main file
    await fs.writeFile(path.join(skillDir, 'index.ts'), 'export const x = 1;\n');

    // Vendor file with shell injection — should be excluded by vettrignore
    await fs.writeFile(
      path.join(skillDir, 'vendor', 'bad.ts'),
      "import { exec } from 'child_process';\nexec('rm -rf /');\n",
    );

    // .vettrignore excludes vendor/
    await fs.writeFile(path.join(skillDir, '.vettrignore'), 'vendor/\n');

    const engine = new VettrEngine({ ...config, trustVettrignore: true });
    const report = await engine.vetSkill(skillDir, tools);

    const exclusionNotice = report.findings.find((f) => f.message.includes('excluded from analysis'));
    assert.ok(exclusionNotice, 'Trusted exclusions should be reported in the findings');

    // No SHELL_INJECTION findings should come from vendor/bad.ts
    const shellFindings = report.findings.filter(
      (f) => f.category === 'SHELL_INJECTION' && f.file.includes('vendor'),
    );
    assert.equal(
      shellFindings.length,
      0,
      `Expected no SHELL_INJECTION findings from vendor/, got: ${JSON.stringify(shellFindings)}`,
    );
  });

  async function writeVendorSkill(name: string, ignore: string): Promise<string> {
    const skillDir = path.join(tempFixturesDir, name);
    await fs.mkdir(path.join(skillDir, 'vendor'), { recursive: true });
    await fs.writeFile(
      path.join(skillDir, 'SKILL.md'),
      `---\nname: ${name}\nversion: 1.0.0\nauthor: test-author\n---\n# Test\n`,
    );
    await fs.writeFile(path.join(skillDir, 'package.json'), JSON.stringify({ name, version: '1.0.0' }));
    await fs.writeFile(path.join(skillDir, 'index.ts'), 'export const x = 1;\n');
    await fs.writeFile(
      path.join(skillDir, 'vendor', 'bad.ts'),
      "import { exec } from 'child_process';\nexec('rm -rf /');\n",
    );
    await fs.writeFile(path.join(skillDir, '.vettrignore'), ignore);
    return skillDir;
  }

  it('vettrignore from the scanned skill is not applied by default', async () => {
    const skillDir = await writeVendorSkill('untrusted-vettrignore-skill', 'vendor/\n');
    const report = await new VettrEngine(config).vetSkill(skillDir, tools);

    const shellFindings = report.findings.filter(
      (f) => f.category === 'SHELL_INJECTION' && f.file.includes('vendor'),
    );
    assert.ok(shellFindings.length > 0, 'Untrusted .vettrignore must not hide vendor/bad.ts');
    assert.ok(
      report.findings.some((f) => f.severity === 'WARNING' && f.message.includes('not applied')),
      'Shipping a .vettrignore should be flagged',
    );
  });

  it('trusted vettrignore rejects patterns that exclude everything or the manifest', async () => {
    const skillDir = await writeVendorSkill('overbroad-vettrignore-skill', '**\npackage.json\n*\n');
    const report = await new VettrEngine({ ...config, trustVettrignore: true }).vetSkill(skillDir, tools);

    const rejected = report.findings.filter((f) => f.message.startsWith('.vettrignore pattern ') && f.message.includes('rejected'));
    assert.equal(rejected.length, 3);
    const shellFindings = report.findings.filter(
      (f) => f.category === 'SHELL_INJECTION' && f.file.includes('vendor'),
    );
    assert.ok(shellFindings.length > 0, 'Rejected patterns must not exclude vendor/bad.ts');
  });

  it('vettrignore absent means all files are scanned', async () => {
    // Same setup but without .vettrignore — vendor file should be scanned
    const skillDir = path.join(tempFixturesDir, 'no-vettrignore-skill');
    await fs.mkdir(skillDir, { recursive: true });
    await fs.mkdir(path.join(skillDir, 'vendor'), { recursive: true });

    await fs.writeFile(
      path.join(skillDir, 'SKILL.md'),
      '---\nname: no-ignore-test\nversion: 1.0.0\nauthor: test-author\n---\n# Test\n',
    );
    await fs.writeFile(
      path.join(skillDir, 'package.json'),
      JSON.stringify({ name: 'no-ignore-test', version: '1.0.0' }),
    );
    await fs.writeFile(path.join(skillDir, 'index.ts'), 'export const x = 1;\n');
    await fs.writeFile(
      path.join(skillDir, 'vendor', 'bad.ts'),
      "import { exec } from 'child_process';\nexec('rm -rf /');\n",
    );

    const engine = new VettrEngine(config);
    const report = await engine.vetSkill(skillDir, tools);

    // Without vettrignore, vendor/bad.ts should be scanned and flagged
    const shellFindings = report.findings.filter(
      (f) => f.category === 'SHELL_INJECTION' && f.file.includes('vendor'),
    );
    assert.ok(
      shellFindings.length > 0,
      'Without .vettrignore, vendor/bad.ts should produce SHELL_INJECTION findings',
    );
  });
});

describe('VettrEngine with the OpenSSF malicious-packages index', () => {
  it('reports the dataset as disabled when no path is configured', async () => {
    const report = await new VettrEngine(config).vetSkill(path.join(tempFixturesDir, 'safe-skill'), tools);
    assert.deepEqual(report.metadata.maliciousPackagesDb, { status: 'disabled' });
  });

  it('reports a configured but unsynced dataset without failing the scan', async () => {
    const engine = new VettrEngine({ ...config, maliciousPackagesDbPath: path.join(tempFixturesDir, 'missing.json') });
    const report = await engine.vetSkill(path.join(tempFixturesDir, 'safe-skill'), tools);
    assert.equal(report.metadata.maliciousPackagesDb?.status, 'not-synced');
    assert.equal(report.recommendation, 'INSTALL');
  });

  it('blocks a skill whose manifest or lockfile pulls a malicious package', async () => {
    const skillDir = path.join(tempFixturesDir, 'openssf-skill');
    await copyDir(path.join(tempFixturesDir, 'safe-skill'), skillDir);
    await fs.writeFile(
      path.join(skillDir, 'package.json'),
      JSON.stringify({ name: 'hello-world', version: '1.0.0', dependencies: { lodash: '^4.17.21', 'evil-pkg': '^1.0.0' } }),
    );
    await fs.writeFile(
      path.join(skillDir, 'package-lock.json'),
      JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/lodash/node_modules/hijacked': { version: '1.2.3' } } }),
    );
    const dbPath = path.join(tempFixturesDir, 'malicious-db.json');
    const syncedAt = new Date(Date.now() - 200 * 3_600_000).toISOString();
    await fs.writeFile(
      dbPath,
      JSON.stringify({
        schema: 1,
        source: 'ossf/malicious-packages',
        commit: 'c504f23264a165b3c11afb5c71429bc8bcbf2f49',
        syncedAt,
        advisoryCount: 2,
        packages: {
          'evil-pkg': { ids: ['MAL-2024-0001'], all: true },
          hijacked: { ids: ['MAL-2024-0002'], versions: ['1.2.3'] },
        },
      }),
    );

    const report = await new VettrEngine({ ...config, maliciousPackagesDbPath: dbPath }).vetSkill(skillDir, tools);

    assert.deepEqual(report.metadata.maliciousPackagesDb, {
      status: 'loaded',
      commit: 'c504f23264a165b3c11afb5c71429bc8bcbf2f49',
      syncedAt,
      advisoryCount: 2,
      stale: true,
    });
    const openssf = report.findings.filter((f) => f.message.includes('OpenSSF'));
    assert.deepEqual(openssf.map((f) => path.basename(f.file)).sort(), ['package-lock.json', 'package.json']);
    assert.ok(openssf.every((f) => f.severity === 'CRITICAL'));
    assert.equal(report.recommendation, 'BLOCK');
  });

  it('checks npm-shrinkwrap.json instead of a package-lock.json next to it', async () => {
    const skillDir = path.join(tempFixturesDir, 'shrinkwrap-skill');
    await copyDir(path.join(tempFixturesDir, 'safe-skill'), skillDir);
    const lock = (version: string) => JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/hijacked': { version } } });
    await fs.writeFile(path.join(skillDir, 'package-lock.json'), lock('1.2.3'));
    await fs.writeFile(path.join(skillDir, 'npm-shrinkwrap.json'), lock('1.2.2'));
    const legacyDir = path.join(tempFixturesDir, 'legacy-shrinkwrap-skill');
    await copyDir(path.join(tempFixturesDir, 'safe-skill'), legacyDir);
    await fs.writeFile(path.join(legacyDir, 'package-lock.json'), lock('1.2.3'));
    await fs.writeFile(path.join(legacyDir, 'npm-shrinkwrap.json'), JSON.stringify({ dependencies: { hijacked: { version: '1.2.2' } } }));
    const legacy = await new VettrEngine({ ...config, maliciousPackagesDbPath: await writeHijackedDb(legacyDir) })
      .vetSkill(legacyDir, tools);
    assert.ok(!legacy.findings.some((f) => f.message.includes('OpenSSF')));

    await fs.writeFile(path.join(legacyDir, 'package-lock.json'), lock('1.2.2'));
    await fs.writeFile(path.join(legacyDir, 'npm-shrinkwrap.json'), JSON.stringify({ dependencies: { hijacked: { version: '1.2.3' } } }));
    const flagged = await new VettrEngine({ ...config, maliciousPackagesDbPath: await writeHijackedDb(legacyDir) })
      .vetSkill(legacyDir, tools);
    const hits = flagged.findings.filter((f) => f.message.includes('OpenSSF'));
    assert.deepEqual(hits.map((f) => path.basename(f.file)), ['npm-shrinkwrap.json']);
    const report = await new VettrEngine({ ...config, maliciousPackagesDbPath: await writeHijackedDb(skillDir) })
      .vetSkill(skillDir, tools);
    assert.ok(!report.findings.some((f) => f.message.includes('OpenSSF')));
  });

  it('still checks package-lock.json when npm-shrinkwrap.json next to it is not a lockfile', async () => {
    const skillDir = path.join(tempFixturesDir, 'empty-shrinkwrap-skill');
    await copyDir(path.join(tempFixturesDir, 'safe-skill'), skillDir);
    await fs.writeFile(
      path.join(skillDir, 'package-lock.json'),
      JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/hijacked': { version: '1.2.3' } } }),
    );
    await fs.writeFile(path.join(skillDir, 'npm-shrinkwrap.json'), '');
    const report = await new VettrEngine({ ...config, maliciousPackagesDbPath: await writeHijackedDb(skillDir) })
      .vetSkill(skillDir, tools);
    assert.ok(report.findings.some((f) => f.message.includes('OpenSSF')));
  });
});

describe('VettrEngine type-aware analysis', () => {
  it('adds no type-aware findings for the safe fixture', async () => {
    const report = await new VettrEngine(config).vetSkill(path.join(tempFixturesDir, 'safe-skill'), tools);
    assert.ok(!report.findings.some((f) => f.message.startsWith('Untrusted input') || f.message.startsWith('Import of')));
  });

  it('reports handler input reaching exec with its flow', async () => {
    const skillDir = path.join(tempFixturesDir, 'taint-skill');
    await copyDir(path.join(tempFixturesDir, 'safe-skill'), skillDir);
    await fs.writeFile(
      path.join(skillDir, 'index.ts'),
      "import { exec as run } from 'child_process';\n" +
        "export default { onLoad(ctx) { ctx.commands.register('/x', (args) => { run(`echo ${args.msg}`); }); } };\n",
    );
    const report = await new VettrEngine(config).vetSkill(skillDir, tools);
    const f = report.findings.find((x) => x.message === 'Untrusted input reaches a child process: child_process.exec()');
    assert.equal(f?.evidence, 'args -> args.msg -> run(...)');
    assert.equal(f?.line, 2);
  });

  it('reads dependencies only from files named package.json', async () => {
    const skillDir = path.join(tempFixturesDir, 'manifest-lookalike-skill');
    await copyDir(path.join(tempFixturesDir, 'safe-skill'), skillDir);
    await fs.writeFile(path.join(skillDir, 'package.json'), JSON.stringify({ name: 'm', dependencies: { yaml: '2.0.0' } }));
    await fs.writeFile(path.join(skillDir, 'zz-backup-package.json'), JSON.stringify({ name: 'm', dependencies: {} }));
    await fs.writeFile(path.join(skillDir, 'index.ts'), "import yaml from 'yaml';\nexport default yaml;\n");
    const report = await new VettrEngine(config).vetSkill(skillDir, tools);
    assert.ok(!report.findings.some((f) => f.message.startsWith('Import of undeclared package')));
  });
});
