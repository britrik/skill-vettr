import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { VettrEngine } from '../vettr-engine.js';
import { VettingConfig, ToolsInterface } from '../types.js';

const thisDir = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.resolve(thisDir, '..', '..', 'test', 'fixtures');

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
    };
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

describe('VettrEngine integration', () => {
  it('passes a safe skill with low risk score', async () => {
    const engine = new VettrEngine(config);
    const report = await engine.vetSkill(path.join(fixturesDir, 'safe-skill'), tools);

    assert.equal(report.skillName, 'hello-world');
    assert.ok(report.riskScore < 20, `Expected low risk, got ${report.riskScore}`);
    assert.ok(['SAFE', 'LOW'].includes(report.riskLevel), `Expected SAFE or LOW, got ${report.riskLevel}`);
    assert.equal(report.recommendation, 'INSTALL');
    assert.equal(report.vettrVersion, '2.0.0');
    assert.ok(report.metadata.checksumSha256);
    assert.ok(report.metadata.fileCount >= 2);
  });

  it('blocks a malicious skill with high risk score', async () => {
    const engine = new VettrEngine(config);
    const report = await engine.vetSkill(path.join(fixturesDir, 'malicious-skill'), tools);

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
    const report = await engine.vetSkill(path.join(fixturesDir, 'malicious-skill'), tools);

    const typoFindings = report.findings.filter((f) => f.category === 'TYPO_SQUATTING');
    assert.ok(typoFindings.length > 0, 'Should detect "helo-world" as typosquat of "hello-world"');
  });

  it('detects network calls', async () => {
    const engine = new VettrEngine(config);
    const report = await engine.vetSkill(path.join(fixturesDir, 'malicious-skill'), tools);

    assert.ok(report.metadata.networkCalls.length > 0, 'Should extract network calls');
    const disallowed = report.metadata.networkCalls.filter((c) => !c.allowed);
    assert.ok(disallowed.length > 0, 'Should flag non-whitelisted hosts');
  });

  it('reports correct metadata', async () => {
    const engine = new VettrEngine(config);
    const report = await engine.vetSkill(path.join(fixturesDir, 'safe-skill'), tools);

    assert.ok(report.metadata.fileCount > 0);
    assert.ok(report.metadata.totalLines > 0);
    assert.equal(typeof report.vettedAt, 'string');
    assert.ok(report.vettedAt.includes('T')); // ISO 8601
  });

  it('rejects non-directory paths', async () => {
    const engine = new VettrEngine(config);
    await assert.rejects(
      engine.vetSkill(path.join(fixturesDir, 'safe-skill', 'package.json'), tools),
      /directory/i,
    );
  });
});
