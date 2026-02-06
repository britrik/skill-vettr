import path from 'node:path';
import os from 'node:os';

import { OpenClawSkill, SkillContext } from '@openclaw/sdk';
import { VettrEngine } from './vettr-engine.js';
import { VettingConfig, VettingReport } from './types.js';
import {
  sanitiseSlug,
  sanitiseUrl,
  sanitisePath,
  getAllowedRoots,
  generateSecureTempName,
} from './utils/sanitise.js';
import { execSafe } from './utils/exec-safe.js';

const DEFAULT_CONFIG: VettingConfig = {
  maxNetworkCalls: 5,
  allowedHosts: [
    'api.openai.com',
    'api.anthropic.com',
    'registry.npmjs.org',
    'api.github.com',
    'raw.githubusercontent.com',
  ],
  blockObfuscation: true,
  requireAuthor: true,
  maxRiskScore: 50,
  checkTyposquatting: true,
  maliciousPatternsRefreshHours: 24,
  blockedAuthors: [],
  blockedPackages: [],
  typosquatTargets: [],
};

export default class SkillVettr implements OpenClawSkill {
  name = 'skill-vettr';
  version = '2.0.0';
  description = 'Security vetting for third-party OpenClaw skills';

  private config: VettingConfig = DEFAULT_CONFIG;
  private engine!: VettrEngine;

  async onLoad(ctx: SkillContext): Promise<void> {
    // Merge user config with defaults
    const userConfig = ctx.config.get<Partial<VettingConfig>>('skill-vettr', {});
    this.config = { ...DEFAULT_CONFIG, ...userConfig };
    this.engine = new VettrEngine(this.config);

    // Register: /skill:vet --path <local-path>
    ctx.commands.register('/skill:vet', async (args) => {
      const skillPath = args['path'] ?? args['source'];

      if (!skillPath || typeof skillPath !== 'string') {
        return 'Usage: /skill:vet --path <directory>';
      }

      try {
        const sanitisedPath = sanitisePath(skillPath, getAllowedRoots());

        ctx.ui.showProgress('Analysing skill...');
        const report = await this.engine.vetSkill(sanitisedPath, ctx.tools);

        return this.handleReport(report, ctx);
      } catch (err) {
        return `Vetting failed: ${err instanceof Error ? err.message : 'Unknown error'}`;
      }
    });

    // Register: /skill:vet-url --url <https://...>
    ctx.commands.register('/skill:vet-url', async (args) => {
      const url = args['url'];

      if (!url || typeof url !== 'string') {
        return 'Usage: /skill:vet-url --url <https://...>';
      }

      let tempDir: string | null = null;

      try {
        const sanitisedUrl = sanitiseUrl(url);
        tempDir = path.join(os.tmpdir(), generateSecureTempName());

        ctx.ui.showProgress(`Downloading from ${sanitisedUrl}...`);

        // Download using safe exec
        if (sanitisedUrl.endsWith('.git')) {
          await execSafe('git', ['clone', '--depth', '1', sanitisedUrl, tempDir]);
        } else {
          const tarPath = path.join(tempDir, 'skill.tar.gz');
          await ctx.tools.writeFile(tarPath, ''); // Create dir
          await execSafe('curl', ['-fsSL', '-o', tarPath, sanitisedUrl]);
          await execSafe('tar', ['-xzf', tarPath, '-C', tempDir]);
        }

        ctx.ui.showProgress('Analysing skill...');
        const report = await this.engine.vetSkill(tempDir, ctx.tools);

        return this.handleReport(report, ctx);
      } catch (err) {
        return `Vetting failed: ${err instanceof Error ? err.message : 'Unknown error'}`;
      } finally {
        // Cleanup
        if (tempDir) {
          await ctx.tools.rm(tempDir, { recursive: true, force: true }).catch(() => {});
        }
      }
    });

    // Register: /skill:vet-clawhub --skill <slug>
    ctx.commands.register('/skill:vet-clawhub', async (args) => {
      const slug = args['skill'];

      if (!slug || typeof slug !== 'string') {
        return 'Usage: /skill:vet-clawhub --skill <slug>';
      }

      let tempDir: string | null = null;

      try {
        const sanitisedSlug = sanitiseSlug(slug);
        tempDir = path.join(os.tmpdir(), generateSecureTempName());

        ctx.ui.showProgress(`Fetching "${sanitisedSlug}" from ClawHub...`);

        await execSafe('clawhub', ['download', sanitisedSlug, '--output', tempDir]);

        ctx.ui.showProgress('Analysing skill...');
        const report = await this.engine.vetSkill(tempDir, ctx.tools);

        return this.handleReport(report, ctx);
      } catch (err) {
        return `Vetting failed: ${err instanceof Error ? err.message : 'Unknown error'}`;
      } finally {
        // Cleanup
        if (tempDir) {
          await ctx.tools.rm(tempDir, { recursive: true, force: true }).catch(() => {});
        }
      }
    });

    // Auto-vet hook (if enabled)
    const autoVet = ctx.config.get<boolean>('skill-vettr.autoVet', false);
    if (autoVet) {
      ctx.hooks.on('skill:pre-install', async (event) => {
        try {
          const report = await this.engine.vetSkill(event.skillPath, ctx.tools);

          if (report.recommendation === 'BLOCK') {
            event.preventDefault();
            ctx.ui.notify(
              `🚫 Installation blocked: ${report.findings[0]?.message ?? 'Critical risk detected'}`
            );
            return;
          }

          if (report.recommendation === 'REVIEW') {
            const approved = await ctx.ui.confirm(
              `⚠️ Skill "${report.skillName}" flagged (score: ${report.riskScore}/100). Install anyway?`
            );
            if (!approved) {
              event.preventDefault();
            }
          }
        } catch (err) {
          event.preventDefault();
          ctx.ui.notify(`Vetting error: ${err instanceof Error ? err.message : 'Unknown'}`);
        }
      });
    }
  }

  private async handleReport(report: VettingReport, ctx: SkillContext): Promise<string> {
    const output = this.formatReport(report);

    if (report.recommendation === 'REVIEW') {
      const approved = await ctx.ui.confirm(
        `⚠️ Skill "${report.skillName}" requires review (score: ${report.riskScore}/100). Approve?`
      );
      return approved ? output + '\n\n✅ User approved' : output + '\n\n❌ User rejected';
    }

    if (report.recommendation === 'BLOCK') {
      return output + '\n\n🚫 Installation BLOCKED - critical security risks detected';
    }

    return output + '\n\n✅ Skill passed vetting';
  }

  private formatReport(report: VettingReport): string {
    const lines = [
      ``,
      `┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓`,
      `┃  SKILL VETTING REPORT                                     ┃`,
      `┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛`,
      ``,
      `  Skill:          ${report.skillName}`,
      `  Risk Score:     ${report.riskScore}/100`,
      `  Risk Level:     ${this.formatRiskLevel(report.riskLevel)}`,
      `  Recommendation: ${this.formatRecommendation(report.recommendation)}`,
      `  Vetted At:      ${report.vettedAt}`,
      `  Vettr Version:  ${report.vettrVersion}`,
      ``,
      `┌─ Metadata ─────────────────────────────────────────────────`,
      `│  Author Verified:     ${report.metadata.authorVerified ? '✓ Yes' : '✗ No'}`,
      `│  External Deps:       ${report.metadata.hasExternalDeps ? '⚠ Yes' : '✓ No'}`,
      `│  Network Calls:       ${report.metadata.networkCalls.length}`,
      `│  Files Analysed:      ${report.metadata.fileCount}`,
      `│  Total Lines:         ${report.metadata.totalLines}`,
      `│  Checksum (SHA-256):  ${report.metadata.checksumSha256?.substring(0, 16)}...`,
      `└─────────────────────────────────────────────────────────────`,
      ``,
    ];

    // Network calls detail
    if (report.metadata.networkCalls.length > 0) {
      lines.push(`┌─ Network Calls ────────────────────────────────────────────`);
      for (const call of report.metadata.networkCalls.slice(0, 10)) {
        const status = call.allowed ? '✓' : '✗';
        const urlDisplay = call.url.length > 50 ? call.url.substring(0, 47) + '...' : call.url;
        lines.push(`│  ${status} ${urlDisplay}`);
      }
      if (report.metadata.networkCalls.length > 10) {
        lines.push(`│  ... and ${report.metadata.networkCalls.length - 10} more`);
      }
      lines.push(`└─────────────────────────────────────────────────────────────`);
      lines.push(``);
    }

    // Findings
    if (report.findings.length > 0) {
      lines.push(`┌─ Findings (${report.findings.length}) ─────────────────────────────────────────`);

      const bySeverity = {
        CRITICAL: report.findings.filter((f) => f.severity === 'CRITICAL'),
        WARNING: report.findings.filter((f) => f.severity === 'WARNING'),
        INFO: report.findings.filter((f) => f.severity === 'INFO'),
      };

      for (const [severity, findings] of Object.entries(bySeverity)) {
        if (findings.length === 0) continue;

        lines.push(`│`);
        lines.push(`│  [${severity}] (${findings.length})`);

        for (const f of findings.slice(0, 5)) {
          lines.push(`│    • ${f.category}: ${f.message}`);
          lines.push(`│      File: ${f.file}${f.line ? `:${f.line}` : ''}`);
          if (f.cwe) {
            lines.push(`│      Ref: ${f.cwe}`);
          }
          lines.push(`│      Evidence: ${f.evidence}`);
        }

        if (findings.length > 5) {
          lines.push(`│    ... and ${findings.length - 5} more ${severity} findings`);
        }
      }

      lines.push(`└─────────────────────────────────────────────────────────────`);
    } else {
      lines.push(`┌─ Findings ─────────────────────────────────────────────────`);
      lines.push(`│  ✓ No security findings detected`);
      lines.push(`└─────────────────────────────────────────────────────────────`);
    }

    return lines.join('\n');
  }

  private formatRiskLevel(level: VettingReport['riskLevel']): string {
    const icons: Record<VettingReport['riskLevel'], string> = {
      SAFE: '🟢 SAFE',
      LOW: '🟡 LOW',
      MEDIUM: '🟠 MEDIUM',
      HIGH: '🔴 HIGH',
      CRITICAL: '⛔ CRITICAL',
    };
    return icons[level];
  }

  private formatRecommendation(rec: VettingReport['recommendation']): string {
    const icons: Record<VettingReport['recommendation'], string> = {
      INSTALL: '✓ INSTALL',
      REVIEW: '⚠ REVIEW',
      BLOCK: '🚫 BLOCK',
    };
    return icons[rec];
  }
}
