import { Finding, VettingConfig } from '../types.js';
import { generateFindingId, truncateEvidence } from '../utils/sanitise.js';
import {
  MaliciousMatch,
  MaliciousPackagesIndex,
  matchDeclaredDependency,
  matchExactVersion,
} from '../utils/malicious-db.js';

interface PackageJson {
  name?: string;
  version?: string;
  dependencies?: Record<string, string> | null;
  devDependencies?: Record<string, string> | null;
  optionalDependencies?: Record<string, string> | null;
  scripts?: Record<string, string> | null;
}

interface LockfileEntry {
  name?: string;
  version?: string;
  resolved?: string;
  link?: boolean;
  dependencies?: Record<string, LockfileEntry> | null;
}

interface PackageLock {
  packages?: Record<string, LockfileEntry> | null;
  dependencies?: Record<string, LockfileEntry> | null;
}

// Only packages involved in real, documented supply-chain attacks. Kept alongside the
// OpenSSF dataset so these are flagged even before the dataset has been synced.
const KNOWN_MALICIOUS_PACKAGES = new Set([
  'event-stream',    // 2018: injected flatmap-stream to steal Bitcoin
  'flatmap-stream',  // Payload delivered via event-stream
]);

const SUSPICIOUS_PREFIXES = ['@free-', '@hack-', '@crack-', '@keygen-'];

export class DependencyAnalyzer {
  analyze(
    packageJson: PackageJson,
    skillPath: string,
    config: VettingConfig,
    maliciousDb?: MaliciousPackagesIndex | null,
  ): Finding[] {
    const findings: Finding[] = [];
    const pkgFile = `${skillPath}/package.json`;

    const deps: Record<string, string> = {
      ...(packageJson.dependencies ?? {}),
      ...(packageJson.devDependencies ?? {}),
    };

    if (maliciousDb) {
      // npm lets optionalDependencies override the same name in dependencies.
      const declared = {
        ...deps,
        ...(packageJson.optionalDependencies ?? {}),
      };
      for (const [name, spec] of Object.entries(declared)) {
        if (typeof spec !== 'string') continue;
        const target = resolveNpmAlias(name, spec);
        if (!target) continue;
        const match = matchDeclaredDependency(maliciousDb, target.name, target.spec);
        if (match) findings.push(maliciousFinding(match, target.name, `${name}@${spec}`, pkgFile));
      }
    }

    // Merge user-configured blocked packages with known malicious ones
    const blockedPackages = new Set([
      ...KNOWN_MALICIOUS_PACKAGES,
      ...(config.blockedPackages ?? []),
    ]);

    for (const [name, version] of Object.entries(deps)) {
      if (typeof version !== 'string') continue;

      // Known malicious or user-blocked packages
      if (blockedPackages.has(name)) {
        findings.push({
          id: generateFindingId(),
          severity: 'CRITICAL',
          category: 'DEPENDENCY_RISK',
          message: `Blocked dependency: ${name}`,
          file: pkgFile,
          evidence: `${name}@${version}`,
          cwe: 'CWE-829',
        });
      }

      // Suspicious prefixes
      for (const prefix of SUSPICIOUS_PREFIXES) {
        if (name.startsWith(prefix)) {
          findings.push({
            id: generateFindingId(),
            severity: 'WARNING',
            category: 'DEPENDENCY_RISK',
            message: `Suspicious package prefix: ${prefix}`,
            file: pkgFile,
            evidence: name,
          });
        }
      }

      // Unversioned deps (git/http/github:)
      if (version.startsWith('git') || version.startsWith('http') || version.includes('github:')) {
        findings.push({
          id: generateFindingId(),
          severity: 'WARNING',
          category: 'DEPENDENCY_RISK',
          message: 'External/unversioned dependency — cannot verify integrity',
          file: pkgFile,
          evidence: `${name}@${truncateEvidence(version, 50)}`,
          cwe: 'CWE-829',
        });
      }

      // Local file: protocol
      if (version.startsWith('file:')) {
        findings.push({
          id: generateFindingId(),
          severity: 'WARNING',
          category: 'DEPENDENCY_RISK',
          message: 'Local file dependency — verify path safety',
          file: pkgFile,
          evidence: `${name}@${version}`,
        });
      }
    }

    // Lifecycle scripts
    const dangerousScripts = ['postinstall', 'preinstall', 'install', 'prepare'];
    if (packageJson.scripts) {
      for (const script of dangerousScripts) {
        const scriptContent = packageJson.scripts[script];
        if (scriptContent) {
          findings.push({
            id: generateFindingId(),
            severity: script === 'postinstall' ? 'CRITICAL' : 'WARNING',
            category: 'DEPENDENCY_RISK',
            message: `Package contains ${script} script — executes automatically`,
            file: pkgFile,
            evidence: truncateEvidence(scriptContent),
            cwe: 'CWE-829',
          });
        }
      }
    }

    return findings;
  }

  /**
   * Check every package pinned in a package-lock.json / npm-shrinkwrap.json against the
   * OpenSSF malicious-packages index. Handles lockfile v1 (nested `dependencies`) and v2/v3 (`packages`).
   */
  analyzeLockfile(lockfile: PackageLock, file: string, maliciousDb: MaliciousPackagesIndex): Finding[] {
    const findings: Finding[] = [];
    const seen = new Set<string>();

    const check = (name: string, version: unknown): void => {
      if (typeof version !== 'string' || name === '') return;
      const key = `${name}@${version}`;
      if (seen.has(key)) return;
      seen.add(key);
      const match = matchExactVersion(maliciousDb, name, version);
      if (match) findings.push(maliciousFinding(match, name, key, file));
    };

    if (lockfile.packages && typeof lockfile.packages === 'object') {
      for (const [key, entry] of Object.entries(lockfile.packages)) {
        if (!entry || typeof entry !== 'object' || key === '') continue;
        const idx = key.lastIndexOf('node_modules/');
        if (idx === -1 || entry.link === true || !fromRegistry(entry.resolved)) continue;
        check(entry.name ?? key.slice(idx + 'node_modules/'.length), entry.version);
      }
    }

    const walk = (deps: Record<string, LockfileEntry> | null | undefined, depth: number): void => {
      if (!deps || typeof deps !== 'object' || depth > 64) return;
      for (const [name, entry] of Object.entries(deps)) {
        if (!entry || typeof entry !== 'object') continue;
        const version = entry.version;
        if (!fromRegistry(entry.resolved)) {
          walk(entry.dependencies, depth + 1);
          continue;
        }
        // v1 aliases record the real package as "npm:<name>@<version>".
        const alias = typeof version === 'string' ? resolveNpmAlias(name, version) : null;
        check(alias?.name ?? name, alias?.spec ?? version);
        walk(entry.dependencies, depth + 1);
      }
    };
    walk(lockfile.dependencies, 0);

    return findings;
  }
}

/** Lockfile entries without `resolved` come from the registry; git and file: sources do not. */
function fromRegistry(resolved: string | undefined): boolean {
  return typeof resolved !== 'string' || /^https?:\/\//.test(resolved);
}

/** Resolve `"alias": "npm:real-name@^1.0.0"` to the package that actually gets installed. */
function resolveNpmAlias(name: string, spec: string): { name: string; spec: string } | null {
  if (!spec.startsWith('npm:')) {
    // git, URL and file: specs are not installed from the registry.
    if (/^(git|https?:|file:|link:|github:|workspace:)/.test(spec) || (spec.includes('/') && !spec.startsWith('@'))) {
      return null;
    }
    return { name, spec };
  }
  const target = spec.slice(4);
  const at = target.lastIndexOf('@');
  if (at <= 0) return { name: target, spec: '*' };
  return { name: target.slice(0, at), spec: target.slice(at + 1) };
}

function maliciousFinding(match: MaliciousMatch, name: string, evidence: string, file: string): Finding {
  const ids = match.ids.slice(0, 3).join(', ') + (match.ids.length > 3 ? ', ...' : '');
  return {
    id: generateFindingId(),
    severity: match.certainty === 'exact' ? 'CRITICAL' : 'WARNING',
    category: 'DEPENDENCY_RISK',
    message:
      match.certainty === 'exact'
        ? `Known malicious package (OpenSSF ${ids}): ${name}`
        : `Dependency range can resolve to a known malicious version (OpenSSF ${ids}): ${name}`,
    file,
    evidence: truncateEvidence(evidence, 100),
    cwe: 'CWE-506',
  };
}
