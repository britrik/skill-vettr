# skill-vettr v2.0.8

Static analysis security scanner for OpenClaw skills. Analyses code before installation to detect common threats.

## Quick Start

```bash
cd ~/.openclaw/skills/skill-scanner
npm install
npm run build
npm test
```

> ⚠️ `npm install` runs dependency lifecycle scripts (tree-sitter includes native builds). For stronger isolation, install inside a container or use `npm ci --ignore-scripts` (note: AST analysis may break without tree-sitter WASM artifacts).

## What It Does

skill-vettr scans a skill's source code, dependencies, and metadata for security issues. It uses:

- **tree-sitter AST parsing** for structural code analysis (eval, exec, spawn, dynamic require, prototype pollution, etc.)
- **Type-aware rules** ([ts-morph](https://github.com/dsherret/ts-morph), one in-memory project per scan): untrusted input reaching child processes, filesystem writes or network requests, and imports that don't resolve or aren't declared in `package.json`
- **Regex patterns** for things AST can't detect (prompt injection, homoglyph attacks, encoded function names)
- **Dependency analysis** for known malicious packages, suspicious prefixes, lifecycle scripts
- **Metadata analysis** for typosquatting (Levenshtein distance), dangerous permissions, blocked authors

## What It Doesn't Do

This is a heuristic scanner. It has inherent limitations:

- Cannot detect runtime-only behaviour (e.g., code that downloads malware at runtime from an innocuous-looking URL)
- AST queries can be evaded by sufficiently motivated attackers (e.g., multi-stage string construction)
- Only scans JS/TS code files — binary payloads, images, and other non-text files are skipped
- Does not sandbox or execute the target skill
- Malicious package lists are small and non-exhaustive

For high-security environments, combine with sandboxing and manual review.

## External Binaries

The `vet-url` and `vet-clawhub` commands invoke external binaries via `execSafe` (uses `execFile`, no shell spawned):

| Binary | Command | Purpose |
|--------|---------|---------|
| `git` | `vet-url` | Clone `.git` URLs (hooks disabled via `-c core.hooksPath=/dev/null`; connection pinned to the validated public address; user and system git config ignored) |
| `tar` | `vet-url` | Extract archives (`--no-same-owner --no-same-permissions`) |
| `clawhub` | `vet-clawhub` | Fetch skills from ClawHub registry |

The `/skill:vet` command (local path) requires only `node`. Ensure external binaries are trusted and available on `PATH` before using remote vetting commands.

## Usage

**Vet a local skill directory:**
```
/skill:vet --path ~/Downloads/suspicious-skill
```

**Vet from URL:**
```
/skill:vet-url --url https://github.com/org/skill/archive/main.tar.gz
```

**Vet from ClawHub:**
```
/skill:vet-clawhub --skill some-skill-name
```

## Configuration

Add to `~/.openclaw/config.json`:

```json
{
  "skill-vettr": {
    "maxRiskScore": 50,
    "requireAuthor": true,
    "autoVet": true,
    "maxNetworkCalls": 5,
    "allowedHosts": ["api.openai.com", "api.anthropic.com", "registry.npmjs.org"],
    "blockedAuthors": [],
    "blockedPackages": [],
    "typosquatTargets": ["my-important-skill"]
  }
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `maxRiskScore` | 50 | Score at or above which installation is blocked |
| `requireAuthor` | true | Warn if SKILL.md lacks an author field |
| `autoVet` | false | Automatically vet skills on `skill:pre-install` hook |
| `maxNetworkCalls` | 5 | Excess network calls beyond this add to risk score |
| `allowedHosts` | (see above) | Hostnames that are allowed for network calls |
| `blockedAuthors` | [] | Author names to block outright |
| `blockedPackages` | [] | npm package names to block (merged with built-in list) |
| `typosquatTargets` | [] | Skill names to check for typosquatting similarity |
| `typeAwareMaxFiles` | 200 | Skip the type-aware rules (one INFO finding) above this many code files |
| `typeAwareMaxBytes` | 2000000 | Skip the type-aware rules (one INFO finding) above this many bytes of code |

## Type-aware rules

After the per-file scan, skill-vettr loads every code file into one in-memory ts-morph project (no disk access, no lib files, nothing executed or emitted) and resolves names with the TypeScript checker, so aliases (`import { exec as run }`), namespace and default imports, `require()` destructuring and shadowed names are handled.

| Rule | Severity | Category | CWE |
|------|----------|----------|-----|
| Untrusted input reaches `child_process` (`exec`, `execSync`, `spawn`, `spawnSync`, `execFile`, `execFileSync`, `fork`) | CRITICAL | SHELL_INJECTION | CWE-78 |
| Untrusted input reaches an `fs` write path (`writeFile`, `appendFile`, `createWriteStream`, `rm`, `unlink` and their sync forms) | WARNING | PATH_TRAVERSAL | CWE-22 |
| Untrusted input reaches `fetch` or `http`/`https` `request`/`get` | WARNING | NETWORK_RISK | CWE-918 |
| Relative import that doesn't resolve to a file in the skill | WARNING | DEPENDENCY_RISK | CWE-829 |
| Bare import of a package missing from the nearest `package.json` (`dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies`; built-ins and `@openclaw/sdk` are exempt) | WARNING | DEPENDENCY_RISK | CWE-829 |

Untrusted input is the parameters of handlers passed to `*.commands.register(name, handler)` and `*.hooks.on(name, handler)`, and `process.argv`. Taint follows assignments, destructuring, property access, template literals, concatenation, `String()`, `JSON.stringify()`, `path.join()`/`path.resolve()`, common string methods, and arguments passed to functions declared in the skill. The evidence shows the flow, e.g. `args -> args.path -> cmd -> exec(...)`.

Limits: taint does not follow values through object fields, return values, class members or across module boundaries, so it under-reports rather than over-reports.

## Risk Levels

| Level | Score | Recommendation |
|-------|-------|----------------|
| SAFE | 0 | INSTALL |
| LOW | 1-19 | INSTALL |
| MEDIUM | 20-39 | REVIEW |
| HIGH | 40-69 | REVIEW or BLOCK |
| CRITICAL | 70+ | BLOCK |

## Testing

```bash
npm run build
npm test
```

Tests use Node's built-in test runner (`node:test`). The test suite covers each analyzer independently plus end-to-end integration tests against fixture skill directories.

## Security Notes

The `vet` and `vet-url` commands allow paths under the current working directory (`process.cwd()`) as a convenience, so you can vet skills directly in your workspace without copying them elsewhere. The trade-off is that any path under `cwd` is accepted for vetting, which may be a broader scope than intended if you run the tool from a high-privilege or sensitive directory. In high-security environments, consider running skill-vettr from a dedicated, isolated directory to limit the allowed root scope.

The `vet-url` command downloads and extracts remote archives into a temporary directory. This is necessary for its purpose but means external binaries (`tar`, `git`) touch the filesystem. Archives are downloaded in-process (max 50 MB, 120s timeout) only from hosts that resolve to public addresses, with each redirect re-validated, and decompressed in-process with a 200 MB cap before `tar` sees them. After extraction or cloning, the skill is refused if its files add up to more than 200 MB, which also catches tar sparse members that declare more than they store. `.git` clones resolve the host first, reject it unless every address is public, and pin git's connection to those addresses (`http.curloptResolve`, IPv4 preferred), so DNS rebinding cannot point the clone at an internal host; redirects are disabled and user/system git config (URL rewrites, proxies, credential helpers) is ignored. Address pinning needs git 2.37 or later (older git silently ignores `http.curloptResolve`), so `vet-url` refuses `.git` URLs when git is older or its version can't be read. The `vet-clawhub` command similarly invokes the `clawhub` CLI. Run these commands only against URLs and slugs you have reason to trust, and prefer running inside a disposable container or VM for untrusted sources.

If you enable the `autoVet` hook, review your configuration carefully — it will automatically invoke the vetting engine on every `skill:pre-install` event.

## Publishing

The root directory of this repository is the publishable artifact. There is no separate build or packaging step required — publish directly from the repo root.

## Licence

MIT

## Download History

[![Download History](https://skill-history.com/chart/britrik/skill-vettr.svg)](https://skill-history.com/britrik/skill-vettr)
