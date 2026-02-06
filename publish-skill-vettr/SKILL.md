---
name: skill-vettr
description: Static analysis security scanner for third-party OpenClaw skills. Detects eval/spawn risks, malicious dependencies, typosquatting, and prompt injection patterns before installation. Use when vetting skills from ClawHub or untrusted sources.
version: "2.0.0"
author: britrik
tags: ["security", "scanner", "vetting", "analysis", "static-analysis"]
emoji: "🛡️"
---

# Skill Vettr

AST-based security scanner for OpenClaw skills. Analyses source code, dependencies, and metadata before installation using tree-sitter parsing and pattern matching.

Following recent supply-chain attacks on ClawHub (including ClawHavoc), vetting third-party skills before installation is critical. This tool provides automated first-pass detection of common threat patterns.

## What It Does

- **Code execution detection** — AST queries for `eval()`, `new Function()`, `vm.runInThisContext()`
- **Shell injection detection** — `exec()`, `execSync()`, `spawn("bash")`, child_process patterns
- **Dynamic imports** — `require(variable)`, `import()` with non-literal arguments
- **Prototype pollution** — `__proto__` and `constructor.prototype` assignments
- **Prompt injection** — Regex for instruction overrides, control tokens, jailbreak patterns
- **Homoglyph attacks** — Cyrillic/Greek lookalike characters in function names
- **Encoded identifiers** — Unicode/hex-escaped "eval", "exec", etc.
- **Credential access** — Path references to `.ssh/`, `.aws/`, `.env` files
- **Malicious dependencies** — Known bad packages (event-stream, etc.), suspicious prefixes
- **Lifecycle script abuse** — `preinstall`, `postinstall` scripts running arbitrary code
- **Typosquatting** — Levenshtein distance checks against popular skill names
- **Blocked authors/packages** — User-configurable blocklists

## Limitations

> **⚠️ Important:** This is a heuristic scanner with inherent limitations. It cannot guarantee safety.

- **Static analysis only** — Cannot detect runtime behaviour (e.g., code that downloads malware from an innocuous URL after installation)
- **Evasion possible** — Sophisticated attackers can evade AST queries via multi-stage string construction or obfuscation
- **JS/TS only** — Binary payloads, images, and non-text files are skipped
- **No sandboxing** — Does not execute or isolate target code
- **Non-exhaustive lists** — Malicious package/author blocklists are small and community-maintained

## Installation & Usage

### Manual Vetting

Vet a local skill directory:

```
/skill:vet --path ~/Downloads/suspicious-skill
```

Vet from URL:

```
/skill:vet-url --url https://github.com/org/skill/archive/main.tar.gz
```

Vet from ClawHub:

```
/skill:vet-clawhub --skill some-skill-name
```

### Auto-Vet Integration

Add to `~/.openclaw/config.json`:

```json
{
  "skill-vettr": {
    "autoVet": true,
    "maxRiskScore": 50,
    "requireAuthor": true,
    "blockedAuthors": [],
    "blockedPackages": [],
    "typosquatTargets": ["my-important-skill"]
  }
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `autoVet` | false | Automatically vet on `skill:pre-install` hook |
| `maxRiskScore` | 50 | Block installation at or above this score |
| `requireAuthor` | true | Warn if SKILL.md lacks author field |
| `blockedAuthors` | [] | Author names to block outright |
| `blockedPackages` | [] | npm packages to block (merged with built-in list) |
| `typosquatTargets` | [] | Skill names to check for typosquatting |

### Risk Levels

| Level | Score | Action |
|-------|-------|--------|
| SAFE | 0 | Install |
| LOW | 1-19 | Install |
| MEDIUM | 20-39 | Review recommended |
| HIGH | 40-69 | Manual review required |
| CRITICAL | 70+ | Block |

## Security Notes

> **⚠️ This is a heuristic scanner only. Always combine with ClawHub/VirusTotal scans and manual source review before installing any skill. No automated tool is 100% reliable — recent supply-chain attacks highlight the risks.**

- Run this tool as a first pass, not a final verdict
- For high-security environments, combine with sandboxing
- Review source code directly for anything scoring MEDIUM or above
- Keep blocklists updated with community threat intelligence

## Source

Full source code and transparency: [github.com/britrik/skill-vettr](https://github.com/britrik/skill-vettr)

MIT License.
