---
name: skill-vettr
version: "2.0.1"
author: britrik
description: Static analysis security scanner for third-party OpenClaw skills. Detects eval/spawn risks, malicious dependencies, typosquatting, and prompt injection patterns before installation. Use when vetting skills from ClawHub or untrusted sources.
tags: ["security", "scanner", "vetting", "analysis", "static-analysis"]
emoji: "🛡️"
metadata:
  openclaw:
    requires:
      bins: ["node", "git", "curl", "tar", "clawhub"]
      env: []
    notes: >
      Run `npm install` after cloning (see install safety notes below).
      Requires .wasm files from node_modules at runtime.
      git/curl/tar are used by vet-url to download and extract remote archives.
      clawhub CLI is used by vet-clawhub to fetch skills from the registry.
      Only the /skill:vet command (local path) needs no external binaries beyond node.
---

# skill-vettr v2.0.1

Security scanner for third-party OpenClaw skills. Analyses source code, dependencies, and metadata before installation using tree-sitter AST parsing and regex pattern matching.

## Installation

```bash
npm install
```

This installs all Node.js dependencies, including tree-sitter `.wasm` grammar files required at runtime for AST-based analysis. The `.wasm` files are located in `node_modules` and must be present for the skill to function.

> ⚠️ **Install safety:** `npm install` runs dependency lifecycle scripts, which can execute arbitrary code. For stronger isolation, run `npm ci --ignore-scripts` — but note that tree-sitter native/WASM artifacts may not build, breaking AST analysis. Prefer installing inside a container or VM when possible.

## External Binaries

The `vet-url` and `vet-clawhub` commands invoke external binaries via `execSafe` (which uses `execFile` — no shell is spawned). Only the following commands are permitted:

| Binary | Used By | Purpose |
|--------|---------|---------|
| `git` | `vet-url` | Clone `.git` URLs (with hooks disabled) |
| `curl` | `vet-url` | Download archive URLs |
| `tar` | `vet-url` | Extract downloaded archives |
| `clawhub` | `vet-clawhub` | Fetch skills from ClawHub registry |

The `/skill:vet` command (local path vetting) requires only `node` and no external binaries.

## Commands

- `/skill:vet --path <directory>` — Vet a local skill directory
- `/skill:vet-url --url <https://...>` — Download and vet from URL
- `/skill:vet-clawhub --skill <slug>` — Fetch and vet from ClawHub

## Detection Categories

| Category | Method | Examples |
|----------|--------|----------|
| Code execution | AST | eval(), new Function(), vm.runInThisContext() |
| Shell injection | AST | exec(), execSync(), spawn("bash"), child_process imports |
| Dynamic require | AST | require(variable), require(templateString) |
| Prototype pollution | AST | __proto__ assignment |
| Prompt injection | Regex | Instruction override patterns, control tokens (in string literals) |
| Homoglyph attacks | Regex | Cyrillic/Greek lookalike characters in identifiers |
| Encoded names | Regex | Unicode/hex-escaped "eval", "exec" |
| Credential paths | Regex | .ssh/, .aws/, keychain path references |
| Network calls | AST | fetch() with literal URLs (checked against allowlist) |
| Malicious deps | Config | Known bad packages, lifecycle scripts, git/http deps |
| Typosquatting | Levenshtein | Skill names within edit distance 2 of targets |
| Dangerous permissions | Config | shell:exec, credentials:read in SKILL.md |

## Limitations

> ⚠️ **This is a heuristic scanner with inherent limitations. It cannot guarantee safety.**

- **Static analysis only** — Cannot detect runtime behaviour (e.g., code that fetches malware after install)
- **Evasion possible** — Sophisticated obfuscation or multi-stage string construction can evade detection
- **JS/TS only** — Binary payloads, images, and non-text files are skipped
- **Limited network detection** — Only detects `fetch()` with literal URL strings; misses axios, http module, dynamic URLs
- **No sandboxing** — Does not execute or isolate target code
- **Comment scanning** — Prompt injection detection scans string literals, not comments
- **Broad filesystem scope** — `vet-url` downloads and extracts remote archives into a temp directory; `vet` accepts any path under `process.cwd()`. Run from an isolated directory to limit exposure
- **External binary trust** — `vet-url` and `vet-clawhub` invoke `git`, `curl`, `tar`, and `clawhub` via `execFile`. These binaries must be trusted and present on `PATH`

For high-security environments, combine with sandboxing, network isolation, and manual source review. Run inside a disposable container when vetting untrusted URLs.
