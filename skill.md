---
name: skill-vettr
version: 2.0.0
author: openclaw-community
description: Static analysis security scanner for third-party OpenClaw skills
tools: [filesystem, shell]
permissions: [filesystem:read, shell:exec]
---

# skill-vettr v2.0.0

Security scanner for third-party OpenClaw skills. Analyses source code, dependencies, and metadata before installation using AST parsing and pattern matching.

## Commands

- `/skill:vet --path <directory>` — Vet a local skill directory
- `/skill:vet-url --url <https://...>` — Download and vet from URL
- `/skill:vet-clawhub --skill <slug>` — Fetch and vet from ClawHub

## Detection Categories

| Category | Method | Examples |
|----------|--------|----------|
| Code execution | AST | eval(), new Function(), vm.runInThisContext() |
| Shell injection | AST | exec(), execSync(), spawn("bash") |
| Dynamic imports | AST | require(variable), import() with non-literal |
| Prototype pollution | AST | __proto__ assignment |
| Prompt injection | Regex | Instruction overrides, control tokens |
| Homoglyph attacks | Regex | Cyrillic lookalike function names |
| Encoded names | Regex | Unicode/hex-escaped "eval" |
| Credential access | Regex | .ssh/, .aws/ path references |
| Malicious deps | Config | event-stream, user-blocked packages |
| Typosquatting | Levenshtein | Names within edit distance 2 of targets |
| Dangerous permissions | Config | shell:exec, credentials:read |

## Limitations

This is a static analysis heuristic scanner. It catches common attack patterns but cannot guarantee safety against sophisticated or novel threats. It does not execute or sandbox target code.
