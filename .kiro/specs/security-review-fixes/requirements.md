# Requirements Document

## Introduction

This document specifies the requirements for fixing security review findings flagged by ClawHub for the `skill-vettr` OpenClaw skill. The findings span six areas: missing install specification, unsafe remote content handling, prompt injection examples triggering pre-scan detectors, version mismatch, overly permissive allowed roots, and a duplicate publish directory. All fixes must preserve the skill's existing detection capabilities and test coverage.

## Glossary

- **SKILL_Manifest**: The `skill.md` file containing YAML frontmatter metadata and markdown instructions for an OpenClaw skill.
- **Vettr_Engine**: The core vetting engine (`VettrEngine` class) that orchestrates all analyzers to produce a `VettingReport`.
- **Vet_URL_Handler**: The `/skill:vet-url` command handler in `src/index.ts` that downloads and analyzes remote skill packages.
- **Sanitise_Module**: The `src/utils/sanitise.ts` module providing path, URL, and slug sanitization plus the `getAllowedRoots()` function.
- **Exec_Safe_Module**: The `src/utils/exec-safe.ts` module providing a safe command execution wrapper with allowlisted commands.
- **Pattern_Analyzer**: The `src/analyzers/pattern-analyzer.ts` regex-based analyzer that detects prompt injection, homoglyphs, and encoded function names.
- **Test_Fixtures**: The `test/fixtures/` directory containing sample skill directories used by integration and unit tests.
- **Publish_Directory**: The `publish-skill-vettr/` directory that appears to be a duplicate of the main source.
- **Pre_Scan_Detector**: ClawHub's automated scanner that flags prompt injection strings in submitted skill content.
- **Lifecycle_Script**: npm package.json scripts (`postinstall`, `preinstall`, `install`, `prepare`) that execute automatically during `npm install`.

## Requirements

### Requirement 1: Install Specification in SKILL.md

**User Story:** As an OpenClaw platform operator, I want the skill manifest to declare its runtime requirements, so that OpenClaw can verify prerequisites before loading the skill.

#### Acceptance Criteria

1. THE SKILL_Manifest SHALL include a `metadata.openclaw.requires.bins` field declaring `["node"]` as a required binary.
2. THE SKILL_Manifest SHALL include a `metadata.openclaw.requires.env` field declaring any required environment variables, or an empty array if none are required.
3. THE SKILL_Manifest SHALL document the installation process for Node.js dependencies (e.g., `npm install`) in the markdown body.
4. THE SKILL_Manifest SHALL declare that `.wasm` grammar files from `node_modules` are required at runtime.

### Requirement 2: Safe Remote Content Handling for Vet-URL

**User Story:** As a security-conscious user, I want the vet-url command to safely handle untrusted remote content, so that downloading and analyzing a malicious package cannot compromise my system.

#### Acceptance Criteria

1. WHEN the Vet_URL_Handler downloads content via `curl`, THE Vet_URL_Handler SHALL enforce a maximum download size limit of 50 MB using the `--max-filesize` flag.
2. WHEN the Vet_URL_Handler clones a git repository, THE Exec_Safe_Module SHALL disable git hooks by passing the `-c core.hooksPath=/dev/null` configuration to the `git clone` command.
3. WHEN the Vet_URL_Handler extracts a tar archive, THE Vet_URL_Handler SHALL create the temp directory before extraction and verify the directory exists.
4. WHEN the Vet_URL_Handler downloads content, THE Vet_URL_Handler SHALL validate that the extracted directory contains a `SKILL.md` file before proceeding with analysis.
5. IF the downloaded content does not contain a `SKILL.md` file, THEN THE Vet_URL_Handler SHALL delete the temp directory and return a descriptive error message.
6. WHEN the Vet_URL_Handler invokes `curl`, THE Vet_URL_Handler SHALL pass the `--max-time 120` flag to enforce a total transfer timeout.
7. WHEN the Vet_URL_Handler extracts a tar archive, THE Vet_URL_Handler SHALL pass `--no-same-owner --no-same-permissions` flags to prevent privilege escalation via archived file metadata.

### Requirement 3: Prompt Injection Example Obfuscation

**User Story:** As a skill publisher, I want prompt injection examples in test fixtures and documentation to not trigger ClawHub's pre-scan detector, so that the skill passes automated security review while retaining valid test coverage.

#### Acceptance Criteria

1. WHEN Test_Fixtures contain prompt injection example strings, THE Test_Fixtures SHALL encode those strings using runtime string concatenation or Base64 encoding so that the literal phrases do not appear in the source.
2. THE Pattern_Analyzer SHALL continue to detect prompt injection patterns in scanned target code after the obfuscation changes.
3. WHEN the SKILL_Manifest references prompt injection as a detection category, THE SKILL_Manifest SHALL use abbreviated or generic descriptions that do not contain literal prompt injection phrases.
4. THE Test_Fixtures SHALL produce the same detection results (same finding categories and severities) as before the obfuscation changes when analyzed by the Vettr_Engine.

### Requirement 4: Version Consistency

**User Story:** As a user reading the documentation, I want all version references to be consistent, so that I can trust the documentation is accurate.

#### Acceptance Criteria

1. THE readme.md SHALL display the same version string as the `package.json` `version` field (currently `2.0.1`).

### Requirement 5: Allowed Roots Improvement

**User Story:** As a developer vetting skills in my current workspace, I want the allowed roots to include the current working directory, so that I can vet skills without copying them to a hardcoded location.

#### Acceptance Criteria

1. THE Sanitise_Module `getAllowedRoots()` function SHALL include `process.cwd()` as an allowed root directory.
2. THE Sanitise_Module SHALL retain `os.tmpdir()`, `~/.openclaw`, and `~/Downloads` as allowed roots.
3. WHEN `process.cwd()` is added as an allowed root, THE SKILL_Manifest or readme.md SHALL document the security implications of allowing the current working directory.

### Requirement 6: Publish Directory Cleanup

**User Story:** As a maintainer, I want the repository to not contain a duplicate source directory, so that there is a single source of truth and no risk of publishing stale code.

#### Acceptance Criteria

1. THE repository SHALL remove the `publish-skill-vettr/` directory.
2. WHEN the `publish-skill-vettr/` directory is removed, THE readme.md SHALL document the publish/release process if one exists, or note that the root directory is the publishable artifact.
