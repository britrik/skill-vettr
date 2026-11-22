import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { TypeAwareAnalyzer, TypeAwareInput, packageNameOf } from '../analyzers/type-aware-analyzer.js';

const ROOT = '/skill';
const analyzer = new TypeAwareAnalyzer();

function run(files: Record<string, string>, opts: Partial<TypeAwareInput> = {}) {
  const codeFiles = Object.entries(files).map(([name, content]) => ({ path: `${ROOT}/${name}`, content }));
  return analyzer.analyze({
    rootDir: ROOT,
    codeFiles,
    allFiles: codeFiles.map((f) => f.path),
    manifest: { name: 'skill', dependencies: {} },
    maxFiles: 50,
    maxBytes: 1_000_000,
    ...opts,
  });
}

const handler = (body: string, imports = '') => `${imports}
export default function setup(ctx) {
  ctx.commands.register('/run', async (args) => {
${body}
  });
}
`;

describe('TypeAwareAnalyzer taint rules', () => {
  it('flags handler input reaching an aliased exec through a template literal', () => {
    const findings = run({
      'index.ts': handler("    const cmd = `ls ${args.path}`;\n    run(cmd);", "import { exec as run } from 'node:child_process';"),
    });
    const f = findings.find((x) => x.category === 'SHELL_INJECTION');
    assert.equal(f?.severity, 'CRITICAL');
    assert.equal(f?.cwe, 'CWE-78');
    assert.equal(f?.evidence, 'args -> args.path -> cmd -> run(...)');
    assert.equal(f?.line, 5);
  });

  it('resolves namespace imports and require destructuring', () => {
    const ns = run({ 'a.ts': handler('    cp.execSync(args.cmd);', "import * as cp from 'child_process';") });
    assert.ok(ns.some((f) => f.message.includes('child_process.execSync')));
    const req = run({ 'b.js': handler('    spawn("sh", ["-c", args.cmd]);', "const { spawn } = require('child_process');") });
    assert.ok(req.some((f) => f.message.includes('child_process.spawn')));
    const def = run({ 'c.ts': handler('    cp.exec(args.cmd);', "import cp from 'child_process';") });
    assert.ok(def.some((f) => f.message.includes('child_process.exec')));
  });

  it('flags tainted filesystem paths through path.join', () => {
    const findings = run({
      'index.ts': handler(
        "    const target = path.join('/tmp', args.name);\n    await fs.writeFile(target, 'x');",
        "import path from 'node:path';\nimport fs from 'node:fs/promises';",
      ),
    });
    const f = findings.find((x) => x.category === 'PATH_TRAVERSAL');
    assert.equal(f?.severity, 'WARNING');
    assert.equal(f?.cwe, 'CWE-22');
    assert.match(f?.evidence ?? '', /path\.join\(\) -> target/);
  });

  it('flags tainted fetch URLs and process.argv', () => {
    const fetchFindings = run({ 'index.ts': handler('    await fetch(`https://x.example/${args.q}`);') });
    assert.equal(fetchFindings.find((x) => x.category === 'NETWORK_RISK')?.cwe, 'CWE-918');
    const argv = run({ 'cli.ts': "import { exec } from 'child_process';\nconst [, , cmd] = process.argv;\nexec(cmd);\n" });
    assert.match(argv.find((x) => x.category === 'SHELL_INJECTION')?.evidence ?? '', /^process\.argv -> cmd/);
  });

  it('follows tainted arguments into local functions', () => {
    const findings = run({
      'index.ts': handler('    runIt(args.cmd);', "import { exec } from 'child_process';\nfunction runIt(c) { exec(c); }"),
    });
    assert.ok(findings.some((f) => f.category === 'SHELL_INJECTION'));
  });

  it('does not flag literal or untainted arguments', () => {
    const findings = run({
      'index.ts': handler("    exec('ls -la');\n    const safe = 'x';\n    exec(safe);\n    await fetch('https://api.example.com');", "import { exec } from 'child_process';"),
    });
    assert.deepEqual(findings, []);
  });

  it('respects shadowing of imported sinks and tainted names', () => {
    const findings = run({
      'index.ts': handler(
        "    const exec = (s) => s;\n    exec(args.cmd);\n    { const args = { cmd: 'ls' }; realExec(args.cmd); }",
        "import { exec as realExec } from 'child_process';",
      ),
    });
    assert.deepEqual(findings, []);
  });

  it('terminates on cyclic assignments', () => {
    const findings = run({
      'index.ts': handler("    let a = args.x; let b = a; a = b; b = a;\n    exec(b);", "import { exec } from 'child_process';"),
    });
    assert.equal(findings.filter((f) => f.category === 'SHELL_INJECTION').length, 1);
  });
});

describe('TypeAwareAnalyzer import rules', () => {
  it('flags undeclared bare packages and accepts declared ones, built-ins and the host SDK', () => {
    const findings = run(
      {
        'index.ts': [
          "import axios from 'axios';",
          "import { x } from '@scope/pkg/sub/path';",
          "import fs from 'fs';",
          "import { join } from 'node:path';",
          "import { readFile } from 'fs/promises';",
          "import sdk from '@openclaw/sdk';",
          "import yaml from 'yaml';",
          "import type { T } from 'types-only';",
          "const lodash = require('lodash/fp');",
        ].join('\n'),
      },
      { manifest: { name: 'skill', dependencies: { yaml: '1' }, peerDependencies: { lodash: '4' } } },
    );
    assert.deepEqual(findings.map((f) => f.message), [
      'Import of undeclared package: axios',
      'Import of undeclared package: @scope/pkg',
    ]);
    assert.ok(findings.every((f) => f.severity === 'WARNING' && f.cwe === 'CWE-829' && f.category === 'DEPENDENCY_RISK'));
    assert.deepEqual(findings.map((f) => f.line), [1, 2]);
  });

  it('resolves relative imports with extensions, index files and .js to .ts mapping', () => {
    const findings = run({
      'index.ts': [
        "import a from './lib/a.js';",
        "import b from './lib';",
        "import c from './lib/c';",
        "import d from './missing.js';",
        "export * from './also-missing';",
      ].join('\n'),
      'lib/a.ts': 'export default 1;',
      'lib/index.ts': 'export default 2;',
      'lib/c.mjs': 'export default 3;',
    });
    assert.deepEqual(findings.map((f) => f.evidence), ['./missing.js', './also-missing']);
  });

  it('skips the undeclared-package check without a root package.json', () => {
    assert.deepEqual(run({ 'index.ts': "import axios from 'axios';" }, { manifest: null }), []);
  });

  it('computes package names for scoped and subpath specifiers', () => {
    assert.equal(packageNameOf('@a/b/c'), '@a/b');
    assert.equal(packageNameOf('a/b'), 'a');
  });
});

describe('TypeAwareAnalyzer limits and determinism', () => {
  it('emits one INFO finding when over the file or byte cap', () => {
    const files = { 'a.ts': 'export {}', 'b.ts': 'export {}' };
    const byFiles = run(files, { maxFiles: 1 });
    assert.equal(byFiles.length, 1);
    assert.equal(byFiles[0]?.severity, 'INFO');
    assert.match(byFiles[0]?.message ?? '', /skipped/);
    assert.equal(run(files, { maxBytes: 5 }).length, 1);
  });

  it('returns identical findings for identical input', () => {
    const files = {
      'z.ts': handler('    exec(args.a);', "import { exec } from 'child_process';\nimport q from 'nope';"),
      'a.ts': handler('    await fetch(args.url);'),
    };
    const strip = (fs: ReturnType<typeof run>) => fs.map(({ id: _id, ...rest }) => rest);
    const first = strip(run(files));
    assert.deepEqual(strip(run(files)), first);
    assert.deepEqual(first.map((f) => f.file), ['/skill/a.ts', '/skill/z.ts', '/skill/z.ts']);
  });
});
