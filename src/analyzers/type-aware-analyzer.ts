import path from 'node:path';
import { builtinModules } from 'node:module';
import { Node, Project, SyntaxKind, ts } from 'ts-morph';
import type { CallExpression, Expression, SourceFile } from 'ts-morph';
import { Finding, FindingCategory } from '../types.js';
import { generateFindingId, truncateEvidence } from '../utils/sanitise.js';

export interface CodeFile {
  path: string;
  content: string;
}

export interface RootManifest {
  name?: string;
  dependencies?: Record<string, string> | null;
  devDependencies?: Record<string, string> | null;
  peerDependencies?: Record<string, string> | null;
  optionalDependencies?: Record<string, string> | null;
}

export interface TypeAwareInput {
  rootDir: string;
  codeFiles: CodeFile[];
  /** Every file path collected for the scan, used to resolve relative imports. */
  allFiles: string[];
  /** Every package.json in the skill, keyed by its directory; each file is checked against the nearest one. */
  manifests: Record<string, RootManifest>;
  maxFiles: number;
  maxBytes: number;
}

const RESOLVE_EXTENSIONS = ['.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs', '.json', '.d.ts'];
const JS_TO_TS: Record<string, string[]> = {
  '.js': ['.ts', '.tsx', '.d.ts'],
  '.jsx': ['.tsx'],
  '.mjs': ['.mts', '.d.mts'],
  '.cjs': ['.cts', '.d.cts'],
};
const BUILTINS = new Set(builtinModules.map((m) => m.replace(/^node:/, '')));
/** Provided by the OpenClaw host at runtime, so skills do not declare it. */
const HOST_PROVIDED = new Set(['@openclaw/sdk']);

type SinkKind = 'exec' | 'fs' | 'net';
const SINKS: Record<string, Record<string, SinkKind>> = {
  child_process: Object.fromEntries(
    ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork'].map((n) => [n, 'exec' as const]),
  ),
  fs: Object.fromEntries(
    ['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'createWriteStream', 'rm', 'rmSync', 'unlink', 'unlinkSync']
      .map((n) => [n, 'fs' as const]),
  ),
  http: { request: 'net', get: 'net' },
  https: { request: 'net', get: 'net' },
};
const SINK_META: Record<SinkKind, { severity: Finding['severity']; category: FindingCategory; cwe: string; what: string }> = {
  exec: { severity: 'CRITICAL', category: 'SHELL_INJECTION', cwe: 'CWE-78', what: 'a child process' },
  fs: { severity: 'WARNING', category: 'PATH_TRAVERSAL', cwe: 'CWE-22', what: 'a filesystem write path' },
  net: { severity: 'WARNING', category: 'NETWORK_RISK', cwe: 'CWE-918', what: 'a network request' },
};
/** Calls whose result carries the taint of their arguments. */
const PASS_THROUGH_FUNCTIONS: Record<string, Set<string>> = {
  path: new Set(['join', 'resolve', 'normalize', 'format']),
};
const PASS_THROUGH_GLOBALS = new Set(['String', 'decodeURIComponent', 'decodeURI', 'encodeURI']);
/** Methods whose result carries the taint of their receiver or arguments. */
const PASS_THROUGH_METHODS = new Set([
  'toString', 'trim', 'trimStart', 'trimEnd', 'concat', 'replace', 'replaceAll', 'slice', 'substring', 'substr',
  'toLowerCase', 'toUpperCase', 'split', 'join', 'padStart', 'padEnd', 'at', 'map', 'filter', 'flat',
]);

const ASSIGNMENT_OPERATORS = new Set([
  SyntaxKind.EqualsToken, SyntaxKind.PlusEqualsToken, SyntaxKind.BarBarEqualsToken, SyntaxKind.QuestionQuestionEqualsToken,
]);
const MAX_PROPAGATION_ROUNDS = 25;
const MAX_EXPRESSION_DEPTH = 40;
const MAX_FLOW_EVIDENCE = 200;

/** Own-property lookup, so names like `hasOwnProperty` or `constructor` never match a table entry. */
function ownLookup<T>(table: Record<string, T> | undefined, key: string): T | undefined {
  return table && Object.hasOwn(table, key) ? table[key] : undefined;
}

function normaliseModule(spec: string): string {
  const bare = spec.replace(/^node:/, '');
  return bare === 'fs/promises' ? 'fs' : bare;
}

/** Package name for a bare specifier: "@scope/pkg/sub" -> "@scope/pkg", "pkg/sub" -> "pkg". */
export function packageNameOf(spec: string): string {
  const parts = spec.split('/');
  return spec.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0]!;
}

interface SinkRef {
  module: string;
  name: string;
}

/**
 * Type-aware rules built on one in-memory ts-morph Project per scan: unresolved imports, and
 * untrusted input (command/hook handler arguments, process.argv) reaching child_process, fs write
 * or network sinks. Scanned code is parsed and bound, never executed or emitted.
 */
export class TypeAwareAnalyzer {
  analyze(input: TypeAwareInput): Finding[] {
    const codeFiles = [...input.codeFiles].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
    const totalBytes = codeFiles.reduce((n, f) => n + Buffer.byteLength(f.content), 0);
    if (codeFiles.length > input.maxFiles || totalBytes > input.maxBytes) {
      return [{
        id: generateFindingId(),
        severity: 'INFO',
        category: 'CODE_OBFUSCATION',
        message: `Type-aware analysis skipped: ${codeFiles.length} code files / ${totalBytes} bytes exceed the limit of ` +
          `${input.maxFiles} files / ${input.maxBytes} bytes`,
        file: input.rootDir,
        evidence: `typeAwareMaxFiles=${input.maxFiles}, typeAwareMaxBytes=${input.maxBytes}`,
      }];
    }
    if (codeFiles.length === 0) return [];

    try {
      const project = new Project({
        useInMemoryFileSystem: true,
        skipLoadingLibFiles: true,
        skipFileDependencyResolution: true,
        compilerOptions: {
          allowJs: true,
          checkJs: false,
          noLib: true,
          noResolve: true,
          types: [],
          target: ts.ScriptTarget.ES2022,
          module: ts.ModuleKind.ESNext,
          moduleResolution: ts.ModuleResolutionKind.Bundler,
        },
      });
      const sourceFiles = codeFiles.map((f) => project.createSourceFile(f.path, f.content, { overwrite: true }));
      const findings = [
        ...this.checkImports(sourceFiles, input),
        ...new TaintPass(project, sourceFiles).run(),
      ];
      return findings.sort(compareFindings);
    } catch (err) {
      return [{
        id: generateFindingId(),
        severity: 'INFO',
        category: 'CODE_OBFUSCATION',
        message: `Type-aware analysis failed: ${truncateEvidence(err instanceof Error ? err.message : String(err), 150)}`,
        file: input.rootDir,
        evidence: 'ts-morph',
      }];
    }
  }

  private checkImports(sourceFiles: SourceFile[], input: TypeAwareInput): Finding[] {
    const findings: Finding[] = [];
    const existing = new Set(input.allFiles.map((f) => path.resolve(f)));
    const declaredFor = new Map<string, Set<string> | null>();
    const declaredNear = (file: string): Set<string> | null => {
      const dir = path.dirname(file);
      if (declaredFor.has(dir)) return declaredFor.get(dir)!;
      let found: Set<string> | null = null;
      for (let d = dir; ; d = path.dirname(d)) {
        const m = Object.hasOwn(input.manifests, d) ? input.manifests[d] : undefined;
        if (m) {
          found = new Set([
            ...Object.keys(m.dependencies ?? {}),
            ...Object.keys(m.devDependencies ?? {}),
            ...Object.keys(m.peerDependencies ?? {}),
            ...Object.keys(m.optionalDependencies ?? {}),
            ...(m.name ? [m.name] : []),
          ]);
          break;
        }
        if (d === path.dirname(d) || d === path.resolve(input.rootDir)) break;
      }
      declaredFor.set(dir, found);
      return found;
    };

    for (const sf of sourceFiles) {
      if (sf.isDeclarationFile()) continue;
      for (const { spec, line } of collectImports(sf)) {
        if (spec.startsWith('.') || spec.startsWith('/')) {
          if (!resolvesRelative(path.dirname(sf.getFilePath()), spec, existing)) {
            findings.push(importFinding(sf.getFilePath(), line, spec, 'Relative import does not resolve to a file in the skill'));
          }
          continue;
        }
        // `#name` imports map through package.json "imports", not dependencies.
        if (spec.startsWith('#')) continue;
        if (spec.startsWith('node:') || BUILTINS.has(spec) || BUILTINS.has(spec.split('/')[0]!)) continue;
        const declared = declaredNear(sf.getFilePath());
        if (declared === null) continue;
        const pkg = packageNameOf(spec);
        if (!declared.has(pkg) && !HOST_PROVIDED.has(pkg)) {
          findings.push(importFinding(sf.getFilePath(), line, spec, `Import of undeclared package: ${pkg}`));
        }
      }
    }
    return findings;
  }
}

function importFinding(file: string, line: number, spec: string, message: string): Finding {
  return {
    id: generateFindingId(),
    severity: 'WARNING',
    category: 'DEPENDENCY_RISK',
    message,
    file,
    line,
    evidence: truncateEvidence(spec, 100),
    cwe: 'CWE-829',
  };
}

function compareFindings(a: Finding, b: Finding): number {
  if (a.file !== b.file) return a.file < b.file ? -1 : 1;
  if ((a.line ?? 0) !== (b.line ?? 0)) return (a.line ?? 0) - (b.line ?? 0);
  if (a.message !== b.message) return a.message < b.message ? -1 : 1;
  return a.evidence < b.evidence ? -1 : a.evidence > b.evidence ? 1 : 0;
}

function collectImports(sf: SourceFile): Array<{ spec: string; line: number }> {
  const out: Array<{ spec: string; line: number }> = [];
  for (const decl of sf.getImportDeclarations()) {
    const named = decl.getNamedImports();
    const onlyInlineTypes = !decl.getDefaultImport() && !decl.getNamespaceImport() && named.length > 0 &&
      named.every((n) => n.isTypeOnly());
    if (decl.isTypeOnly() || onlyInlineTypes) continue;
    out.push({ spec: decl.getModuleSpecifierValue(), line: decl.getStartLineNumber() });
  }
  for (const decl of sf.getExportDeclarations()) {
    const spec = decl.getModuleSpecifierValue();
    const named = decl.getNamedExports();
    const onlyInlineTypes = named.length > 0 && named.every((n) => n.isTypeOnly());
    if (spec && !decl.isTypeOnly() && !onlyInlineTypes) out.push({ spec, line: decl.getStartLineNumber() });
  }
  for (const call of sf.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const callee = call.getExpression();
    const isRequire = Node.isIdentifier(callee) && callee.getText() === 'require' && (callee.getSymbol()?.getDeclarations().length ?? 0) === 0;
    const isDynamicImport = callee.getKind() === SyntaxKind.ImportKeyword;
    if (!isRequire && !isDynamicImport) continue;
    const arg = call.getArguments()[0];
    if (arg && Node.isStringLiteral(arg)) out.push({ spec: arg.getLiteralValue(), line: call.getStartLineNumber() });
  }
  return out;
}

function resolvesRelative(fromDir: string, spec: string, existing: Set<string>): boolean {
  const base = path.resolve(fromDir, spec);
  const candidates = [base];
  for (const ext of RESOLVE_EXTENSIONS) {
    candidates.push(base + ext, path.join(base, `index${ext}`));
  }
  const ext = path.extname(base);
  for (const alt of JS_TO_TS[ext] ?? []) candidates.push(base.slice(0, -ext.length) + alt);
  return candidates.some((c) => existing.has(c));
}

class TaintPass {
  private tainted = new Map<ts.Symbol, string>();
  /** Objects with a property assigned somewhere, so their fields can't be read from the initializer alone. */
  private mutated = new Set<ts.Symbol>();
  private checker: ts.TypeChecker;

  constructor(project: Project, private sourceFiles: SourceFile[]) {
    this.checker = project.getTypeChecker().compilerObject;
  }

  run(): Finding[] {
    const files = this.sourceFiles.filter((sf) => !sf.isDeclarationFile());
    for (const sf of files) this.seedHandlerParameters(sf);
    for (const sf of files) this.collectMutatedObjects(sf);

    // Propagate until nothing changes; the round cap stops cyclic assignments from looping.
    for (let round = 0; round < MAX_PROPAGATION_ROUNDS; round++) {
      let changed = false;
      for (const sf of files) changed = this.propagate(sf) || changed;
      if (!changed) break;
    }

    const findings: Finding[] = [];
    for (const sf of files) {
      for (const call of sf.getDescendantsOfKind(SyntaxKind.CallExpression)) {
        const finding = this.checkSink(sf, call);
        if (finding) findings.push(finding);
      }
    }
    return findings;
  }

  private symbolOf(node: Node): ts.Symbol | undefined {
    return this.checker.getSymbolAtLocation(node.compilerNode) ?? undefined;
  }

  /** True for a name the scanned code does not declare (a global such as fetch or require). */
  private isGlobal(id: Node): boolean {
    return (this.symbolOf(id)?.getDeclarations()?.length ?? 0) === 0;
  }

  private taint(node: Node, flow: string): boolean {
    const sym = this.symbolOf(node);
    if (!sym || this.tainted.has(sym)) return false;
    this.tainted.set(sym, flow);
    return true;
  }

  /** Taint every name bound by a parameter, variable name or destructuring pattern. */
  private taintBinding(name: Node, flow: string): boolean {
    if (Node.isIdentifier(name)) return this.taint(name, flow === name.getText() ? flow : `${flow} -> ${name.getText()}`);
    let changed = false;
    for (const id of name.getDescendantsOfKind(SyntaxKind.Identifier)) {
      const parent = id.getParent();
      // Skip property keys in `{ key: local }`; only the local binding is a variable.
      if (Node.isBindingElement(parent) && parent.getPropertyNameNode() === id) continue;
      if (Node.isBindingElement(parent) && parent.getNameNode() === id) {
        changed = this.taint(id, `${flow} -> ${id.getText()}`) || changed;
      }
    }
    return changed;
  }

  private collectMutatedObjects(sf: SourceFile): void {
    for (const bin of sf.getDescendantsOfKind(SyntaxKind.BinaryExpression)) {
      if (!ASSIGNMENT_OPERATORS.has(bin.getOperatorToken().getKind())) continue;
      let target: Node = bin.getLeft();
      if (!Node.isPropertyAccessExpression(target) && !Node.isElementAccessExpression(target)) continue;
      while (Node.isPropertyAccessExpression(target) || Node.isElementAccessExpression(target)) target = target.getExpression();
      const sym = Node.isIdentifier(target) ? this.symbolOf(target) : undefined;
      if (sym) this.mutated.add(sym);
    }
  }

  /**
   * Field-precise read of `obj.key` when `obj` is a never-mutated const object literal: the flow of
   * that one property, or undefined when it can't be determined from the literal.
   */
  private fieldFlow(expr: Node, depth: number): string | null | undefined {
    if (!Node.isPropertyAccessExpression(expr) && !Node.isElementAccessExpression(expr)) return undefined;
    const receiver = expr.getExpression();
    let key: string | undefined;
    if (Node.isPropertyAccessExpression(expr)) key = expr.getName();
    else {
      const arg = expr.getArgumentExpression();
      if (arg && (Node.isStringLiteral(arg) || Node.isNoSubstitutionTemplateLiteral(arg))) key = arg.getLiteralValue();
    }
    if (key === undefined || !Node.isIdentifier(receiver)) return undefined;
    const sym = this.symbolOf(receiver);
    if (!sym || this.mutated.has(sym)) return undefined;
    const decls = sym.getDeclarations() ?? [];
    if (decls.length !== 1) return undefined;
    const decl = this.wrap(receiver, decls[0]!);
    if (!Node.isVariableDeclaration(decl) || decl.getVariableStatement()?.getDeclarationKind() !== 'const') return undefined;
    const init = decl.getInitializer();
    if (!init || !Node.isObjectLiteralExpression(init)) return undefined;
    const props = init.getProperties();
    if (props.some((p) => Node.isSpreadAssignment(p))) return undefined;
    for (const prop of props) {
      if (Node.isPropertyAssignment(prop) && prop.getName() === key) return this.flowOf(prop.getInitializer()!, depth + 1);
      if (Node.isShorthandPropertyAssignment(prop) && prop.getName() === key) {
        const value = this.checker.getShorthandAssignmentValueSymbol(prop.compilerNode);
        return (value && this.tainted.get(value)) ?? null;
      }
    }
    return undefined;
  }

  private seedHandlerParameters(sf: SourceFile): void {
    for (const call of sf.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      const callee = call.getExpression();
      if (!Node.isPropertyAccessExpression(callee)) continue;
      const method = callee.getName();
      const owner = callee.getExpression();
      const ownerName = Node.isPropertyAccessExpression(owner) ? owner.getName() : undefined;
      const isRegistration = (ownerName === 'commands' && method === 'register') || (ownerName === 'hooks' && method === 'on');
      if (!isRegistration) continue;
      const handler = this.functionFor(call.getArguments()[1]);
      if (!handler) continue;
      for (const param of handler.getParameters()) {
        const name = param.getNameNode();
        this.taintBinding(name, Node.isIdentifier(name) ? name.getText() : 'handler argument');
      }
    }
  }

  /** The function a handler or callee expression refers to, when it is declared in the scanned code. */
  private functionFor(expr: Node | undefined): (Node & { getParameters(): Array<import('ts-morph').ParameterDeclaration> }) | undefined {
    if (!expr) return undefined;
    if (Node.isArrowFunction(expr) || Node.isFunctionExpression(expr)) return expr;
    if (!Node.isIdentifier(expr)) return undefined;
    for (const decl of this.symbolOf(expr)?.getDeclarations() ?? []) {
      const node = this.wrap(expr, decl);
      if (Node.isFunctionDeclaration(node)) return node;
      if (Node.isVariableDeclaration(node)) {
        const init = node.getInitializer();
        if (init && (Node.isArrowFunction(init) || Node.isFunctionExpression(init))) return init;
      }
    }
    return undefined;
  }

  private wrap(context: Node, decl: ts.Node): Node {
    return (context as unknown as { _getNodeFromCompilerNode(n: ts.Node): Node })._getNodeFromCompilerNode(decl);
  }

  private propagate(sf: SourceFile): boolean {
    let changed = false;
    sf.forEachDescendant((node) => {
      if (Node.isVariableDeclaration(node)) {
        const init = node.getInitializer();
        const flow = init && this.flowOf(init);
        if (flow) changed = this.taintBinding(node.getNameNode(), flow) || changed;
      } else if (Node.isBinaryExpression(node) && ASSIGNMENT_OPERATORS.has(node.getOperatorToken().getKind())) {
        const flow = this.flowOf(node.getRight());
        if (flow) {
          let target: Node = node.getLeft();
          while (Node.isPropertyAccessExpression(target) || Node.isElementAccessExpression(target)) target = target.getExpression();
          if (Node.isIdentifier(target)) changed = this.taint(target, `${flow} -> ${target.getText()}`) || changed;
        }
      } else if (Node.isForOfStatement(node)) {
        const flow = this.flowOf(node.getExpression());
        const init = node.getInitializer();
        if (flow && Node.isVariableDeclarationList(init)) {
          for (const decl of init.getDeclarations()) changed = this.taintBinding(decl.getNameNode(), flow) || changed;
        }
      } else if (Node.isCallExpression(node)) {
        // One level into functions declared in the scanned code: tainted argument -> parameter.
        const fn = this.functionFor(node.getExpression());
        if (!fn) return;
        const params = fn.getParameters();
        node.getArguments().forEach((arg, i) => {
          const param = params[i];
          const flow = param && this.flowOf(arg);
          if (flow) changed = this.taintBinding(param.getNameNode(), flow) || changed;
        });
      }
    });
    return changed;
  }

  /** The taint flow that reaches `expr`, or null when it carries no untrusted input. */
  private flowOf(expr: Node, depth = 0): string | null {
    if (depth > MAX_EXPRESSION_DEPTH) return null;
    const next = (n: Node | undefined) => (n ? this.flowOf(n, depth + 1) : null);

    if (Node.isIdentifier(expr)) {
      const sym = this.symbolOf(expr);
      return sym ? this.tainted.get(sym) ?? null : null;
    }
    if (Node.isPropertyAccessExpression(expr) || Node.isElementAccessExpression(expr)) {
      if (isProcessArgv(expr)) return 'process.argv';
      const field = this.fieldFlow(expr, depth);
      if (field !== undefined) return field ? `${field} -> ${shortText(expr)}` : null;
      const inner = next(expr.getExpression());
      return inner ? `${inner} -> ${shortText(expr)}` : null;
    }
    if (Node.isParenthesizedExpression(expr) || Node.isAwaitExpression(expr) || Node.isAsExpression(expr) ||
        Node.isNonNullExpression(expr) || Node.isTypeAssertion(expr) || Node.isSatisfiesExpression(expr) ||
        Node.isSpreadElement(expr)) {
      return next(expr.getExpression());
    }
    if (Node.isTemplateExpression(expr)) {
      for (const span of expr.getTemplateSpans()) {
        const f = next(span.getExpression());
        if (f) return f;
      }
      return null;
    }
    if (Node.isBinaryExpression(expr)) {
      const op = expr.getOperatorToken().getKind();
      if (op === SyntaxKind.PlusToken || op === SyntaxKind.BarBarToken || op === SyntaxKind.QuestionQuestionToken ||
          op === SyntaxKind.CommaToken) {
        return next(expr.getLeft()) ?? next(expr.getRight());
      }
      return null;
    }
    if (Node.isConditionalExpression(expr)) return next(expr.getWhenTrue()) ?? next(expr.getWhenFalse());
    if (Node.isArrayLiteralExpression(expr)) {
      for (const el of expr.getElements()) {
        const f = next(el);
        if (f) return f;
      }
      return null;
    }
    if (Node.isObjectLiteralExpression(expr)) {
      for (const prop of expr.getProperties()) {
        if (Node.isPropertyAssignment(prop)) {
          const f = next(prop.getInitializer());
          if (f) return f;
        } else if (Node.isShorthandPropertyAssignment(prop)) {
          const sym = this.checker.getShorthandAssignmentValueSymbol(prop.compilerNode);
          const f = sym ? this.tainted.get(sym) : undefined;
          if (f) return f;
        } else if (Node.isSpreadAssignment(prop)) {
          const f = next(prop.getExpression());
          if (f) return f;
        }
      }
      return null;
    }
    if (Node.isCallExpression(expr)) return this.callFlow(expr, depth);
    return null;
  }

  private callFlow(call: CallExpression, depth: number): string | null {
    const callee = call.getExpression();
    const argFlow = () => {
      for (const arg of call.getArguments()) {
        const f = this.flowOf(arg, depth + 1);
        if (f) return f;
      }
      return null;
    };
    if (Node.isIdentifier(callee) && this.isGlobal(callee) && PASS_THROUGH_GLOBALS.has(callee.getText())) {
      const f = argFlow();
      return f ? `${f} -> ${callee.getText()}()` : null;
    }
    const ref = this.resolveImported(callee);
    if (ref && ownLookup(PASS_THROUGH_FUNCTIONS, ref.module)?.has(ref.name)) {
      const f = argFlow();
      return f ? `${f} -> ${ref.module}.${ref.name}()` : null;
    }
    if (Node.isPropertyAccessExpression(callee)) {
      const receiver = callee.getExpression();
      if (Node.isIdentifier(receiver) && receiver.getText() === 'JSON' && this.isGlobal(receiver) && callee.getName() === 'stringify') {
        const f = argFlow();
        return f ? `${f} -> JSON.stringify()` : null;
      }
      if (PASS_THROUGH_METHODS.has(callee.getName())) {
        const f = this.flowOf(receiver, depth + 1) ?? argFlow();
        return f ? `${f} -> .${callee.getName()}()` : null;
      }
    }
    return null;
  }

  /**
   * Resolve a callee to the module export it refers to, following import aliases, namespace and
   * default imports, `require()` results and destructuring by symbol, so shadowed names don't match.
   */
  private resolveImported(callee: Node): SinkRef | null {
    if (Node.isIdentifier(callee)) {
      const sym = this.symbolOf(callee);
      for (const decl of sym?.getDeclarations() ?? []) {
        const node = this.wrap(callee, decl);
        if (Node.isImportSpecifier(node)) {
          return { module: normaliseModule(node.getImportDeclaration().getModuleSpecifierValue()), name: node.getName() };
        }
        if (Node.isBindingElement(node)) {
          const pattern = node.getParent();
          const decl2 = pattern?.getParent();
          if (Node.isVariableDeclaration(decl2)) {
            const mod = this.moduleObjectOf(decl2.getInitializer());
            const key = node.getPropertyNameNode()?.getText() ?? node.getName();
            if (mod) return { module: mod, name: key };
          }
        }
        if (Node.isVariableDeclaration(node)) {
          const init = node.getInitializer();
          if (init && Node.isPropertyAccessExpression(init)) {
            const mod = this.moduleObjectOf(init.getExpression());
            if (mod) return { module: mod, name: init.getName() };
          }
        }
      }
      return null;
    }
    if (Node.isPropertyAccessExpression(callee)) {
      const mod = this.moduleObjectOf(callee.getExpression());
      return mod ? { module: mod, name: callee.getName() } : null;
    }
    return null;
  }

  /** The module an expression evaluates to the namespace of (`cp`, `require('fs')`, `fs.promises`). */
  private moduleObjectOf(expr: Node | undefined, depth = 0): string | null {
    if (!expr || depth > 5) return null;
    if (Node.isParenthesizedExpression(expr) || Node.isAwaitExpression(expr)) return this.moduleObjectOf(expr.getExpression(), depth + 1);
    if (Node.isCallExpression(expr)) {
      const callee = expr.getExpression();
      const isLoader = (Node.isIdentifier(callee) && callee.getText() === 'require' && this.isGlobal(callee)) ||
        callee.getKind() === SyntaxKind.ImportKeyword;
      const arg = expr.getArguments()[0];
      return isLoader && arg && Node.isStringLiteral(arg) ? normaliseModule(arg.getLiteralValue()) : null;
    }
    if (Node.isPropertyAccessExpression(expr)) {
      const mod = this.moduleObjectOf(expr.getExpression(), depth + 1);
      return mod === 'fs' && expr.getName() === 'promises' ? 'fs' : null;
    }
    if (Node.isIdentifier(expr)) {
      for (const decl of this.symbolOf(expr)?.getDeclarations() ?? []) {
        const node = this.wrap(expr, decl);
        if (Node.isNamespaceImport(node)) {
          return normaliseModule(node.getParentOrThrow().getParentOrThrow().asKindOrThrow(SyntaxKind.ImportDeclaration).getModuleSpecifierValue());
        }
        if (Node.isImportClause(node)) {
          return normaliseModule(node.getParentOrThrow().asKindOrThrow(SyntaxKind.ImportDeclaration).getModuleSpecifierValue());
        }
        if (Node.isImportSpecifier(node) && node.getName() === 'promises') {
          const mod = normaliseModule(node.getImportDeclaration().getModuleSpecifierValue());
          return mod === 'fs' ? 'fs' : null;
        }
        if (Node.isVariableDeclaration(node) && Node.isIdentifier(node.getNameNode())) {
          return this.moduleObjectOf(node.getInitializer(), depth + 1);
        }
      }
    }
    return null;
  }

  private checkSink(sf: SourceFile, call: CallExpression): Finding | null {
    const callee = call.getExpression();
    let kind: SinkKind | undefined;
    let label: string;
    if (Node.isIdentifier(callee) && callee.getText() === 'fetch' && this.isGlobal(callee)) {
      kind = 'net';
      label = 'fetch';
    } else {
      const ref = this.resolveImported(callee);
      kind = ref ? ownLookup(ownLookup(SINKS, ref.module), ref.name) : undefined;
      label = ref ? `${ref.module}.${ref.name}` : '';
    }
    if (!kind) return null;

    const args = call.getArguments();
    const checked = kind === 'exec' ? args : args.slice(0, 1);
    for (const arg of checked) {
      const flow = this.flowOf(arg);
      if (!flow) continue;
      const meta = SINK_META[kind];
      return {
        id: generateFindingId(),
        severity: meta.severity,
        category: meta.category,
        message: `Untrusted input reaches ${meta.what}: ${label}()`,
        file: sf.getFilePath(),
        line: call.getStartLineNumber(),
        evidence: truncateEvidence(`${flow} -> ${callee.getText()}(...)`, MAX_FLOW_EVIDENCE),
        cwe: meta.cwe,
      };
    }
    return null;
  }
}

function isProcessArgv(expr: Node): boolean {
  if (!Node.isPropertyAccessExpression(expr) || expr.getName() !== 'argv') return false;
  const obj = expr.getExpression();
  return Node.isIdentifier(obj) && obj.getText() === 'process' && (obj.getSymbol()?.getDeclarations().length ?? 0) === 0;
}

function shortText(node: Expression | Node): string {
  return truncateEvidence(node.getText().replace(/\s+/g, ' '), 60);
}
