export interface SkillManifest {
  name: string;
  version: string;
  author?: string;
  description?: string;
  tools?: string[];
  permissions?: string[];
  dependencies?: Record<string, string>;
}

export interface VettingReport {
  skillName: string;
  riskScore: number;
  riskLevel: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  findings: Finding[];
  metadata: SkillMetadata;
  recommendation: 'INSTALL' | 'REVIEW' | 'BLOCK';
  vettedAt: string;
  vettrVersion: string;
}

export interface SkillMetadata {
  authorVerified: boolean;
  hasExternalDeps: boolean;
  networkCalls: NetworkCall[];
  fileCount: number;
  totalLines: number;
  checksumSha256?: string;
  /** Which OpenSSF malicious-packages dataset the scan used, so results can be reproduced. */
  maliciousPackagesDb?: MaliciousPackagesDbInfo;
}

export interface MaliciousPackagesDbInfo {
  status: 'loaded' | 'not-synced' | 'invalid' | 'disabled';
  commit?: string;
  syncedAt?: string;
  advisoryCount?: number;
  /** True when the dataset is older than `maliciousPackagesMaxAgeHours`. */
  stale?: boolean;
  error?: string;
}

export interface NetworkCall {
  url: string;
  file: string;
  line?: number;
  allowed: boolean;
}

export interface Finding {
  id: string;
  severity: 'INFO' | 'WARNING' | 'CRITICAL';
  category: FindingCategory;
  message: string;
  file: string;
  line?: number;
  evidence: string;
  cwe?: string;
}

export type FindingCategory =
  | 'PROMPT_INJECTION'
  | 'CODE_OBFUSCATION'
  | 'NETWORK_RISK'
  | 'PERMISSION_RISK'
  | 'DEPENDENCY_RISK'
  | 'TYPO_SQUATTING'
  | 'PATH_TRAVERSAL'
  | 'SHELL_INJECTION';

export interface VettingConfig {
  maxNetworkCalls: number;
  allowedHosts: string[];
  blockObfuscation: boolean;
  requireAuthor: boolean;
  maxRiskScore: number;
  checkTyposquatting: boolean;
  maliciousPatternsUrl?: string;
  maliciousPatternsRefreshHours: number;
  blockedAuthors?: string[];
  blockedPackages?: string[];
  typosquatTargets?: string[];
  allowCwd?: boolean;
  /**
   * Local index of the OpenSSF malicious-packages dataset (npm advisories), written by
   * /skill:vet-sync. Unset disables the check.
   */
  maliciousPackagesDbPath?: string;
  /** Sync the dataset before vetting when it is missing or older than maliciousPackagesRefreshHours. */
  maliciousPackagesAutoSync?: boolean;
  /** Index age that triggers an automatic sync. Falls back to maliciousPatternsRefreshHours. */
  maliciousPackagesRefreshHours?: number;
  /** Reports mark the dataset stale after this many hours. Defaults to 168. */
  maliciousPackagesMaxAgeHours?: number;
  /** Honour a .vettrignore shipped inside the scanned skill. Off by default: the scanned skill controls that file. */
  trustVettrignore?: boolean;
}

export interface AllowedRootsConfig {
  allowCwd?: boolean;
  additionalRoots?: string[];
}

export interface ToolsInterface {
  readFile(path: string): Promise<string>;
  writeFile(path: string, content: string): Promise<void>;
  stat(path: string): Promise<{ isDirectory(): boolean; isFile(): boolean; isSymbolicLink(): boolean }>;
  lstat(path: string): Promise<{ isDirectory(): boolean; isFile(): boolean; isSymbolicLink(): boolean }>;
  realpath(path: string): Promise<string>;
  readdir(path: string): Promise<string[]>;
  mkdtemp(prefix: string): Promise<string>;
  rm(path: string, opts?: { recursive?: boolean; force?: boolean }): Promise<void>;
  exists(path: string): Promise<boolean>;
}
