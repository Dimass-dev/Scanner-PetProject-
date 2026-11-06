// Shared API contract types. Keep these in sync with Server/DTOs.

export interface RiskScore {
  level: string;
  score: number;
  counts: Record<string, number>;
}

export interface Finding {
  ruleId: string;
  title: string;
  category: string;
  severity: string;
  description: string;
  evidence: string | null;
  recommendation: string | null;
  standardReference: string | null;
  confidence?: string;
}

export interface ScanResult {
  scanId: string;
  fileName: string;
  fileSize: number;
  status: string;
  risk: RiskScore | null;
  findings: Finding[];
  artifacts: Record<string, unknown>;
  errors: string[];
}

export interface FileResult {
  relativePath: string;
  fileSize: number;
  status: string;
  risk: RiskScore | null;
  findings: Finding[];
  artifacts: Record<string, unknown>;
  errors: string[];
}

export interface ArchiveScanResult {
  scanId: string;
  archiveName: string;
  extractedFileCount: number;
  scannedFileCount: number;
  overallRisk: RiskScore | null;
  files: FileResult[];
  extractionErrors: string[];
  errorMessage: string | null;
}

export interface WebScanResult {
  scanId: string;
  targetUrl: string;
  status: string;
  risk: RiskScore;
  findings: Finding[];
  artifacts: Record<string, Record<string, string>>;
  errors: string[];
}

export interface RateLimitResult {
  status: string;
  summary: string;
  httpStatusCodes?: number[];
  error?: string;
}
