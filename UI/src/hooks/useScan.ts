import { useState, useCallback } from 'react';

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

export interface FileResult {
  relativePath: string;
  status: string;
  risk: RiskScore | null;
  findings: Finding[];
  artifacts: Record<string, unknown>;
  errors: string[];
}

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

export function useScan() {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | ArchiveScanResult | null>(null);
  const [abortController, setAbortController] = useState<AbortController | null>(null);

  const scanFile = useCallback(async (file: File) => {
    setIsLoading(true);
    setError(null);
    setResult(null);

    const controller = new AbortController();
    setAbortController(controller);

    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await fetch('/api/scan/file', {
        method: 'POST',
        body: formData,
        signal: controller.signal,
      });

      if (!response.ok) {
        if (response.status === 413) {
          throw new Error('File too large (max 100 MB)');
        } else if (response.status === 415) {
          throw new Error('Unsupported file type');
        } else if (response.status === 429) {
          throw new Error('Rate limit exceeded. Please try again later.');
        } else {
          let errorMsg = `HTTP ${response.status}`;
          try {
            const data = await response.json();
            if (data?.error) errorMsg = data.error;
          } catch {
            // response was not JSON
          }
          throw new Error(errorMsg);
        }
      }

      const data: ScanResult = await response.json();
      setResult(data);
      return data;
    } catch (err: unknown) {
      if (err instanceof Error && err.name === 'AbortError') {
        setError('Scan cancelled');
      } else {
        setError(err instanceof Error ? err.message || 'Scan failed' : 'Scan failed');
      }
      throw err;
    } finally {
      setIsLoading(false);
      setAbortController(null);
    }
  }, []);

  const scanArchive = useCallback(async (file: File) => {
    setIsLoading(true);
    setError(null);
    setResult(null);

    const controller = new AbortController();
    setAbortController(controller);

    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await fetch('/api/scan/archive', {
        method: 'POST',
        body: formData,
        signal: controller.signal,
      });

      if (!response.ok) {
        if (response.status === 413) {
          throw new Error('Archive too large (max 200 MB)');
        } else if (response.status === 415) {
          throw new Error('Only .zip archives are supported');
        } else if (response.status === 429) {
          throw new Error('Rate limit exceeded. Please try again later.');
        } else {
          let errorMsg = `HTTP ${response.status}`;
          try {
            const data = await response.json();
            if (data?.error) errorMsg = data.error;
          } catch {
            // response was not JSON
          }
          throw new Error(errorMsg);
        }
      }

      const data: ArchiveScanResult = await response.json();
      setResult(data);
      return data;
    } catch (err: unknown) {
      if (err instanceof Error && err.name === 'AbortError') {
        setError('Scan cancelled');
      } else {
        setError(err instanceof Error ? err.message || 'Scan failed' : 'Scan failed');
      }
      throw err;
    } finally {
      setIsLoading(false);
      setAbortController(null);
    }
  }, []);

  const abort = useCallback(() => {
    if (abortController) {
      abortController.abort();
      setAbortController(null);
    }
  }, [abortController]);

  const reset = useCallback(() => {
    setIsLoading(false);
    setError(null);
    setResult(null);
    setAbortController(null);
  }, []);

  return {
    isLoading,
    error,
    result,
    scanFile,
    scanArchive,
    abort,
    reset,
  };
}
