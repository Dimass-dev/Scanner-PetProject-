import { useCallback, useRef, useState } from 'react';
import { apiFetch } from '../api/client';
import type { ArchiveScanResult, ScanResult } from '../api/types';

export function useScan() {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | ArchiveScanResult | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const runScan = useCallback(async <T extends ScanResult | ArchiveScanResult>(
    url: string,
    file: File,
    statusMessages: Record<number, string>,
  ): Promise<T> => {
    setIsLoading(true);
    setError(null);
    setResult(null);

    const controller = new AbortController();
    abortRef.current = controller;

    try {
      const formData = new FormData();
      formData.append('file', file);
      const data = await apiFetch<T>(
        url,
        { method: 'POST', body: formData, signal: controller.signal },
        statusMessages,
      );
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
      abortRef.current = null;
    }
  }, []);

  const scanFile = useCallback(
    (file: File) =>
      runScan<ScanResult>('/api/scan/file', file, {
        413: 'File too large (max 100 MB)',
        415: 'Unsupported file type',
        429: 'Rate limit exceeded. Please try again later.',
      }),
    [runScan],
  );

  const scanArchive = useCallback(
    (file: File) =>
      runScan<ArchiveScanResult>('/api/scan/archive', file, {
        413: 'Archive too large (max 200 MB)',
        415: 'Only .zip archives are supported',
        429: 'Rate limit exceeded. Please try again later.',
      }),
    [runScan],
  );

  const abort = useCallback(() => {
    abortRef.current?.abort();
    abortRef.current = null;
  }, []);

  const reset = useCallback(() => {
    setIsLoading(false);
    setError(null);
    setResult(null);
    abortRef.current = null;
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
