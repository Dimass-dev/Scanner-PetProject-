import { useMemo, useState } from 'react';
import type { ArchiveScanResult, FileResult } from '../api/types';
import { RiskBanner } from './RiskBanner';
import { FindingsList } from './FindingsList';
import { ArtifactsPanel } from './ArtifactsPanel';
import './ArchiveResults.css';

interface ArchiveResultsProps {
  result: ArchiveScanResult;
  onReset: () => void;
}

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / 1024 ** index).toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

function statusClass(status: string): string {
  return status.toLowerCase().replace(/[^a-z]+/g, '-');
}

export function ArchiveResults({ result, onReset }: ArchiveResultsProps) {
  const [selectedPath, setSelectedPath] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const searchId = 'archive-file-search';

  const filteredFiles = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    if (!normalized) return result.files;
    return result.files.filter(file => file.relativePath.toLowerCase().includes(normalized));
  }, [result.files, query]);

  const selectedFile: FileResult | undefined = useMemo(
    () => result.files.find(file => file.relativePath === selectedPath),
    [result.files, selectedPath],
  );

  const totalFindings = result.files.reduce((total, file) => total + file.findings.length, 0);
  const filesWithErrors = result.files.filter(file => file.errors.length > 0).length;

  if (result.errorMessage) {
    return (
      <div className="results">
        <div className="results-header">
          <h2>{result.archiveName}</h2>
          <button type="button" onClick={onReset} className="new-scan-btn">New Scan</button>
        </div>
        <div className="error-state" role="alert">
          <span className="error-icon" aria-hidden="true">⚠️</span>
          <p>{result.errorMessage}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="results archive-results">
      <div className="results-header">
        <h2>{result.archiveName}</h2>
        <button type="button" onClick={onReset} className="new-scan-btn">New Scan</button>
      </div>

      <div className="archive-summary" aria-label="Archive summary">
        <div className="summary-stat">
          <span className="summary-value">{result.extractedFileCount}</span>
          <span className="summary-label">Extracted</span>
        </div>
        <div className="summary-stat">
          <span className="summary-value">{result.scannedFileCount}</span>
          <span className="summary-label">Scanned PE files</span>
        </div>
        <div className="summary-stat">
          <span className="summary-value">{totalFindings}</span>
          <span className="summary-label">Findings</span>
        </div>
        <div className="summary-stat">
          <span className="summary-value">{result.extractionErrors.length + filesWithErrors}</span>
          <span className="summary-label">Warnings</span>
        </div>
      </div>

      {result.overallRisk && <RiskBanner risk={result.overallRisk} />}

      {result.extractionErrors.length > 0 && (
        <section className="extraction-errors" aria-labelledby="extraction-warnings-heading">
          <h3 id="extraction-warnings-heading">Extraction Warnings</h3>
          <ul>
            {result.extractionErrors.map((error, index) => (
              <li key={`${index}-${error}`}>{error}</li>
            ))}
          </ul>
        </section>
      )}

      {result.files.length === 0 ? (
        <div className="empty-archive" role="status">
          <p>No PE files were found in this archive.</p>
        </div>
      ) : (
        <div className="archive-browser">
          <aside className="archive-files" aria-label="Archive files">
            <label className="archive-search" htmlFor={searchId}>
              <span>Filter files</span>
              <input
                id={searchId}
                type="search"
                value={query}
                onChange={event => setQuery(event.target.value)}
                placeholder="Search by path..."
                autoComplete="off"
              />
            </label>

            <p className="file-list-count" role="status">
              {filteredFiles.length} of {result.files.length} files
            </p>

            <ul className="file-list">
              {filteredFiles.map((file, index) => {
                const isSelected = file.relativePath === selectedPath;
                return (
                  <li key={`${file.relativePath}-${index}`}>
                    <button
                      type="button"
                      className={`file-list-item ${isSelected ? 'selected' : ''}`}
                      onClick={() => setSelectedPath(file.relativePath)}
                      aria-current={isSelected ? 'true' : undefined}
                    >
                      <span className="file-list-name" title={file.relativePath}>{file.relativePath}</span>
                      <span className="file-list-meta">
                        <span className={`status-chip ${statusClass(file.status)}`}>{file.status}</span>
                        <span>{formatBytes(file.fileSize)}</span>
                        <span>{file.findings.length} finding{file.findings.length === 1 ? '' : 's'}</span>
                      </span>
                    </button>
                  </li>
                );
              })}
            </ul>

            {filteredFiles.length === 0 && (
              <p className="no-files-match" role="status">No files match “{query}”.</p>
            )}
          </aside>

          <section className="archive-detail" aria-label="Selected file details">
            {selectedFile ? (
              <>
                <div className="archive-detail-header">
                  <h3>{selectedFile.relativePath}</h3>
                  <span className={`status-chip ${statusClass(selectedFile.status)}`}>{selectedFile.status}</span>
                </div>
                <p className="archive-detail-size">{formatBytes(selectedFile.fileSize)}</p>

                {selectedFile.risk && <RiskBanner risk={selectedFile.risk} />}

                {selectedFile.errors.length > 0 && (
                  <div className="file-errors" role="alert">
                    <h4>Scan errors</h4>
                    <ul>
                      {selectedFile.errors.map((error, index) => (
                        <li key={`${index}-${error}`}>{error}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {selectedFile.findings.length > 0 ? (
                  <FindingsList findings={selectedFile.findings} />
                ) : (
                  <p className="no-findings" role="status">No findings for this file.</p>
                )}

                <ArtifactsPanel artifacts={selectedFile.artifacts} compact />
              </>
            ) : (
              <div className="archive-placeholder">
                <p>Select a file to inspect its findings and details.</p>
              </div>
            )}
          </section>
        </div>
      )}
    </div>
  );
}
