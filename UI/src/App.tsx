import { useState } from 'react';
import { useScan } from './hooks/useScan';
import { UploadZone } from './components/UploadZone';
import { RiskBanner } from './components/RiskBanner';
import { FindingsList } from './components/FindingsList';
import { ArtifactsPanel } from './components/ArtifactsPanel';
import { ArchiveResults } from './components/ArchiveResults';
import { WebScanPanel } from './components/WebScanPanel';
import { LoadTestPanel } from './components/LoadTestPanel';
import './App.css';

type ScannerView = 'files' | 'web' | 'load';

function App() {
  const [activeView, setActiveView] = useState<ScannerView>('files');
  const { isLoading, error, result, scanFile, scanArchive, abort, reset } = useScan();

  const handleFileSelect = async (file: File) => {
    try {
      if (file.name.toLowerCase().endsWith('.zip')) {
        await scanArchive(file);
      } else {
        await scanFile(file);
      }
    } catch (err) {
      console.error('Scan error:', err);
    }
  };

  const isArchiveResult = result && 'files' in result;
  const singleFileResult = !isArchiveResult ? result : null;
  const archiveResult = isArchiveResult ? result : null;

  const tabs: { id: ScannerView; label: string }[] = [
    { id: 'files', label: 'PE files and ZIP' },
    { id: 'web', label: 'Web service' },
    { id: 'load', label: 'Load test' },
  ];

  return (
    <div className="app">
      <header className="app-header">
        <h1>🛡️ Multi-Scanner</h1>
        <p className="subtitle">Local security checks for PE files and web services</p>
        <p className="disclaimer">Use only with systems you own or have permission to assess.</p>
      </header>

      <nav className="scanner-tabs" role="tablist" aria-label="Scanner type">
        {tabs.map(tab => (
          <button
            key={tab.id}
            id={`scanner-tab-${tab.id}`}
            type="button"
            role="tab"
            aria-selected={activeView === tab.id}
            aria-controls="scanner-panel"
            className={activeView === tab.id ? 'active' : ''}
            onClick={() => setActiveView(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      <main
        id="scanner-panel"
        className="app-main"
        role="tabpanel"
        aria-labelledby={`scanner-tab-${activeView}`}
        aria-busy={isLoading}
      >
        {activeView === 'web' ? <WebScanPanel /> : activeView === 'load' ? <LoadTestPanel /> : <>
          <UploadZone onFileSelect={handleFileSelect} isLoading={isLoading} />

          {isLoading && (
            <div className="loading-state" role="status" aria-live="polite">
              <div className="spinner" aria-hidden="true"></div>
              <p>Analyzing file...</p>
              <button type="button" onClick={abort} className="abort-btn">Cancel</button>
            </div>
          )}

          {error && (
            <div className="error-state" role="alert">
              <span className="error-icon" aria-hidden="true">❌</span>
              <p>{error}</p>
              <button type="button" onClick={reset} className="reset-btn">Try Again</button>
            </div>
          )}

          {singleFileResult && (
            <div className="results">
              <div className="results-header">
                <h2>{singleFileResult.fileName}</h2>
                <button type="button" onClick={reset} className="new-scan-btn">New Scan</button>
              </div>

              {singleFileResult.risk && <RiskBanner risk={singleFileResult.risk} />}

              {singleFileResult.errors.length > 0 && (
                <div className="file-errors" role="alert">
                  <h3>Scan errors</h3>
                  <ul>
                    {singleFileResult.errors.map((scanError, index) => (
                      <li key={`${index}-${scanError}`}>{scanError}</li>
                    ))}
                  </ul>
                </div>
              )}

              {singleFileResult.findings.length > 0 && (
                <FindingsList findings={singleFileResult.findings} />
              )}

              <ArtifactsPanel artifacts={singleFileResult.artifacts} />
            </div>
          )}

          {archiveResult && (
            <ArchiveResults key={archiveResult.scanId} result={archiveResult} onReset={reset} />
          )}
        </>}
      </main>

      <footer className="app-footer">
        <p>Multi-Scanner Platform v0.1.0</p>
        <p>Web tab runs a bounded passive baseline. It does not perform penetration or load testing.</p>
      </footer>
    </div>
  );
}

export default App;
