import { useState } from 'react';
import { useScan } from './hooks/useScan';
import { UploadZone } from './components/UploadZone';
import { RiskBanner } from './components/RiskBanner';
import { FindingsList } from './components/FindingsList';
import { WebScanPanel } from './components/WebScanPanel';
import { LoadTestPanel } from './components/LoadTestPanel';
import './App.css';

function App() {
  const [activeView, setActiveView] = useState<'files' | 'web' | 'load'>('files');
  const { isLoading, error, result, scanFile, scanArchive, abort, reset } = useScan();

  const handleFileSelect = async (file: File) => {
    try {
      if (file.name.endsWith('.zip')) {
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

  return (
    <div className="app">
      <header className="app-header">
        <h1>🛡️ Multi-Scanner</h1>
        <p className="subtitle">Local security checks for PE files and web services</p>
        <p className="disclaimer">Use only with systems you own or have permission to assess.</p>
      </header>

      <nav className="scanner-tabs" aria-label="Scanner type">
        <button className={activeView === 'files' ? 'active' : ''} onClick={() => setActiveView('files')}>PE files and ZIP</button>
        <button className={activeView === 'web' ? 'active' : ''} onClick={() => setActiveView('web')}>Web service</button>
        <button className={activeView === 'load' ? 'active' : ''} onClick={() => setActiveView('load')}>Load test</button>
      </nav>

      <main className="app-main">
        {activeView === 'web' ? <WebScanPanel /> : activeView === 'load' ? <LoadTestPanel /> : <>
        <UploadZone onFileSelect={handleFileSelect} isLoading={isLoading} />

        {isLoading && (
          <div className="loading-state">
            <div className="spinner"></div>
            <p>Analyzing file...</p>
            <button onClick={abort} className="abort-btn">Cancel</button>
          </div>
        )}

        {error && (
          <div className="error-state">
            <span className="error-icon">❌</span>
            <p>{error}</p>
            <button onClick={reset} className="reset-btn">Try Again</button>
          </div>
        )}

        {singleFileResult && singleFileResult.risk && (
          <div className="results">
            <div className="results-header">
              <h2>{singleFileResult.fileName}</h2>
              <button onClick={reset} className="new-scan-btn">New Scan</button>
            </div>

            <RiskBanner risk={singleFileResult.risk} />

            {singleFileResult.findings.length > 0 && (
              <FindingsList findings={singleFileResult.findings} />
            )}

            {singleFileResult.artifacts && Object.keys(singleFileResult.artifacts).length > 0 && (
              <div className="artifacts">
                <h3>File Details</h3>
                <div className="artifacts-grid">
                  {Object.entries(singleFileResult.artifacts).map(([key, value]) => (
                    <div key={key} className="artifact-card">
                      <h4>{key}</h4>
                      <pre>{JSON.stringify(value, null, 2)}</pre>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {archiveResult && (
          <div className="results">
            <div className="results-header">
              <h2>{archiveResult.archiveName}</h2>
              <button onClick={reset} className="new-scan-btn">New Scan</button>
            </div>

            <div className="archive-summary">
              <p>Extracted: {archiveResult.extractedFileCount} files</p>
              <p>Scanned: {archiveResult.scannedFileCount} PE files</p>
            </div>

            {archiveResult.overallRisk && (
              <RiskBanner risk={archiveResult.overallRisk} />
            )}

            {archiveResult.files.map((file, idx) => (
              <div key={idx} className="file-result">
                <h3>{file.relativePath}</h3>
                {file.risk && <RiskBanner risk={file.risk} />}
                {file.findings.length > 0 && <FindingsList findings={file.findings} />}
              </div>
            ))}

            {archiveResult.extractionErrors.length > 0 && (
              <div className="extraction-errors">
                <h3>Extraction Warnings</h3>
                <ul>
                  {archiveResult.extractionErrors.map((err, idx) => (
                    <li key={idx}>{err}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
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
