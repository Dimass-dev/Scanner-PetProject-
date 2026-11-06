import { useRef, useState, type FormEvent } from 'react';
import { apiFetch } from '../api/client';
import type { RateLimitResult, WebScanResult } from '../api/types';
import { parseCount } from '../utils/parseCount';
import { FindingsList } from './FindingsList';
import { RiskBanner } from './RiskBanner';
import './WebScanPanel.css';

export function WebScanPanel() {
  const [targetUrl, setTargetUrl] = useState('http://localhost:5173');
  const [openApiDocument, setOpenApiDocument] = useState<string | null>(null);
  const [specFileName, setSpecFileName] = useState<string | null>(null);
  const [enableLimitedActive, setEnableLimitedActive] = useState(false);
  const [activeConfirmed, setActiveConfirmed] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<WebScanResult | null>(null);
  const controllerRef = useRef<AbortController | null>(null);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setResult(null);
    setIsLoading(true);
    const nextController = new AbortController();
    controllerRef.current = nextController;

    try {
      const data = await apiFetch<WebScanResult>('/api/scan/web', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetUrl, openApiDocument, enableLimitedActive, confirmedActiveTest: activeConfirmed }),
        signal: nextController.signal,
      });
      setResult(data);
    } catch (cause) {
      const failure = cause as Error;
      setError(failure.name === 'AbortError' ? 'Scan cancelled.' : failure.message || 'Web scan failed.');
    } finally {
      setIsLoading(false);
      controllerRef.current = null;
    }
  }

  function downloadReport() {
    if (!result) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' }));
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `web-scan-${result.scanId}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <section className="web-scan-panel" aria-labelledby="web-scan-title">
      <h2 id="web-scan-title">Passive web baseline</h2>
      <p className="web-scan-intro">
        Checks the approved origin over HTTP(S), follows a small number of same-origin links, and reviews response headers and cookies.
        It does not submit forms, log in, send attack payloads, or test load.
      </p>

      <form className="web-scan-form" onSubmit={handleSubmit}>
        <label htmlFor="web-target-url">Target URL</label>
        <div className="web-scan-controls">
          <input
            id="web-target-url"
            type="url"
            required
            maxLength={2048}
            value={targetUrl}
            onChange={(event) => setTargetUrl(event.target.value)}
            placeholder="https://localhost:5001"
            disabled={isLoading}
          />
          <button type="submit" disabled={isLoading || (enableLimitedActive && !activeConfirmed)}>{isLoading ? 'Scanning…' : 'Scan web target'}</button>
          {isLoading && <button type="button" className="web-cancel" onClick={() => controllerRef.current?.abort()}>Cancel</button>}
        </div>
        <label className="openapi-label" htmlFor="openapi-file">OpenAPI 3.x JSON (optional)</label>
        <input
          id="openapi-file"
          type="file"
          accept=".json,application/json"
          disabled={isLoading}
          onChange={async (event) => {
            const file = event.currentTarget.files?.[0];
            event.currentTarget.value = '';
            if (!file) return;
            if (file.size > 1_048_576) {
              setError('OpenAPI file must be no larger than 1 MiB.');
              setOpenApiDocument(null);
              setSpecFileName(null);
              return;
            }
            setOpenApiDocument(await file.text());
            setSpecFileName(file.name);
            setError(null);
          }}
        />
        {specFileName && <p className="web-scan-scope-note">Loaded specification: {specFileName}</p>}
        <div className="active-probe-box">
          <label className="active-probe-toggle">
            <input type="checkbox" checked={enableLimitedActive} onChange={(event) => { setEnableLimitedActive(event.target.checked); if (!event.target.checked) setActiveConfirmed(false); }} disabled={isLoading} />
            Enable limited active query check
          </label>
          <p>When enabled, the scanner may send up to three bounded GET probes: a malformed query value for database error disclosure, an inert HTML marker, and documented GET routes without credentials. It does not execute scripts, submit forms, or extract data. Even GET routes can change state; use a staging copy.</p>
          {enableLimitedActive && (
            <label className="active-probe-confirm">
              <input type="checkbox" checked={activeConfirmed} onChange={(event) => setActiveConfirmed(event.target.checked)} disabled={isLoading} />
              I own this target or have permission to test it, and I understand GET requests can have side effects.
            </label>
          )}
        </div>
        <p className="web-scan-scope-note">
          Only origins listed in the server’s <code>WebScanner:AllowedOrigins</code> setting are accepted. Add only systems you own or have permission to test.
        </p>
      </form>

      {error && <div className="web-scan-error" role="alert">{error}</div>}

      {result && (
        <div className="web-scan-results" aria-live="polite">
          <div className="web-results-header">
            <div>
              <h3>Scan result</h3>
              <code>{result.targetUrl}</code>
            </div>
            <div className="web-results-actions">
              <span className="web-scan-status">{result.status}</span>
              <button type="button" onClick={downloadReport}>Download JSON report</button>
            </div>
          </div>
          <RiskBanner risk={result.risk} />

          {result.findings.length > 0
            ? <FindingsList findings={result.findings} />
            : <p className="web-no-findings">No findings were raised by the checks that ran. Review coverage and limitations below.</p>}

          {Object.entries(result.artifacts).map(([kind, properties]) => (
            <section className="web-coverage" key={kind}>
              <h3>{kind === 'web.coverage' ? 'Coverage and limitations' : kind}</h3>
              <dl>
                {Object.entries(properties).map(([name, value]) => (
                  <div key={name}><dt>{name}</dt><dd>{value}</dd></div>
                ))}
              </dl>
            </section>
          ))}

          {result.errors.length > 0 && <ul className="web-scan-error-list">{result.errors.map((item) => <li key={item}>{item}</li>)}</ul>}
        </div>
      )}

      <AuthRateLimitPanel targetUrl={targetUrl} />
    </section>
  );
}

function AuthRateLimitPanel({ targetUrl }: { targetUrl: string }) {
  const [loginPath, setLoginPath] = useState('/api/login');
  const [testUsername, setTestUsername] = useState('');
  const [attempts, setAttempts] = useState(3);
  const [confirmed, setConfirmed] = useState(false);
  const [running, setRunning] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const probeControllerRef = useRef<AbortController | null>(null);

  async function runProbe(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setRunning(true);
    setMessage(null);
    const nextController = new AbortController();
    probeControllerRef.current = nextController;
    try {
      const result = await apiFetch<RateLimitResult>('/api/scan/web/auth-rate-limit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetUrl, loginPath, testUsername, attempts, confirmedControlledTestAccount: confirmed }),
        signal: nextController.signal,
      });
      setMessage(`${result.status}: ${result.summary} HTTP responses: ${(result.httpStatusCodes ?? []).join(', ') || 'none'}.`);
    } catch (cause) {
      const failure = cause as Error;
      setMessage(failure.name === 'AbortError' ? 'Rate-limit check cancelled.' : failure.message || 'Rate-limit check failed.');
    } finally {
      setRunning(false);
      probeControllerRef.current = null;
    }
  }

  return (
    <details className="auth-probe">
      <summary>Controlled login rate-limit check (limited active test)</summary>
      <p>This sends at most five failed JSON login attempts with generated random passwords and fixed <code>username</code>/<code>password</code> fields. It can lock the test account. Use only a dedicated account on an approved staging or local target.</p>
      <form onSubmit={runProbe}>
        <label htmlFor="auth-login-path">Login path</label>
        <input id="auth-login-path" required value={loginPath} onChange={(event) => setLoginPath(event.target.value)} placeholder="/api/login" disabled={running} />
        <label htmlFor="auth-test-user">Dedicated test username</label>
        <input id="auth-test-user" required maxLength={128} value={testUsername} onChange={(event) => setTestUsername(event.target.value)} disabled={running} />
        <label htmlFor="auth-attempts">Maximum attempts (server cap: 5)</label>
        <input id="auth-attempts" type="number" min={1} max={5} value={attempts} onChange={(event) => setAttempts(parseCount(event.target.value, attempts))} disabled={running} />
        <label className="auth-confirm">
          <input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} disabled={running} />
          I own this service and this is a dedicated test account; I accept that it may be temporarily locked.
        </label>
        <button type="submit" disabled={running || !confirmed}>{running ? 'Checking…' : 'Check login throttling'}</button>
        {running && <button type="button" onClick={() => probeControllerRef.current?.abort()}>Cancel check</button>}
      </form>
      {message && <p className="auth-probe-result" role="status">{message}</p>}
    </details>
  );
}
