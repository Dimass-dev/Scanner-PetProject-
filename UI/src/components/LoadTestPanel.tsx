import { useMemo, useState } from 'react';
import { parseCount } from '../utils/parseCount';
import './LoadTestPanel.css';

interface K6Summary {
  metrics?: Record<string, { values?: Record<string, number> }>;
}

export function LoadTestPanel() {
  const [targetUrl, setTargetUrl] = useState('http://127.0.0.1:5290');
  const [path, setPath] = useState('/api/scan/health');
  const [rate, setRate] = useState(2);
  const [duration, setDuration] = useState(20);
  const [vus, setVus] = useState(2);
  const [remoteConfirmed, setRemoteConfirmed] = useState(false);
  const [summary, setSummary] = useState<K6Summary | null>(null);
  const [error, setError] = useState<string | null>(null);

  const target = useMemo(() => {
    try {
      const base = new URL(targetUrl);
      if (!['http:', 'https:'].includes(base.protocol) || base.username || base.password || base.search || base.hash) return '';
      const endpoint = new URL(path, `${base.origin}/`);
      return endpoint.origin === base.origin && !endpoint.search && !endpoint.hash ? endpoint.toString() : '';
    } catch {
      return '';
    }
  }, [targetUrl, path]);

  const isLocal = useMemo(() => {
    try {
      const parsed = new URL(targetUrl);
      if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) return false;
      const host = parsed.hostname.toLowerCase();
      return host === 'localhost' || host === '127.0.0.1' || host === '[::1]' || host === '::1';
    } catch {
      return false;
    }
  }, [targetUrl]);

  const canGenerate = Boolean(target) && path.startsWith('/') && !path.startsWith('//') && (isLocal || remoteConfirmed);

  function downloadScript() {
    setError(null);
    const script = `import http from 'k6/http';
import { check } from 'k6';

const TARGET = ${JSON.stringify(target)};
const RATE_PER_SECOND = ${rate};
const DURATION = '${duration}s';
const VUS = ${vus};

const host = new URL(TARGET).hostname.toLowerCase();
const isLocal = host === 'localhost' || host === '127.0.0.1' || host === '[::1]' || host === '::1';
if (!isLocal && __ENV.ALLOW_REMOTE_TARGET !== 'I_OWN_AND_APPROVE_THIS_TARGET') {
  throw new Error('Remote target blocked. Set ALLOW_REMOTE_TARGET=I_OWN_AND_APPROVE_THIS_TARGET only for a target you own or are authorized to test.');
}

export const options = {
  scenarios: {
    bounded_read_only_check: {
      executor: 'constant-arrival-rate',
      rate: RATE_PER_SECOND,
      timeUnit: '1s',
      duration: DURATION,
      preAllocatedVUs: VUS,
      maxVUs: VUS,
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(95)<1500'],
  },
};

export default function () {
  const response = http.get(TARGET, { redirects: 0, tags: { check: 'read-only-get' } });
  check(response, { 'responded with HTTP status': (res) => res.status > 0 });
}
`;
    const url = URL.createObjectURL(new Blob([script], { type: 'text/javascript' }));
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'bounded-web-load-check.js';
    anchor.click();
    URL.revokeObjectURL(url);
  }

  async function importSummary(file?: File) {
    if (!file) return;
    setError(null);
    try {
      if (file.size > 2 * 1024 * 1024) throw new Error('Summary file must be 2 MiB or smaller.');
      const parsed = JSON.parse(await file.text()) as K6Summary;
      if (!parsed.metrics || typeof parsed.metrics !== 'object') throw new Error('This file does not look like a k6 --summary-export JSON report.');
      setSummary(parsed);
    } catch (cause) {
      setSummary(null);
      setError((cause as Error).message);
    }
  }

  const metrics = summary?.metrics;
  const p95 = metrics?.http_req_duration?.values?.['p(95)'];
  const errorRate = metrics?.http_req_failed?.values?.rate;
  const throughput = metrics?.http_reqs?.values?.rate;

  return (
    <section className="load-test-panel" aria-labelledby="load-test-title">
      <h2 id="load-test-title">Bounded performance check</h2>
      <p>This creates a small k6 script for read-only GET requests. The scanner does not run the load test itself. Start on a local or staging service, watch its logs and resource metrics, and stop the run if the service degrades.</p>

      <form className="load-test-form" onSubmit={(event) => { event.preventDefault(); downloadScript(); }}>
        <label htmlFor="load-target">Target base URL</label>
        <input id="load-target" type="url" required value={targetUrl} onChange={(event) => setTargetUrl(event.target.value)} />
        <label htmlFor="load-path">Read-only endpoint path</label>
        <input id="load-path" required value={path} onChange={(event) => setPath(event.target.value)} placeholder="/health" />
        <div className="load-limits">
          <label>Requests/sec (1–5)<input type="number" min={1} max={5} value={rate} onChange={(event) => setRate(parseCount(event.target.value, rate))} /></label>
          <label>Duration seconds (10–30)<input type="number" min={10} max={30} value={duration} onChange={(event) => setDuration(parseCount(event.target.value, duration))} /></label>
          <label>Virtual users (1–5)<input type="number" min={1} max={5} value={vus} onChange={(event) => setVus(parseCount(event.target.value, vus))} /></label>
        </div>
        {!isLocal && (
          <label className="load-confirm"><input type="checkbox" checked={remoteConfirmed} onChange={(event) => setRemoteConfirmed(event.target.checked)} /> I own or have permission to test this remote target.</label>
        )}
        <button type="submit" disabled={!canGenerate || rate < 1 || rate > 5 || duration < 10 || duration > 30 || vus < 1 || vus > 5}>Download bounded k6 script</button>
      </form>

      <details className="load-run-help">
        <summary>How to run and import results</summary>
        <ol>
          <li>Install k6 and review the downloaded script before running it.</li>
          <li>Run <code>k6 run --summary-export summary.json bounded-web-load-check.js</code>.</li>
          <li>For a remote target, explicitly set <code>ALLOW_REMOTE_TARGET=I_OWN_AND_APPROVE_THIS_TARGET</code>.</li>
          <li>Import the generated <code>summary.json</code> below.</li>
        </ol>
      </details>

      <label className="summary-import" htmlFor="k6-summary">Import k6 summary JSON</label>
      <input id="k6-summary" type="file" accept=".json,application/json" onChange={(event) => { void importSummary(event.currentTarget.files?.[0]); event.currentTarget.value = ''; }} />
      {error && <p className="load-error" role="alert">{error}</p>}
      {summary && (
        <dl className="load-metrics" aria-live="polite">
          <div><dt>HTTP p95</dt><dd>{p95 === undefined ? 'Unavailable' : `${p95.toFixed(1)} ms`}</dd></div>
          <div><dt>Failed request rate</dt><dd>{errorRate === undefined ? 'Unavailable' : `${(errorRate * 100).toFixed(2)}%`}</dd></div>
          <div><dt>Requests/sec</dt><dd>{throughput === undefined ? 'Unavailable' : throughput.toFixed(2)}</dd></div>
        </dl>
      )}
    </section>
  );
}
