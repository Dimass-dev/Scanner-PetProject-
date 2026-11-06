import { useId } from 'react';
import './ArtifactsPanel.css';

interface ArtifactsPanelProps {
  artifacts: Record<string, unknown>;
  compact?: boolean;
}

const ARTIFACT_ORDER = ['header', 'mitigations', 'sections', 'imports', 'signature'];
const ARTIFACT_LABELS: Record<string, string> = {
  header: 'PE Header',
  mitigations: 'Security Mitigations',
  sections: 'Sections',
  imports: 'Imports',
  signature: 'Code Signature',
  risk: 'Risk',
};
const PROPERTY_LABELS: Record<string, string> = {
  architecture: 'Architecture',
  subsystem: 'Subsystem',
  entryPoint: 'Entry point',
  timestamp: 'Timestamp',
  checksum: 'Checksum',
  isDll: 'DLL',
  sizeOfImage: 'Image size',
  aslr: 'ASLR',
  dep: 'DEP',
  cfg: 'CFG',
  highEntropyVA: 'High Entropy VA',
  count: 'Count',
  sections: 'Names',
  dllCount: 'DLLs',
  functionCount: 'Functions',
  dlls: 'DLL names',
  state: 'State',
  subject: 'Subject',
  issuer: 'Issuer',
  thumbprint: 'Thumbprint',
  size: 'Size',
  offset: 'Offset',
  entropy: 'Entropy',
};

function isStringRecord(value: unknown): value is Record<string, string> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function labelForKey(key: string): string {
  const known = PROPERTY_LABELS[key] ?? PROPERTY_LABELS[key.toLowerCase()];
  if (known) return known;

  return key
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .replace(/[_-]+/g, ' ')
    .replace(/\b\w/g, char => char.toUpperCase());
}

function isEnabled(value: string): boolean | null {
  if (value.toLowerCase() === 'true') return true;
  if (value.toLowerCase() === 'false') return false;
  return null;
}

export function ArtifactsPanel({ artifacts, compact = false }: ArtifactsPanelProps) {
  const headingId = useId();
  const entries = Object.entries(artifacts)
    .filter(([key]) => key.toLowerCase() !== 'risk')
    .sort(([a], [b]) => {
      const ai = ARTIFACT_ORDER.indexOf(a.toLowerCase());
      const bi = ARTIFACT_ORDER.indexOf(b.toLowerCase());
      return (ai === -1 ? ARTIFACT_ORDER.length : ai) - (bi === -1 ? ARTIFACT_ORDER.length : bi);
    });

  if (entries.length === 0) return null;

  return (
    <section className={`artifacts ${compact ? 'compact' : ''}`} aria-labelledby={headingId}>
      <h3 id={headingId}>{compact ? 'Details' : 'File Details'}</h3>
      <div className="artifacts-grid">
        {entries.map(([key, value]) => (
          <article key={key} className="artifact-card">
            <h4>{ARTIFACT_LABELS[key.toLowerCase()] ?? labelForKey(key)}</h4>
            {isStringRecord(value) ? (
              <dl className="artifact-properties">
                {Object.entries(value).map(([property, propertyValue]) => {
                  const enabled = isEnabled(propertyValue);
                  return (
                    <div key={property} className="artifact-property">
                      <dt>{labelForKey(property)}</dt>
                      <dd>
                        {enabled === null ? (
                          propertyValue
                        ) : (
                          <span className={`boolean-badge ${enabled ? 'enabled' : 'disabled'}`}>
                            {enabled ? 'Enabled' : 'Disabled'}
                          </span>
                        )}
                      </dd>
                    </div>
                  );
                })}
              </dl>
            ) : (
              <pre>{JSON.stringify(value, null, 2)}</pre>
            )}
          </article>
        ))}
      </div>
    </section>
  );
}
