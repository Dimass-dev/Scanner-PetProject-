import { useState, useMemo } from 'react';
import type { Finding } from '../hooks/useScan';
import './FindingsList.css';

interface FindingsListProps {
  findings: Finding[];
}

const SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Info'];

export function FindingsList({ findings }: FindingsListProps) {
  const [selectedSeverity, setSelectedSeverity] = useState<string>('All');
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);

  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = { All: findings.length };
    findings.forEach(f => {
      counts[f.severity] = (counts[f.severity] || 0) + 1;
    });
    return counts;
  }, [findings]);

  const filteredFindings = useMemo(() => {
    const filtered = selectedSeverity === 'All'
      ? findings
      : findings.filter(f => f.severity === selectedSeverity);

    return filtered.sort((a, b) => {
      const orderA = SEVERITY_ORDER.indexOf(a.severity);
      const orderB = SEVERITY_ORDER.indexOf(b.severity);
      return orderA - orderB;
    });
  }, [findings, selectedSeverity]);

  return (
    <div className="findings-list">
      <div className="findings-header">
        <h2>Findings ({filteredFindings.length})</h2>
        <div className="severity-filters">
          {['All', ...SEVERITY_ORDER].map(severity => (
            <button
              key={severity}
              className={`filter-btn ${severity.toLowerCase()} ${selectedSeverity === severity ? 'active' : ''}`}
              onClick={() => setSelectedSeverity(severity)}
              disabled={!severityCounts[severity]}
            >
              {severity} {severityCounts[severity] ? `(${severityCounts[severity]})` : ''}
            </button>
          ))}
        </div>
      </div>

      <div className="findings-items">
        {filteredFindings.length === 0 ? (
          <div className="no-findings">No findings for selected severity</div>
        ) : (
          filteredFindings.map(finding => (
            <div key={finding.ruleId} className={`finding-item ${finding.severity.toLowerCase()}`}>
              <div
                className="finding-summary"
                onClick={() => setExpandedFinding(expandedFinding === finding.ruleId ? null : finding.ruleId)}
              >
                <div className="finding-title">
                  <span className={`severity-badge ${finding.severity.toLowerCase()}`}>
                    {finding.severity}
                  </span>
                  <span className="title-text">{finding.title}</span>
                  <span className="rule-id">{finding.ruleId}</span>
                </div>
                <button className="expand-btn">
                  {expandedFinding === finding.ruleId ? '−' : '+'}
                </button>
              </div>

              {expandedFinding === finding.ruleId && (
                <div className="finding-details">
                  <div className="detail-section">
                    <strong>Category:</strong> {finding.category}
                  </div>
                  {finding.confidence && (
                    <div className="detail-section">
                      <strong>Confidence:</strong> {finding.confidence}
                    </div>
                  )}
                  <div className="detail-section">
                    <strong>Description:</strong>
                    <p>{finding.description}</p>
                  </div>
                  {finding.evidence && (
                    <div className="detail-section">
                      <strong>Evidence:</strong>
                      <code className="evidence">{finding.evidence}</code>
                    </div>
                  )}
                  {finding.recommendation && (
                    <div className="detail-section">
                      <strong>Recommendation:</strong>
                      <p>{finding.recommendation}</p>
                    </div>
                  )}
                  {finding.standardReference && (
                    <div className="detail-section">
                      <strong>Reference:</strong> {finding.standardReference}
                    </div>
                  )}
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
