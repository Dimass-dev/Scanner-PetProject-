import type { RiskScore } from '../hooks/useScan';
import './RiskBanner.css';

interface RiskBannerProps {
  risk: RiskScore;
}

const RISK_COLORS: Record<string, string> = {
  Info: '#5bc0de',
  Low: '#5cb85c',
  Medium: '#f0ad4e',
  High: '#d9534f',
  Critical: '#8b0000',
};

export function RiskBanner({ risk }: RiskBannerProps) {
  const color = RISK_COLORS[risk.level] || '#666';

  return (
    <div className="risk-banner" style={{ borderLeftColor: color }}>
      <div className="risk-level" style={{ color }}>
        <span className="risk-icon">🛡️</span>
        <span className="risk-text">{risk.level} Risk</span>
      </div>
      <div className="risk-score">
        Score: {risk.score}
      </div>
      <div className="risk-counts">
        {risk.counts.critical > 0 && (
          <span className="count critical">Critical: {risk.counts.critical}</span>
        )}
        {risk.counts.high > 0 && (
          <span className="count high">High: {risk.counts.high}</span>
        )}
        {risk.counts.medium > 0 && (
          <span className="count medium">Medium: {risk.counts.medium}</span>
        )}
        {risk.counts.low > 0 && (
          <span className="count low">Low: {risk.counts.low}</span>
        )}
        {risk.counts.info > 0 && (
          <span className="count info">Info: {risk.counts.info}</span>
        )}
      </div>
    </div>
  );
}
