import type { RiskScore } from '../api/types';
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
  const color = RISK_COLORS[risk.level] ?? '#666';
  const count = (key: string) => risk.counts[key] ?? 0;

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
        {count('critical') > 0 && (
          <span className="count critical">Critical: {count('critical')}</span>
        )}
        {count('high') > 0 && (
          <span className="count high">High: {count('high')}</span>
        )}
        {count('medium') > 0 && (
          <span className="count medium">Medium: {count('medium')}</span>
        )}
        {count('low') > 0 && (
          <span className="count low">Low: {count('low')}</span>
        )}
        {count('info') > 0 && (
          <span className="count info">Info: {count('info')}</span>
        )}
      </div>
    </div>
  );
}
