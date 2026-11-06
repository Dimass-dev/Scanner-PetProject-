using Core.Scanning;

namespace Core.Risk;

/// <summary>
/// Assesses overall risk level based on scan findings.
/// </summary>
public sealed class RiskAssessmentEngine
{
    private const int CriticalWeight = 50;
    private const int HighWeight = 15;
    private const int MediumWeight = 5;
    private const int LowWeight = 1;
    private const int InfoWeight = 0;

    /// <summary>Assess risk from findings.</summary>
    public RiskScore Assess(IReadOnlyList<ScanFinding> findings)
    {
        var counts = new Dictionary<ScanSeverity, int>
        {
            [ScanSeverity.Critical] = 0,
            [ScanSeverity.High] = 0,
            [ScanSeverity.Medium] = 0,
            [ScanSeverity.Low] = 0,
            [ScanSeverity.Informational] = 0
        };

        int totalScore = 0;

        foreach (var finding in findings)
        {
            counts[finding.Severity]++;
            totalScore += GetWeight(finding.Severity);
        }

        var level = DetermineRiskLevel(counts, totalScore);

        return new RiskScore(level, totalScore, counts);
    }

    private RiskLevel DetermineRiskLevel(Dictionary<ScanSeverity, int> counts, int score)
    {
        // Any Critical finding = Critical risk
        if (counts[ScanSeverity.Critical] > 0)
        {
            return RiskLevel.Critical;
        }

        // Score >= 15 or 2+ High = High risk
        if (score >= 15 || counts[ScanSeverity.High] >= 2)
        {
            return RiskLevel.High;
        }

        // Score >= 5 or 1+ Medium = Medium risk
        if (score >= 5 || counts[ScanSeverity.Medium] >= 1)
        {
            return RiskLevel.Medium;
        }

        // Score >= 1 or 1+ Low = Low risk
        if (score >= 1 || counts[ScanSeverity.Low] >= 1)
        {
            return RiskLevel.Low;
        }

        // No findings = Info
        return RiskLevel.Info;
    }

    private int GetWeight(ScanSeverity severity) => severity switch
    {
        ScanSeverity.Critical => CriticalWeight,
        ScanSeverity.High => HighWeight,
        ScanSeverity.Medium => MediumWeight,
        ScanSeverity.Low => LowWeight,
        ScanSeverity.Informational => InfoWeight,
        _ => 0
    };
}

/// <summary>Risk level classification.</summary>
public enum RiskLevel
{
    Info,
    Low,
    Medium,
    High,
    Critical
}

/// <summary>Risk assessment result.</summary>
public sealed record RiskScore(
    RiskLevel Level,
    int Score,
    IReadOnlyDictionary<ScanSeverity, int> Counts);
