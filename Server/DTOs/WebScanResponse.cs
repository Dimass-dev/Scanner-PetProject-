using Core.Risk;
using Core.Scanning;

namespace Server.DTOs;

public sealed record WebScanResponse(
    string ScanId,
    string TargetUrl,
    string Status,
    RiskScoreDto Risk,
    IReadOnlyList<ScanFindingDto> Findings,
    Dictionary<string, object> Artifacts,
    IReadOnlyList<string> Errors)
{
    public static WebScanResponse FromReport(string scanId, string targetUrl, ScanReport report)
    {
        var risk = new RiskAssessmentEngine().Assess(report.Findings);
        var riskDto = new RiskScoreDto(risk.Level.ToString(), risk.Score, new Dictionary<string, int>
        {
            ["critical"] = risk.Counts.GetValueOrDefault(ScanSeverity.Critical),
            ["high"] = risk.Counts.GetValueOrDefault(ScanSeverity.High),
            ["medium"] = risk.Counts.GetValueOrDefault(ScanSeverity.Medium),
            ["low"] = risk.Counts.GetValueOrDefault(ScanSeverity.Low),
            ["info"] = risk.Counts.GetValueOrDefault(ScanSeverity.Informational)
        });

        var findings = report.Findings.Select(finding => new ScanFindingDto(
            finding.RuleId,
            finding.Title,
            finding.Category,
            finding.Severity == ScanSeverity.Informational ? "Info" : finding.Severity.ToString(),
            finding.Description,
            finding.Evidence,
            finding.Recommendation,
            finding.StandardReference,
            finding.Confidence)).ToArray();

        var artifacts = report.Artifacts.ToDictionary(
            artifact => artifact.Kind,
            artifact => (object)artifact.Properties,
            StringComparer.OrdinalIgnoreCase);
        var errors = report.Modules
            .Where(module => module.Status == ScanStatus.Failed && module.ErrorMessage is not null)
            .Select(module => module.ErrorMessage!)
            .ToArray();

        return new WebScanResponse(scanId, targetUrl, report.Status.ToString(), riskDto, findings, artifacts, errors);
    }
}
