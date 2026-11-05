using Core.Risk;
using Core.Scanning;

namespace Server.DTOs;

/// <summary>Response for single file scan.</summary>
public sealed record ScanFileResponse(
    string ScanId,
    string FileName,
    long FileSize,
    string Status,
    RiskScoreDto? Risk,
    IReadOnlyList<ScanFindingDto> Findings,
    Dictionary<string, object> Artifacts,
    IReadOnlyList<string> Errors)
{
    public static ScanFileResponse FromReport(string scanId, string fileName, string filePath, ScanReport report, long? fileSizeOverride = null)
    {
        var fileInfo = new FileInfo(filePath);
        var allFindings = report.Modules.SelectMany(m => m.Findings).ToList();

        // Extract risk from artifacts
        RiskScoreDto? risk = null;
        var artifactsDict = new Dictionary<string, object>();

        foreach (var module in report.Modules)
        {
            foreach (var artifact in module.Artifacts)
            {
                if (artifact.Kind == "Risk")
                {
                    // Parse risk from artifact properties
                    if (artifact.Properties.TryGetValue("Level", out var level) &&
                        artifact.Properties.TryGetValue("Score", out var score) &&
                        Enum.TryParse<RiskLevel>(level, out var riskLevel) &&
                        int.TryParse(score, out var riskScore))
                    {
                        var counts = new Dictionary<string, int>
                        {
                            ["critical"] = int.Parse(artifact.Properties.GetValueOrDefault("Critical", "0")),
                            ["high"] = int.Parse(artifact.Properties.GetValueOrDefault("High", "0")),
                            ["medium"] = int.Parse(artifact.Properties.GetValueOrDefault("Medium", "0")),
                            ["low"] = int.Parse(artifact.Properties.GetValueOrDefault("Low", "0")),
                            ["info"] = int.Parse(artifact.Properties.GetValueOrDefault("Info", "0"))
                        };

                        risk = new RiskScoreDto(riskLevel.ToString(), riskScore, counts);
                    }
                }
                else
                {
                    artifactsDict[artifact.Kind.ToLowerInvariant()] = artifact.Properties;
                }
            }
        }

        var findingDtos = allFindings.Select(f => new ScanFindingDto(
            f.RuleId,
            f.Title,
            f.Category,
            f.Severity == ScanSeverity.Informational ? "Info" : f.Severity.ToString(),
            f.Description,
            f.Evidence,
            f.Recommendation,
            f.StandardReference,
            f.Confidence
        )).ToList();

        var errors = report.Modules
            .Where(m => m.Status == ScanStatus.Failed && m.ErrorMessage != null)
            .Select(m => m.ErrorMessage!)
            .ToList();

        return new ScanFileResponse(
            scanId,
            fileName,
            fileSizeOverride ?? (fileInfo.Exists ? fileInfo.Length : 0),
            report.Status.ToString(),
            risk,
            findingDtos,
            artifactsDict,
            errors);
    }
}

/// <summary>Response for archive scan.</summary>
public sealed record ArchiveScanResponse(
    string ScanId,
    string ArchiveName,
    int ExtractedFileCount,
    int ScannedFileCount,
    RiskScoreDto? OverallRisk,
    IReadOnlyList<FileScanDto> Files,
    IReadOnlyList<string> ExtractionErrors,
    string? ErrorMessage)
{
    public static ArchiveScanResponse FromResult(string scanId, string archiveName, Services.ArchiveScanResult result)
    {
        if (!string.IsNullOrEmpty(result.ErrorMessage))
        {
            return new ArchiveScanResponse(
                scanId,
                archiveName,
                0,
                0,
                null,
                Array.Empty<FileScanDto>(),
                Array.Empty<string>(),
                result.ErrorMessage);
        }

        var fileDtos = result.FileReports.Select(fr =>
        {
            var response = ScanFileResponse.FromReport(
                Guid.NewGuid().ToString(),
                Path.GetFileName(fr.RelativePath),
                fr.RelativePath,
                fr.Report,
                fr.FileSize);

            return new FileScanDto(
                fr.RelativePath,
                fr.FileSize,
                response.Status,
                response.Risk,
                response.Findings,
                response.Artifacts,
                fr.Error != null ? new[] { fr.Error } : Array.Empty<string>());
        }).ToList();

        // Calculate overall risk (max level)
        RiskScoreDto? overallRisk = null;
        if (fileDtos.Any(f => f.Risk != null))
        {
            var maxLevel = fileDtos
                .Where(f => f.Risk != null)
                .Select(f => Enum.Parse<RiskLevel>(f.Risk!.Level))
                .Max();

            var totalCounts = new Dictionary<string, int>
            {
                ["critical"] = fileDtos.Sum(f => f.Risk?.Counts.GetValueOrDefault("critical", 0) ?? 0),
                ["high"] = fileDtos.Sum(f => f.Risk?.Counts.GetValueOrDefault("high", 0) ?? 0),
                ["medium"] = fileDtos.Sum(f => f.Risk?.Counts.GetValueOrDefault("medium", 0) ?? 0),
                ["low"] = fileDtos.Sum(f => f.Risk?.Counts.GetValueOrDefault("low", 0) ?? 0),
                ["info"] = fileDtos.Sum(f => f.Risk?.Counts.GetValueOrDefault("info", 0) ?? 0)
            };

            int totalScore = fileDtos.Sum(f => f.Risk?.Score ?? 0);

            overallRisk = new RiskScoreDto(maxLevel.ToString(), totalScore, totalCounts);
        }

        return new ArchiveScanResponse(
            scanId,
            archiveName,
            result.ExtractedFileCount,
            result.ScannedFileCount,
            overallRisk,
            fileDtos,
            result.ExtractionErrors.ToList(),
            null);
    }
}

/// <summary>Risk score DTO.</summary>
public sealed record RiskScoreDto(
    string Level,
    int Score,
    Dictionary<string, int> Counts);

/// <summary>Finding DTO.</summary>
public sealed record ScanFindingDto(
    string RuleId,
    string Title,
    string Category,
    string Severity,
    string Description,
    string? Evidence,
    string? Recommendation,
    string? StandardReference,
    string Confidence = "Medium");

/// <summary>File scan DTO (for archive response).</summary>
public sealed record FileScanDto(
    string RelativePath,
    long FileSize,
    string Status,
    RiskScoreDto? Risk,
    IReadOnlyList<ScanFindingDto> Findings,
    Dictionary<string, object> Artifacts,
    IReadOnlyList<string> Errors);
