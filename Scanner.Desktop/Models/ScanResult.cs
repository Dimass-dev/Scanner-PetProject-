using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Scanner.Desktop.Models;

/// <summary>Mirrors the response of POST /api/scan/file.</summary>
public class ScanResult
{
    [JsonPropertyName("scanId")]
    public string ScanId { get; set; } = string.Empty;

    [JsonPropertyName("fileName")]
    public string FileName { get; set; } = string.Empty;

    [JsonPropertyName("fileSize")]
    public long FileSize { get; set; }

    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;

    [JsonPropertyName("risk")]
    public RiskScore? Risk { get; set; }

    [JsonPropertyName("findings")]
    public List<Finding> Findings { get; set; } = new();

    [JsonPropertyName("artifacts")]
    public Dictionary<string, JsonElement> Artifacts { get; set; } = new();

    [JsonPropertyName("errors")]
    public List<string> Errors { get; set; } = new();

    [JsonIgnore]
    public string RiskLevel => Risk?.Level ?? string.Empty;

    [JsonIgnore]
    public int TotalScore => Risk?.Score ?? 0;

    [JsonIgnore]
    public Mitigations? Mitigations => ArtifactReader.ReadMitigations(Artifacts);
}

/// <summary>Mirrors the response of POST /api/scan/archive.</summary>
public class ArchiveScanResult
{
    [JsonPropertyName("scanId")]
    public string ScanId { get; set; } = string.Empty;

    [JsonPropertyName("archiveName")]
    public string ArchiveName { get; set; } = string.Empty;

    [JsonPropertyName("extractedFileCount")]
    public int ExtractedFileCount { get; set; }

    [JsonPropertyName("scannedFileCount")]
    public int ScannedFileCount { get; set; }

    [JsonPropertyName("overallRisk")]
    public RiskScore? OverallRisk { get; set; }

    [JsonPropertyName("files")]
    public List<ArchiveFileResult> Results { get; set; } = new();

    [JsonPropertyName("extractionErrors")]
    public List<string> ExtractionErrors { get; set; } = new();

    [JsonPropertyName("errorMessage")]
    public string? ErrorMessage { get; set; }

    [JsonIgnore]
    public int TotalFiles => ExtractedFileCount;

    [JsonIgnore]
    public int ScannedFiles => ScannedFileCount;
}

/// <summary>A PE file reported inside an archive scan response.</summary>
public class ArchiveFileResult
{
    [JsonPropertyName("relativePath")]
    public string RelativePath { get; set; } = string.Empty;

    [JsonPropertyName("fileSize")]
    public long FileSize { get; set; }

    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;

    [JsonPropertyName("risk")]
    public RiskScore? Risk { get; set; }

    [JsonPropertyName("findings")]
    public List<Finding> Findings { get; set; } = new();

    [JsonPropertyName("artifacts")]
    public Dictionary<string, JsonElement> Artifacts { get; set; } = new();

    [JsonPropertyName("errors")]
    public List<string> Errors { get; set; } = new();

    [JsonIgnore]
    public string FileName => Path.GetFileName(RelativePath);

    [JsonIgnore]
    public string RiskLevel => Risk?.Level ?? string.Empty;

    [JsonIgnore]
    public int TotalScore => Risk?.Score ?? 0;

    [JsonIgnore]
    public Mitigations? Mitigations => ArtifactReader.ReadMitigations(Artifacts);
}

public class RiskScore
{
    [JsonPropertyName("level")]
    public string Level { get; set; } = string.Empty;

    [JsonPropertyName("score")]
    public int Score { get; set; }

    [JsonPropertyName("counts")]
    public Dictionary<string, int> Counts { get; set; } = new();
}

public class Finding
{
    [JsonPropertyName("ruleId")]
    public string RuleId { get; set; } = string.Empty;

    [JsonPropertyName("title")]
    public string Title { get; set; } = string.Empty;

    [JsonPropertyName("category")]
    public string Category { get; set; } = string.Empty;

    [JsonPropertyName("severity")]
    public string Severity { get; set; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;

    [JsonPropertyName("evidence")]
    public string? Evidence { get; set; }

    [JsonPropertyName("recommendation")]
    public string? Recommendation { get; set; }

    [JsonPropertyName("standardReference")]
    public string? StandardReference { get; set; }

    [JsonPropertyName("confidence")]
    public string Confidence { get; set; } = "Medium";

    [JsonIgnore]
    public string Message => Title;

    [JsonIgnore]
    public string? Details
    {
        get
        {
            var parts = new List<string>();
            if (!string.IsNullOrWhiteSpace(Description))
            {
                parts.Add(Description);
            }

            if (!string.IsNullOrWhiteSpace(Evidence))
            {
                parts.Add($"Evidence: {Evidence}");
            }

            if (!string.IsNullOrWhiteSpace(Recommendation))
            {
                parts.Add($"Recommendation: {Recommendation}");
            }

            return parts.Count == 0 ? null : string.Join(" ", parts);
        }
    }

    [JsonIgnore]
    public int Score => 0;
}

public class Mitigations
{
    public bool Aslr { get; set; }
    public bool Dep { get; set; }
    public bool Cfg { get; set; }
    public bool SafeSeh { get; set; }
    public bool HighEntropyVa { get; set; }
}

internal static class ArtifactReader
{
    public static Mitigations? ReadMitigations(Dictionary<string, JsonElement>? artifacts)
    {
        if (artifacts is null ||
            !artifacts.TryGetValue("mitigations", out JsonElement element) ||
            element.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        return new Mitigations
        {
            Aslr = ReadBool(element, "ASLR"),
            Dep = ReadBool(element, "DEP"),
            Cfg = ReadBool(element, "CFG"),
            SafeSeh = ReadBool(element, "SafeSEH"),
            HighEntropyVa = ReadBool(element, "HighEntropyVA")
        };
    }

    private static bool ReadBool(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out JsonElement value))
        {
            return false;
        }

        return value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.String => bool.TryParse(value.GetString(), out bool parsed) && parsed,
            _ => false
        };
    }
}
