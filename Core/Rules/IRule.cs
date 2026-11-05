namespace Core.Rules;

/// <summary>
/// Represents a security rule that evaluates a PE file for suspicious patterns.
/// </summary>
public interface IRule
{
    /// <summary>Unique rule identifier (e.g., "PE-MIT-001").</summary>
    string Id { get; }

    /// <summary>Rule category (e.g., "Mitigations", "Imports", "Sections").</summary>
    string Category { get; }

    /// <summary>Short human-readable title.</summary>
    string Title { get; }

    /// <summary>Evaluate the rule against a PE image.</summary>
    IEnumerable<Scanning.ScanFinding> Evaluate(RuleContext context);
}

/// <summary>
/// Context provided to rules during evaluation.
/// </summary>
public sealed record RuleContext(
    Analysis.PeImage Image,
    RuleOptions Options);

/// <summary>
/// Configuration options for rule evaluation.
/// </summary>
public sealed class RuleOptions
{
    /// <summary>JSON catalogs for risky APIs, section names, etc.</summary>
    public RuleCatalogs Catalogs { get; init; } = new();

    /// <summary>Thresholds for entropy, overlay size, etc.</summary>
    public RuleThresholds Thresholds { get; set; } = new();
}

/// <summary>
/// Rule catalogs loaded from JSON.
/// </summary>
public sealed class RuleCatalogs
{
    public RiskyApiCatalog RiskyApis { get; set; } = new();
    public SuspiciousSectionNamesCatalog SectionNames { get; set; } = new();
}

/// <summary>
/// Configurable thresholds for rules.
/// </summary>
public sealed class RuleThresholds
{
    public double HighEntropyThreshold { get; init; } = 7.2;
    public double MediumEntropyThreshold { get; init; } = 6.8;
    public long OverlaySizeThreshold { get; init; } = 65536; // 64 KB
    public double OverlayPercentageThreshold { get; init; } = 0.05; // 5%
}

/// <summary>
/// Catalog of risky Windows APIs grouped by category.
/// </summary>
public sealed class RiskyApiCatalog
{
    public Dictionary<string, ApiGroup> Groups { get; init; } = new();
}

public sealed class ApiGroup
{
    public string Name { get; init; } = "";
    public List<string> Apis { get; init; } = new();
    public string Severity { get; init; } = "Medium";
}

/// <summary>
/// Catalog of suspicious section names (packers, obfuscators).
/// </summary>
public sealed class SuspiciousSectionNamesCatalog
{
    public Dictionary<string, SectionPattern> Patterns { get; init; } = new();
}

public sealed class SectionPattern
{
    public string Pattern { get; init; } = "";
    public string Description { get; init; } = "";
    public string Severity { get; init; } = "High";
}
