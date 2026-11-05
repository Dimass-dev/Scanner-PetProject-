namespace Core.Scanning;

public enum ScanTargetKind
{
    PeFile,
    WebApplication
}

public enum ScanSeverity
{
    Informational,
    Low,
    Medium,
    High,
    Critical
}

public enum ScanStatus
{
    Succeeded,
    PartiallySucceeded,
    Failed,
    Unsupported
}

/// <summary>A source-neutral target that can be passed to any scan module.</summary>
public sealed record ScanTarget(ScanTargetKind Kind, string Value, string? OpenApiDocument = null, bool EnableLimitedActive = false)
{
    public static ScanTarget ForPeFile(string path) => new(ScanTargetKind.PeFile, path);
    public static ScanTarget ForWebApplication(string url, string? openApiDocument = null, bool enableLimitedActive = false) =>
        new(ScanTargetKind.WebApplication, url, openApiDocument, enableLimitedActive);
}

/// <summary>Common finding contract shared by all present and future scan modules.</summary>
public sealed record ScanFinding(
    string RuleId,
    string Title,
    string Category,
    ScanSeverity Severity,
    string Description,
    string Evidence,
    string Recommendation,
    string? StandardReference = null,
    string Confidence = "Medium");

/// <summary>Module-specific evidence represented with a shared, serializable shape.</summary>
public sealed record ScanArtifact(
    string Kind,
    string Name,
    IReadOnlyDictionary<string, string> Properties);

public sealed record ScanModuleResult(
    string ModuleId,
    ScanStatus Status,
    IReadOnlyList<ScanFinding> Findings,
    IReadOnlyList<ScanArtifact> Artifacts,
    string? ErrorMessage = null)
{
    public static ScanModuleResult Success(
        string moduleId,
        IReadOnlyList<ScanFinding>? findings = null,
        IReadOnlyList<ScanArtifact>? artifacts = null) =>
        new(moduleId, ScanStatus.Succeeded, findings ?? [], artifacts ?? []);

    public static ScanModuleResult Failure(string moduleId, string errorMessage) =>
        new(moduleId, ScanStatus.Failed, [], [], errorMessage);
}

/// <summary>Unified report envelope returned for every scan target.</summary>
public sealed record ScanReport(
    ScanTarget Target,
    IReadOnlyList<ScanModuleResult> Modules)
{
    public ScanStatus Status => Modules.Count == 0
        ? ScanStatus.Unsupported
        : Modules.All(module => module.Status == ScanStatus.Succeeded)
            ? ScanStatus.Succeeded
            : Modules.Any(module => module.Status == ScanStatus.Succeeded)
                ? ScanStatus.PartiallySucceeded
                : ScanStatus.Failed;

    public IReadOnlyList<ScanFinding> Findings => Modules.SelectMany(module => module.Findings).ToArray();
    public IReadOnlyList<ScanArtifact> Artifacts => Modules.SelectMany(module => module.Artifacts).ToArray();
}
