using Core.Scanning;
using System.Text.RegularExpressions;

namespace Core.Rules.BuiltIn;

/// <summary>PE-IMP-001/002: Process injection API patterns.</summary>
public sealed class InjectionApisRule : IRule
{
    public string Id => "PE-IMP-001";
    public string Category => "Imports";
    public string Title => "Process injection APIs detected";

    public IEnumerable<ScanFinding> Evaluate(RuleContext context)
    {
        var catalog = context.Options.Catalogs.RiskyApis;
        if (!catalog.Groups.TryGetValue("injection", out var injectionGroup))
            yield break;

        var detectedApis = new List<string>();

        // Check regular imports
        if (context.Image.Imports.IsSuccess)
        {
            foreach (var dll in context.Image.Imports.Libraries)
            {
                foreach (var function in dll.Functions)
                {
                    var funcName = function.DisplayName;
                    if (MatchesApi(funcName, injectionGroup.Apis))
                        detectedApis.Add(funcName);
                }
            }
        }

        // Check delay imports
        foreach (var dll in context.Image.DelayImports)
        {
            foreach (var function in dll.Functions)
            {
                var funcName = function.DisplayName;
                if (MatchesApi(funcName, injectionGroup.Apis))
                    detectedApis.Add($"{funcName} (delay-load)");
            }
        }

        if (detectedApis.Count == 0)
            yield break;

        var severity = detectedApis.Count >= 3 ? ScanSeverity.Critical :
                       detectedApis.Count >= 2 ? ScanSeverity.High : ScanSeverity.Medium;

        yield return new ScanFinding(
            RuleId: severity == ScanSeverity.Critical ? "PE-IMP-001" : "PE-IMP-002",
            Title: Title,
            Category: Category,
            Severity: severity,
            Description: $"Detected {detectedApis.Count} process injection API(s). These APIs can be used to inject code into other processes.",
            Evidence: string.Join(", ", detectedApis.Take(10)),
            Recommendation: "Process injection is a common malware technique. Verify the legitimacy of this binary.",
            StandardReference: "MITRE ATT&CK T1055");
    }

    private static bool MatchesApi(string function, List<string> apis)
    {
        string normalized = Regex.Replace(function, "[AW]$", "", RegexOptions.IgnoreCase);
        return apis.Any(api => string.Equals(api, normalized, StringComparison.OrdinalIgnoreCase));
    }
}

/// <summary>PE-IMP-003: Networking APIs.</summary>
public sealed class NetworkingApisRule : IRule
{
    public string Id => "PE-IMP-003";
    public string Category => "Imports";
    public string Title => "Network communication APIs";

    public IEnumerable<ScanFinding> Evaluate(RuleContext context)
    {
        var catalog = context.Options.Catalogs.RiskyApis;
        if (!catalog.Groups.TryGetValue("networking", out var group))
            yield break;

        var detectedApis = CollectMatchingApis(context, group.Apis);
        if (detectedApis.Count == 0)
            yield break;

        yield return new ScanFinding(
            RuleId: Id,
            Title: Title,
            Category: Category,
            Severity: ScanSeverity.Medium,
            Description: $"Detected {detectedApis.Count} networking API(s). File can communicate over the network.",
            Evidence: string.Join(", ", detectedApis.Take(10)),
            Recommendation: "Networking capabilities can be used for command-and-control or data exfiltration.",
            StandardReference: "MITRE ATT&CK T1071");
    }

    private static List<string> CollectMatchingApis(RuleContext context, List<string> apis)
    {
        var detected = new List<string>();

        if (context.Image.Imports.IsSuccess)
        {
            foreach (var dll in context.Image.Imports.Libraries)
                foreach (var function in dll.Functions)
                {
                    var funcName = function.DisplayName;
                    if (MatchesAnyApi(funcName, apis))
                        detected.Add(funcName);
                }
        }

        foreach (var dll in context.Image.DelayImports)
            foreach (var function in dll.Functions)
            {
                var funcName = function.DisplayName;
                if (MatchesAnyApi(funcName, apis))
                    detected.Add(funcName);
            }

        return detected;
    }

    private static bool MatchesAnyApi(string function, List<string> apis)
    {
        string normalized = Regex.Replace(function, "[AW]$", "", RegexOptions.IgnoreCase);
        return apis.Any(api => string.Equals(api, normalized, StringComparison.OrdinalIgnoreCase));
    }
}

/// <summary>PE-IMP-004: Persistence APIs.</summary>
public sealed class PersistenceApisRule : IRule
{
    public string Id => "PE-IMP-004";
    public string Category => "Imports";
    public string Title => "Persistence mechanism APIs";

    public IEnumerable<ScanFinding> Evaluate(RuleContext context)
    {
        var catalog = context.Options.Catalogs.RiskyApis;
        if (!catalog.Groups.TryGetValue("persistence", out var group))
            yield break;

        var detectedApis = CollectMatchingApis(context, group.Apis);
        if (detectedApis.Count == 0)
            yield break;

        yield return new ScanFinding(
            RuleId: Id,
            Title: Title,
            Category: Category,
            Severity: ScanSeverity.Medium,
            Description: $"Detected {detectedApis.Count} persistence-related API(s). File can establish persistence on the system.",
            Evidence: string.Join(", ", detectedApis.Take(10)),
            Recommendation: "Registry and service APIs can be used for persistence. Review the behavior.",
            StandardReference: "MITRE ATT&CK T1547");
    }

    private static List<string> CollectMatchingApis(RuleContext context, List<string> apis)
    {
        var detected = new List<string>();

        if (context.Image.Imports.IsSuccess)
        {
            foreach (var dll in context.Image.Imports.Libraries)
                foreach (var function in dll.Functions)
                {
                    var funcName = function.DisplayName;
                    if (MatchesAnyApi(funcName, apis))
                        detected.Add(funcName);
                }
        }

        foreach (var dll in context.Image.DelayImports)
            foreach (var function in dll.Functions)
            {
                var funcName = function.DisplayName;
                if (MatchesAnyApi(funcName, apis))
                    detected.Add(funcName);
            }

        return detected;
    }

    private static bool MatchesAnyApi(string function, List<string> apis)
    {
        string normalized = Regex.Replace(function, "[AW]$", "", RegexOptions.IgnoreCase);
        return apis.Any(api => string.Equals(api, normalized, StringComparison.OrdinalIgnoreCase));
    }
}

/// <summary>PE-IMP-005: Anti-debug APIs.</summary>
public sealed class AntiDebugApisRule : IRule
{
    public string Id => "PE-IMP-005";
    public string Category => "Imports";
    public string Title => "Anti-debug APIs detected";

    public IEnumerable<ScanFinding> Evaluate(RuleContext context)
    {
        var catalog = context.Options.Catalogs.RiskyApis;
        if (!catalog.Groups.TryGetValue("antidebug", out var group))
            yield break;

        var detectedApis = CollectMatchingApis(context, group.Apis);
        if (detectedApis.Count == 0)
            yield break;

        var severity = detectedApis.Count >= 3 ? ScanSeverity.Medium : ScanSeverity.Low;

        yield return new ScanFinding(
            RuleId: Id,
            Title: Title,
            Category: Category,
            Severity: severity,
            Description: $"Detected {detectedApis.Count} anti-debug API(s). File may resist debugging and analysis.",
            Evidence: string.Join(", ", detectedApis.Take(10)),
            Recommendation: "Anti-debug techniques are common in malware to evade analysis.",
            StandardReference: "MITRE ATT&CK T1622");
    }

    private static List<string> CollectMatchingApis(RuleContext context, List<string> apis)
    {
        var detected = new List<string>();

        if (context.Image.Imports.IsSuccess)
        {
            foreach (var dll in context.Image.Imports.Libraries)
                foreach (var function in dll.Functions)
                {
                    var funcName = function.DisplayName;
                    if (MatchesAnyApi(funcName, apis))
                        detected.Add(funcName);
                }
        }

        foreach (var dll in context.Image.DelayImports)
            foreach (var function in dll.Functions)
            {
                var funcName = function.DisplayName;
                if (MatchesAnyApi(funcName, apis))
                    detected.Add(funcName);
            }

        return detected;
    }

    private static bool MatchesAnyApi(string function, List<string> apis)
    {
        string normalized = Regex.Replace(function, "[AW]$", "", RegexOptions.IgnoreCase);
        return apis.Any(api => string.Equals(api, normalized, StringComparison.OrdinalIgnoreCase));
    }
}

/// <summary>PE-IMP-006: Dynamic API resolution.</summary>
public sealed class DynamicResolutionRule : IRule
{
    public string Id => "PE-IMP-006";
    public string Category => "Imports";
    public string Title => "Dynamic API resolution";

    public IEnumerable<ScanFinding> Evaluate(RuleContext context)
    {
        bool hasLoadLibrary = false;
        bool hasGetProcAddress = false;

        if (context.Image.Imports.IsSuccess)
        {
            foreach (var dll in context.Image.Imports.Libraries)
            {
                foreach (var function in dll.Functions)
                {
                    var funcName = function.DisplayName;
                    string normalized = Regex.Replace(funcName, "[AW]$", "", RegexOptions.IgnoreCase);

                    if (normalized.Equals("LoadLibrary", StringComparison.OrdinalIgnoreCase) ||
                        normalized.Equals("LdrLoadDll", StringComparison.OrdinalIgnoreCase))
                        hasLoadLibrary = true;

                    if (normalized.Equals("GetProcAddress", StringComparison.OrdinalIgnoreCase) ||
                        normalized.Equals("LdrGetProcedureAddress", StringComparison.OrdinalIgnoreCase))
                        hasGetProcAddress = true;
                }
            }
        }

        if (hasLoadLibrary && hasGetProcAddress)
        {
            yield return new ScanFinding(
                RuleId: Id,
                Title: Title,
                Category: Category,
                Severity: ScanSeverity.Medium,
                Description: "File imports both LoadLibrary and GetProcAddress, enabling dynamic API resolution.",
                Evidence: "LoadLibrary + GetProcAddress pattern detected",
                Recommendation: "Dynamic API resolution can hide malicious functionality from static analysis.",
                StandardReference: null);
        }
    }
}

/// <summary>PE-IMP-010: No imports (packed or unusual).</summary>
public sealed class NoImportsRule : IRule
{
    public string Id => "PE-IMP-010";
    public string Category => "Imports";
    public string Title => "No imports detected";

    public IEnumerable<ScanFinding> Evaluate(RuleContext context)
    {
        // Pure resource DLLs have no code and no imports by design
        if (context.Image.Header.IsDll && context.Image.Sections.Count > 0 &&
            context.Image.Sections.All(s => !s.Flags.HasFlag(Core.Models.SectionFlag.MemExecute)))
        {
            yield break;
        }

        int totalImports = 0;
        if (context.Image.Imports.IsSuccess)
        {
            totalImports = context.Image.Imports.Libraries.Sum(dll => dll.Functions.Count);
        }

        int totalDelayImports = context.Image.DelayImports.Sum(dll => dll.Functions.Count);

        if (totalImports == 0 && totalDelayImports == 0)
        {
            yield return new ScanFinding(
                RuleId: Id,
                Title: Title,
                Category: Category,
                Severity: ScanSeverity.High,
                Description: "The PE file has no import table. This is highly unusual and often indicates packing or manual API resolution.",
                Evidence: "Import directory is empty or missing",
                Recommendation: "Files without imports are suspicious. This may be packed malware.",
                StandardReference: null);
        }
    }
}
