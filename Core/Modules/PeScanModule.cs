using System.Text.Json;
using Core.Analysis;
using Core.Rules;
using Core.Rules.BuiltIn;
using Core.Scanning;

namespace Core.Modules;

/// <summary>
/// PE scan module that uses the new PeImageParser and rule-based analysis.
/// </summary>
public sealed class PeScanModule : IScanModule
{
    private const int MaximumArtifactValueLength = 512;

    private readonly PeImageParser _parser;
    private readonly RuleEngine _ruleEngine;
    private readonly Risk.RiskAssessmentEngine _riskEngine;
    private readonly RuleOptions _ruleOptions;

    public string ModuleId => "pe-static-analysis";
    public bool Supports(ScanTargetKind targetKind) => targetKind == ScanTargetKind.PeFile;

    public PeScanModule(
        PeImageParser parser,
        RuleEngine ruleEngine,
        Risk.RiskAssessmentEngine riskEngine,
        RuleOptions ruleOptions)
    {
        _parser = parser;
        _ruleEngine = ruleEngine;
        _riskEngine = riskEngine;
        _ruleOptions = ruleOptions;
    }

    public async Task<ScanModuleResult> ScanAsync(ScanTarget target, CancellationToken cancellationToken = default)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!Supports(target.Kind))
            {
                return ScanModuleResult.Failure(ModuleId, "This module only accepts PE file targets.");
            }

            // Parse PE file on a worker thread; the parser is synchronous and checks the token.
            var parseResult = await Task.Run(
                () => _parser.Parse(target.Value, cancellationToken),
                cancellationToken).ConfigureAwait(false);

            if (!parseResult.IsSuccess || parseResult.Value == null)
            {
                return ScanModuleResult.Failure(ModuleId, parseResult.ErrorMessage ?? "Failed to parse PE file");
            }

            cancellationToken.ThrowIfCancellationRequested();
            var image = parseResult.Value;

            // Evaluate rules
            var context = new RuleContext(image, _ruleOptions);
            var findings = _ruleEngine.Evaluate(context);

            cancellationToken.ThrowIfCancellationRequested();

            // Assess risk
            var risk = _riskEngine.Assess(findings);

            // Build artifacts
            var artifacts = BuildArtifacts(image, risk);

            return ScanModuleResult.Success(ModuleId, findings, artifacts);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            return ScanModuleResult.Failure(ModuleId, $"Scan error: {ex.Message}");
        }
    }

    private List<ScanArtifact> BuildArtifacts(PeImage image, Risk.RiskScore risk)
    {
        var artifacts = new List<ScanArtifact>();

        // Header artifact
        var headerProps = new Dictionary<string, string>
        {
            ["Architecture"] = image.Header.Architecture,
            ["Subsystem"] = image.Header.SubsystemName,
            ["IsDll"] = image.Header.IsDll.ToString(),
            ["EntryPoint"] = $"0x{image.Header.AddressOfEntryPoint:X}",
            ["FileSize"] = $"{image.FileSize:N0} bytes",
            ["Timestamp"] = FormatTimestamp(image.Header.TimeDateStamp)
        };
        artifacts.Add(new ScanArtifact("Header", "PE Header", headerProps));

        // Mitigations artifact
        var mitigationProps = new Dictionary<string, string>
        {
            ["ASLR"] = image.Header.HasASLR.ToString(),
            ["DEP"] = image.Header.HasDEP.ToString(),
            ["CFG"] = image.Header.HasControlFlowGuard.ToString(),
            ["HighEntropyVA"] = image.Header.HasHighEntropyVA.ToString(),
            ["SafeSEH"] = image.LoadConfig?.HasSEH.ToString() ?? "N/A"
        };
        artifacts.Add(new ScanArtifact("Mitigations", "Security Mitigations", mitigationProps));

        // Sections artifact
        var sectionsProps = new Dictionary<string, string>
        {
            ["Count"] = image.Sections.Count.ToString(),
            ["Sections"] = Limit(string.Join(", ", image.Sections.Select(s => s.Name))) ?? string.Empty
        };
        artifacts.Add(new ScanArtifact("Sections", $"{image.Sections.Count} Section(s)", sectionsProps));

        // Imports artifact
        var importList = image.Imports.IsSuccess ? image.Imports.Libraries : Array.Empty<Models.ImportDLL.ImportedDLL>();
        var importCount = importList.Sum(dll => dll.Functions.Count);
        var importProps = new Dictionary<string, string>
        {
            ["DllCount"] = importList.Count.ToString(),
            ["FunctionCount"] = importCount.ToString(),
            ["DLLs"] = Limit(string.Join(", ", importList.Take(5).Select(dll => dll.DLLName))) ?? string.Empty
        };
        artifacts.Add(new ScanArtifact("Imports", $"{importCount} Import(s)", importProps));

        // Signature artifact
        var sigProps = new Dictionary<string, string>
        {
            ["State"] = image.Signature.State.ToString(),
            ["Subject"] = Limit(image.Signature.SubjectName) ?? "N/A",
            ["Issuer"] = Limit(image.Signature.IssuerName) ?? "N/A"
        };
        artifacts.Add(new ScanArtifact("Signature", "Code Signature", sigProps));

        // Risk artifact
        var riskProps = new Dictionary<string, string>
        {
            ["Level"] = risk.Level.ToString(),
            ["Score"] = risk.Score.ToString(),
            ["Critical"] = risk.Counts[ScanSeverity.Critical].ToString(),
            ["High"] = risk.Counts[ScanSeverity.High].ToString(),
            ["Medium"] = risk.Counts[ScanSeverity.Medium].ToString(),
            ["Low"] = risk.Counts[ScanSeverity.Low].ToString(),
            ["Info"] = risk.Counts[ScanSeverity.Informational].ToString()
        };
        artifacts.Add(new ScanArtifact("Risk", $"Risk: {risk.Level}", riskProps));

        return artifacts;
    }

    private static string? Limit(string? value)
    {
        if (value is null)
        {
            return null;
        }

        return value.Length <= MaximumArtifactValueLength
            ? value
            : value[..MaximumArtifactValueLength] + "...";
    }

    private string FormatTimestamp(uint timestamp)
    {
        if (timestamp == 0)
        {
            return "0 (null)";
        }

        try
        {
            var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var time = epoch.AddSeconds(timestamp);
            return time.ToString("yyyy-MM-dd HH:mm:ss") + " UTC";
        }
        catch
        {
            return timestamp.ToString();
        }
    }

    /// <summary>Resolve path to a catalog file across multiple standard locations.</summary>
    private static string? ResolveCatalogFile(string fileName, string? customBasePath)
    {
        if (!string.IsNullOrWhiteSpace(customBasePath))
        {
            string candidate = Path.Combine(customBasePath, fileName);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        string baseDir = AppContext.BaseDirectory;
        string[] candidates =
        [
            Path.Combine(baseDir, "Rules", "catalogs", fileName),
            Path.Combine(baseDir, "catalogs", fileName),
            Path.Combine(baseDir, fileName)
        ];

        foreach (string candidate in candidates)
        {
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        // Search upward in development workspaces
        var currentDir = new DirectoryInfo(baseDir);
        for (int depth = 0; depth < 6 && currentDir != null; depth++)
        {
            string candidate = Path.Combine(currentDir.FullName, "Core", "Rules", "catalogs", fileName);
            if (File.Exists(candidate))
            {
                return candidate;
            }

            candidate = Path.Combine(currentDir.FullName, "Rules", "catalogs", fileName);
            if (File.Exists(candidate))
            {
                return candidate;
            }

            currentDir = currentDir.Parent;
        }

        return null;
    }

    /// <summary>Load rule catalogs from JSON files or embedded resources.</summary>
    public static RuleOptions LoadRuleOptions(string? catalogBasePath = null)
    {
        var options = new RuleOptions();
        var jsonOptions = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };

        try
        {
            // Load thresholds
            string? thresholdsPath = ResolveCatalogFile("thresholds.json", catalogBasePath);
            if (thresholdsPath != null && File.Exists(thresholdsPath))
            {
                string json = File.ReadAllText(thresholdsPath);
                var thresholdsData = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json, jsonOptions);

                if (thresholdsData != null)
                {
                    double highEntropy = 7.2;
                    double mediumEntropy = 6.8;
                    long overlayBytes = 65536;
                    double overlayPercent = 0.05;

                    if (thresholdsData.TryGetValue("entropy", out var entropySection))
                    {
                        if (entropySection.TryGetProperty("highThreshold", out var highProp))
                        {
                            highEntropy = highProp.GetDouble();
                        }

                        if (entropySection.TryGetProperty("mediumThreshold", out var medProp))
                        {
                            mediumEntropy = medProp.GetDouble();
                        }
                    }

                    if (thresholdsData.TryGetValue("overlay", out var overlaySection))
                    {
                        if (overlaySection.TryGetProperty("sizeBytes", out var sizeProp))
                        {
                            overlayBytes = sizeProp.GetInt64();
                        }

                        if (overlaySection.TryGetProperty("percentageOfFile", out var pctProp))
                        {
                            overlayPercent = pctProp.GetDouble();
                        }
                    }

                    options.Thresholds = new RuleThresholds
                    {
                        HighEntropyThreshold = highEntropy,
                        MediumEntropyThreshold = mediumEntropy,
                        OverlaySizeThreshold = overlayBytes,
                        OverlayPercentageThreshold = overlayPercent
                    };
                }
            }

            // Load risky APIs (case-insensitive for proper object mapping)
            string? apisPath = ResolveCatalogFile("risky-apis.json", catalogBasePath);
            if (apisPath != null && File.Exists(apisPath))
            {
                string json = File.ReadAllText(apisPath);
                var catalog = JsonSerializer.Deserialize<RiskyApiCatalog>(json, jsonOptions);
                if (catalog != null)
                {
                    options.Catalogs.RiskyApis = catalog;
                }
            }

            // Load section names (case-insensitive for proper object mapping)
            string? sectionsPath = ResolveCatalogFile("section-names.json", catalogBasePath);
            if (sectionsPath != null && File.Exists(sectionsPath))
            {
                string json = File.ReadAllText(sectionsPath);
                var catalog = JsonSerializer.Deserialize<SuspiciousSectionNamesCatalog>(json, jsonOptions);
                if (catalog != null)
                {
                    options.Catalogs.SectionNames = catalog;
                }
            }
        }
        catch
        {
            // Use defaults if loading fails
        }

        return options;
    }

    /// <summary>Create a PeScanModule with all built-in rules.</summary>
    public static PeScanModule CreateDefault(string? catalogBasePath = null)
    {
        var headerParser = new PE.HeaderParser();
        var sectionParser = new Sections.SectionParser();
        var loadConfigParser = new Parsing.LoadConfigParser();
        var delayImportParser = new Parsing.DelayImportParser();
        var entropyScanner = new Parsing.EntropyScanner();
        var overlayScanner = new Parsing.OverlayScanner();
        var certificateParser = new Parsing.CertificateParser();
        var importedParser = new ImpParser.ImportedParser();

        var peImageParser = new PeImageParser(
            headerParser,
            sectionParser,
            loadConfigParser,
            delayImportParser,
            entropyScanner,
            overlayScanner,
            certificateParser,
            importedParser);

        var rules = new List<IRule>
        {
            // Mitigations
            new MissingAslrRule(),
            new MissingDepRule(),
            new MissingCfgRule(),
            new MissingSafeSehRule(),
            new MissingHighEntropyVaRule(),
            new CfgMismatchRule(),

            // Sections
            new WritableExecutableSectionRule(),
            new SuspiciousEntryPointRule(),
            new SuspiciousSectionNameRule(),
            new HighEntropySectionRule(),
            new OverlayRule(),

            // Imports
            new InjectionApisRule(),
            new NetworkingApisRule(),
            new PersistenceApisRule(),
            new AntiDebugApisRule(),
            new DynamicResolutionRule(),
            new NoImportsRule(),

            // Header
            new UnusualSubsystemRule(),
            new SuspiciousTimestampRule(),
            new InvalidChecksumRule(),
            new InvalidSignatureRule(),
            new UntrustedSignatureRule(),
            new UnsignedBinaryRule()
        };

        var ruleOptions = LoadRuleOptions(catalogBasePath);
        var ruleEngine = new RuleEngine(rules);
        var riskEngine = new Risk.RiskAssessmentEngine();

        return new PeScanModule(peImageParser, ruleEngine, riskEngine, ruleOptions);
    }
}
