using Core.Analysis;
using Core.ImpParser;
using Core.Models;
using Core.Models.ImportDLL;
using Core.Risk;
using Core.Rules;
using Core.Rules.BuiltIn;
using Core.Scanning;
using Xunit;

namespace Scanner.Tests;

public sealed class RuleAndRiskTests
{
    [Fact]
    public void RiskAssessment_NoFindings_IsInfo()
    {
        var score = new RiskAssessmentEngine().Assess(Array.Empty<ScanFinding>());
        Assert.Equal(RiskLevel.Info, score.Level);
        Assert.Equal(0, score.Score);
    }

    [Fact]
    public void RiskAssessment_MediumFinding_IsMedium()
    {
        var score = new RiskAssessmentEngine().Assess(new[] { Finding(ScanSeverity.Medium) });
        Assert.Equal(RiskLevel.Medium, score.Level);
        Assert.Equal(5, score.Score);
        Assert.Equal(1, score.Counts[ScanSeverity.Medium]);
    }

    [Fact]
    public void RiskAssessment_TwoHighFindings_EscalateToHigh()
    {
        var score = new RiskAssessmentEngine().Assess(new[]
        {
            Finding(ScanSeverity.High),
            Finding(ScanSeverity.High)
        });

        Assert.Equal(RiskLevel.High, score.Level);
        Assert.Equal(30, score.Score);
        Assert.Equal(2, score.Counts[ScanSeverity.High]);
    }

    [Fact]
    public void RiskAssessment_CriticalFinding_WinsEvenWithLowScore()
    {
        var score = new RiskAssessmentEngine().Assess(new[]
        {
            Finding(ScanSeverity.Critical),
            Finding(ScanSeverity.Informational)
        });

        Assert.Equal(RiskLevel.Critical, score.Level);
        Assert.Equal(50, score.Score);
        Assert.Equal(1, score.Counts[ScanSeverity.Critical]);
    }

    [Fact]
    public void RiskAssessment_InformationalOnly_RemainsInfo()
    {
        var score = new RiskAssessmentEngine().Assess(new[] { Finding(ScanSeverity.Informational) });
        Assert.Equal(RiskLevel.Info, score.Level);
        Assert.Equal(0, score.Score);
    }

    [Fact]
    public void RuleEngine_RuleThrows_ProducesSystemFindingAndContinues()
    {
        var engine = new RuleEngine(new IRule[]
        {
            new ThrowingRule(),
            new FixedRule()
        });

        var findings = engine.Evaluate(CreateContext(CreateImage()));

        Assert.Contains(findings, finding => finding.RuleId == "THROW-ERROR" && finding.Category == "System");
        Assert.Contains(findings, finding => finding.RuleId == "FIXED");
    }

    [Fact]
    public void WritableExecutableSection_ProducesCriticalFinding()
    {
        var image = CreateImage(sections: new[]
        {
            Section(".text", SectionFlag.MemWrite | SectionFlag.MemExecute)
        });

        var findings = new WritableExecutableSectionRule()
            .Evaluate(CreateContext(image))
            .ToArray();

        var finding = Assert.Single(findings);
        Assert.Equal(ScanSeverity.Critical, finding.Severity);
        Assert.Contains(".text", finding.Evidence);
    }

    [Fact]
    public void EntryPointOutsideSections_ProducesHighFinding()
    {
        var image = CreateImage(
            header: new HPInfo { AddressOfEntryPoint = 0x9999 },
            sections: new[] { Section(".text", SectionFlag.MemExecute) });

        var findings = new SuspiciousEntryPointRule()
            .Evaluate(CreateContext(image))
            .ToArray();

        var finding = Assert.Single(findings);
        Assert.Equal(ScanSeverity.High, finding.Severity);
        Assert.Contains("outside", finding.Title, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void EntryPointInWritableSection_ProducesHighFinding()
    {
        var image = CreateImage(
            header: new HPInfo { AddressOfEntryPoint = 0x1010 },
            sections: new[] { Section(".data", SectionFlag.MemWrite | SectionFlag.MemExecute) });

        var findings = new SuspiciousEntryPointRule()
            .Evaluate(CreateContext(image))
            .ToArray();

        Assert.Contains(findings, finding => finding.Severity == ScanSeverity.High);
        Assert.Contains(findings, finding => finding.Title.Contains("writable", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void InjectionApis_TwoMatches_ProducesHighFinding()
    {
        var image = CreateImage(imports: new[]
        {
            Dll("kernel32.dll", "VirtualAllocEx", "WriteProcessMemory", "CreateFileW")
        });

        var findings = new InjectionApisRule()
            .Evaluate(CreateContext(image, CreateRiskyApiCatalog()))
            .ToArray();

        var finding = Assert.Single(findings);
        Assert.Equal(ScanSeverity.High, finding.Severity);
        Assert.Contains("VirtualAllocEx", finding.Evidence);
        Assert.Contains("WriteProcessMemory", finding.Evidence);
    }

    [Fact]
    public void InjectionApis_ThreeMatches_ProducesCriticalFinding()
    {
        var image = CreateImage(imports: new[]
        {
            Dll("kernel32.dll", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread")
        });

        var findings = new InjectionApisRule()
            .Evaluate(CreateContext(image, CreateRiskyApiCatalog()))
            .ToArray();

        Assert.Equal(ScanSeverity.Critical, Assert.Single(findings).Severity);
    }

    [Fact]
    public void UnsignedBinary_ProducesLowFinding()
    {
        var image = CreateImage(signature: new CertificateInfo(
            SignatureState.Unsigned, null, null, null, null, null, Array.Empty<string>()));

        var findings = new UnsignedBinaryRule()
            .Evaluate(CreateContext(image))
            .ToArray();

        Assert.Equal(ScanSeverity.Low, Assert.Single(findings).Severity);
    }

    private static ScanFinding Finding(ScanSeverity severity) => new(
        RuleId: "TEST",
        Title: "Test finding",
        Category: "Test",
        Severity: severity,
        Description: "Test",
        Evidence: string.Empty,
        Recommendation: string.Empty,
        StandardReference: null);

    private static RuleContext CreateContext(PeImage image, RiskyApiCatalog? catalog = null) => new(
        image,
        new RuleOptions
        {
            Catalogs = new RuleCatalogs
            {
                RiskyApis = catalog ?? new RiskyApiCatalog()
            }
        });

    private static RiskyApiCatalog CreateRiskyApiCatalog() => new()
    {
        Groups = new Dictionary<string, ApiGroup>
        {
            ["injection"] = new()
            {
                Name = "Injection",
                Severity = "Critical",
                Apis = new List<string> { "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread" }
            }
        }
    };

    private static PeImage CreateImage(
        HPInfo? header = null,
        IReadOnlyList<SingleSectionInfo>? sections = null,
        IReadOnlyList<ImportedDLL>? imports = null,
        CertificateInfo? signature = null) => new(
        Path: "synthetic.exe",
        FileSize: 4096,
        Header: header ?? new HPInfo
        {
            Architecture = "x64",
            Subsystem = 3,
            SubsystemName = "Console",
            HasASLR = true,
            HasDEP = true,
            HasHighEntropyVA = true,
            HasControlFlowGuard = true
        },
        Sections: sections ?? Array.Empty<SingleSectionInfo>(),
        Entropy: Array.Empty<SectionEntropy>(),
        Imports: ImportParseResult.Success(imports ?? Array.Empty<ImportedDLL>()),
        DelayImports: Array.Empty<ImportedDLL>(),
        LoadConfig: null,
        Signature: signature ?? new CertificateInfo(
            SignatureState.Unsigned, null, null, null, null, null, Array.Empty<string>()),
        Overlay: new OverlayInfo(0, 0, 0));

    private static SingleSectionInfo Section(string name, SectionFlag flags) => new()
    {
        SectionName = name,
        VirtualAddress = 0x1000,
        VirtualSize = 0x200,
        SizeOfRawData = 0x200,
        PointerToRawData = 0x200,
        Characteristics = flags
    };

    private static ImportedDLL Dll(string name, params string[] functions) =>
        new(name, functions);

    private sealed class ThrowingRule : IRule
    {
        public string Id => "THROW";
        public string Category => "Test";
        public string Title => "Throwing rule";

        public IEnumerable<ScanFinding> Evaluate(RuleContext context) =>
            throw new InvalidOperationException("boom");
    }

    private sealed class FixedRule : IRule
    {
        public string Id => "FIXED";
        public string Category => "Test";
        public string Title => "Fixed rule";

        public IEnumerable<ScanFinding> Evaluate(RuleContext context) =>
            new[] { Finding(ScanSeverity.Informational) with { RuleId = "FIXED" } };
    }
}
