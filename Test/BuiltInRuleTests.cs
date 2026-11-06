using Core.Analysis;
using Core.ImpParser;
using Core.Models;
using Core.Models.ImportDLL;
using Core.Rules;
using Core.Rules.BuiltIn;
using Core.Scanning;
using Xunit;

namespace Scanner.Tests;

/// <summary>
/// Direct behavior tests for the built-in rules not covered by RuleAndRiskTests.
/// Images are built in memory; no file fixtures required.
/// </summary>
public sealed class BuiltInRuleTests
{
    // --- Mitigations -------------------------------------------------------

    [Fact]
    public void MissingAslr_Exe_ProducesHighFinding()
    {
        var image = CreateImage(header: Header(HasASLR: false));
        var finding = Assert.Single(new MissingAslrRule().Evaluate(Ctx(image)));
        Assert.Equal(ScanSeverity.High, finding.Severity);
        Assert.Contains("DYNAMIC_BASE", finding.Evidence);
    }

    [Fact]
    public void MissingAslr_Dll_ProducesMediumFinding()
    {
        var image = CreateImage(header: Header(HasASLR: false, isDll: true));
        var finding = Assert.Single(new MissingAslrRule().Evaluate(Ctx(image)));
        Assert.Equal(ScanSeverity.Medium, finding.Severity);
    }

    [Fact]
    public void MissingDep_ProducesHighFinding()
    {
        var image = CreateImage(header: Header(HasDEP: false));
        var finding = Assert.Single(new MissingDepRule().Evaluate(Ctx(image)));
        Assert.Equal(ScanSeverity.High, finding.Severity);
        Assert.Contains("NX_COMPAT", finding.Evidence);
    }

    [Fact]
    public void MissingCfg_ProducesLowFinding()
    {
        var image = CreateImage(header: Header(HasControlFlowGuard: false));
        var finding = Assert.Single(new MissingCfgRule().Evaluate(Ctx(image)));
        Assert.Equal(ScanSeverity.Low, finding.Severity);
    }

    [Fact]
    public void MissingSafeSeh_X86WithoutLoadConfig_ProducesMediumFinding()
    {
        var image = CreateImage(header: Header(architecture: "x86"));
        var finding = Assert.Single(new MissingSafeSehRule().Evaluate(Ctx(image)));
        Assert.Equal(ScanSeverity.Medium, finding.Severity);
    }

    [Fact]
    public void MissingSafeSeh_X64_ProducesNoFinding()
    {
        var image = CreateImage(header: Header(architecture: "x64"));
        Assert.Empty(new MissingSafeSehRule().Evaluate(Ctx(image)));
    }

    [Fact]
    public void MissingSafeSeh_SehPresent_ProducesNoFinding()
    {
        var header = Header(architecture: "x86");
        var image = CreateImage(header: header, loadConfig: LoadConfig(hasSEH: true));
        Assert.Empty(new MissingSafeSehRule().Evaluate(Ctx(image)));
    }

    [Fact]
    public void MissingHighEntropyVa_X64_ProducesLowFinding()
    {
        var image = CreateImage(header: Header(HasHighEntropyVA: false));
        var finding = Assert.Single(new MissingHighEntropyVaRule().Evaluate(Ctx(image)));
        Assert.Equal(ScanSeverity.Low, finding.Severity);
    }

    [Fact]
    public void CfgMismatch_FlagWithoutInstrumentation_ProducesInformational()
    {
        var image = CreateImage(
            header: Header(HasControlFlowGuard: true),
            loadConfig: LoadConfig(isCFInstrumented: false));
        var finding = Assert.Single(new CfgMismatchRule().Evaluate(Ctx(image)));
        Assert.Equal(ScanSeverity.Informational, finding.Severity);
    }

    [Fact]
    public void CfgMismatch_ProperlyInstrumented_ProducesNoFinding()
    {
        var image = CreateImage(
            header: Header(HasControlFlowGuard: true),
            loadConfig: LoadConfig(isCFInstrumented: true));
        Assert.Empty(new CfgMismatchRule().Evaluate(Ctx(image)));
    }

    // --- Header ------------------------------------------------------------

    [Theory]
    [InlineData(1u)]          // Native
    [InlineData(10u)]         // EFI application
    public void UnusualSubsystem_ProducesMediumFinding(uint subsystem)
    {
        var image = CreateImage(header: Header(subsystem: subsystem));
        var finding = Assert.Single(new UnusualSubsystemRule().Evaluate(Ctx(image)));
        Assert.Equal(ScanSeverity.Medium, finding.Severity);
        Assert.Equal("PE-HDR-001", finding.RuleId);
    }

    [Theory]
    [InlineData(2u)]          // GUI
    [InlineData(3u)]          // Console
    [InlineData(5u)]          // OS/2 — out of the unusual set
    public void UnusualSubsystem_StandardValue_ProducesNoFinding(uint subsystem)
    {
        var image = CreateImage(header: Header(subsystem: subsystem));
        Assert.Empty(new UnusualSubsystemRule().Evaluate(Ctx(image)));
    }

    [Fact]
    public void SuspiciousTimestamp_Zero_ProducesNullTimestampFinding()
    {
        var image = CreateImage(header: Header(timeDateStamp: 0));
        var finding = Assert.Single(new SuspiciousTimestampRule().Evaluate(Ctx(image)));
        Assert.Equal(ScanSeverity.Low, finding.Severity);
        Assert.Contains("Null", finding.Title);
    }

    [Fact]
    public void SuspiciousTimestamp_Future_ProducesFutureTimestampFinding()
    {
        long future = (long)(DateTime.UtcNow.AddYears(2) - DateTime.UnixEpoch).TotalSeconds;
        var image = CreateImage(header: Header(timeDateStamp: unchecked((uint)future)));
        var finding = Assert.Single(new SuspiciousTimestampRule().Evaluate(Ctx(image)));
        Assert.Contains("Future", finding.Title);
    }

    [Fact]
    public void SuspiciousTimestamp_PlausiblePast_ProducesNoFinding()
    {
        long past = (long)(new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc) - DateTime.UnixEpoch).TotalSeconds;
        var image = CreateImage(header: Header(timeDateStamp: unchecked((uint)past)));
        Assert.Empty(new SuspiciousTimestampRule().Evaluate(Ctx(image)));
    }

    [Fact]
    public void InvalidChecksum_NativeDriverWithZero_ProducesLowFinding()
    {
        var image = CreateImage(header: Header(subsystem: 1, checkSum: 0));
        var finding = Assert.Single(new InvalidChecksumRule().Evaluate(Ctx(image)));
        Assert.Equal(ScanSeverity.Low, finding.Severity);
    }

    [Fact]
    public void InvalidChecksum_GuiWithZero_ProducesNoFinding()
    {
        var image = CreateImage(header: Header(subsystem: 3, checkSum: 0));
        Assert.Empty(new InvalidChecksumRule().Evaluate(Ctx(image)));
    }

    // --- Signature ---------------------------------------------------------

    [Fact]
    public void InvalidSignature_ProducesHighFindingWithChainErrors()
    {
        var signature = new CertificateInfo(
            SignatureState.Invalid, "Test Subject", "Test Issuer", null, null, null,
            new[] { "A required certificate is not within its validity period" });
        var image = CreateImage(signature: signature);

        var finding = Assert.Single(new InvalidSignatureRule().Evaluate(Ctx(image)));
        Assert.Equal(ScanSeverity.High, finding.Severity);
        Assert.Contains("validity period", finding.Evidence);
    }

    [Fact]
    public void UntrustedSignature_ProducesLowFinding()
    {
        var signature = new CertificateInfo(
            SignatureState.Untrusted, "Test Subject", "Unknown Issuer", null, null, null, Array.Empty<string>());
        var image = CreateImage(signature: signature);

        var finding = Assert.Single(new UntrustedSignatureRule().Evaluate(Ctx(image)));
        Assert.Equal(ScanSeverity.Low, finding.Severity);
        Assert.Contains("Test Subject", finding.Description);
    }

    [Fact]
    public void ExpiredSignature_ProducesLowFinding()
    {
        var signature = new CertificateInfo(
            SignatureState.Expired, "Test Subject", "Test Issuer",
            DateTime.UtcNow.AddYears(-2), DateTime.UtcNow.AddYears(-1), null, Array.Empty<string>());
        var image = CreateImage(signature: signature);

        var finding = Assert.Single(new UntrustedSignatureRule().Evaluate(Ctx(image)));
        Assert.Equal(ScanSeverity.Low, finding.Severity);
        Assert.Contains("Expired", finding.Title);
    }

    [Fact]
    public void ValidSignature_ProducesNoSignatureFindings()
    {
        var signature = new CertificateInfo(
            SignatureState.Valid, "Test Subject", "Test Issuer",
            DateTime.UtcNow.AddYears(-1), DateTime.UtcNow.AddYears(1), null, Array.Empty<string>());
        var image = CreateImage(signature: signature);

        Assert.Empty(new InvalidSignatureRule().Evaluate(Ctx(image)));
        Assert.Empty(new UntrustedSignatureRule().Evaluate(Ctx(image)));
        Assert.Empty(new UnsignedBinaryRule().Evaluate(Ctx(image)));
    }

    // --- Imports -----------------------------------------------------------

    [Fact]
    public void NetworkingApis_ProducesMediumFinding()
    {
        var catalog = Catalog(("networking", "Networking", new[] { "InternetOpen", "WinHttpOpen" }));
        var image = CreateImage(imports: new[] { Dll("wininet.dll", "InternetOpenW", "InternetCloseHandle") });

        var finding = Assert.Single(new NetworkingApisRule().Evaluate(Ctx(image, catalog)));
        Assert.Equal(ScanSeverity.Medium, finding.Severity);
        Assert.Equal("PE-IMP-003", finding.RuleId);
        Assert.Contains("InternetOpenW", finding.Evidence);
    }

    [Fact]
    public void PersistenceApis_ProducesMediumFinding()
    {
        var catalog = Catalog(("persistence", "Persistence", new[] { "RegSetValue", "CreateService" }));
        var image = CreateImage(imports: new[] { Dll("advapi32.dll", "RegSetValueW") });

        var finding = Assert.Single(new PersistenceApisRule().Evaluate(Ctx(image, catalog)));
        Assert.Equal(ScanSeverity.Medium, finding.Severity);
        Assert.Equal("PE-IMP-004", finding.RuleId);
    }

    [Fact]
    public void AntiDebugApis_SingleMatch_ProducesLowFinding()
    {
        var catalog = Catalog(("antidebug", "AntiDebug", new[] { "IsDebuggerPresent", "CheckRemoteDebuggerPresent" }));
        var image = CreateImage(imports: new[] { Dll("kernel32.dll", "IsDebuggerPresent", "CreateFileW") });

        var finding = Assert.Single(new AntiDebugApisRule().Evaluate(Ctx(image, catalog)));
        Assert.Equal(ScanSeverity.Low, finding.Severity);
    }

    [Fact]
    public void AntiDebugApis_ThreeMatches_ProducesMediumFinding()
    {
        var catalog = Catalog(("antidebug", "AntiDebug", new[] { "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugString" }));
        var image = CreateImage(imports: new[]
        {
            Dll("kernel32.dll", "IsDebuggerPresent", "CheckRemoteDebuggerPresentW", "OutputDebugStringW")
        });

        var finding = Assert.Single(new AntiDebugApisRule().Evaluate(Ctx(image, catalog)));
        Assert.Equal(ScanSeverity.Medium, finding.Severity);
    }

    [Fact]
    public void DynamicResolution_LoadLibraryPlusGetProcAddress_ProducesMediumFinding()
    {
        var image = CreateImage(imports: new[] { Dll("kernel32.dll", "LoadLibraryW", "GetProcAddress") });
        var finding = Assert.Single(new DynamicResolutionRule().Evaluate(Ctx(image)));
        Assert.Equal(ScanSeverity.Medium, finding.Severity);
        Assert.Equal("PE-IMP-006", finding.RuleId);
    }

    [Fact]
    public void DynamicResolution_WithoutGetProcAddress_ProducesNoFinding()
    {
        var image = CreateImage(imports: new[] { Dll("kernel32.dll", "LoadLibraryW") });
        Assert.Empty(new DynamicResolutionRule().Evaluate(Ctx(image)));
    }

    [Fact]
    public void NoImports_ExecutableWithoutImports_ProducesHighFinding()
    {
        var image = CreateImage(imports: Array.Empty<ImportedDLL>());
        var finding = Assert.Single(new NoImportsRule().Evaluate(Ctx(image)));
        Assert.Equal(ScanSeverity.High, finding.Severity);
        Assert.Equal("PE-IMP-010", finding.RuleId);
    }

    [Fact]
    public void NoImports_ResourceOnlyDll_ProducesNoFinding()
    {
        var image = CreateImage(
            header: Header(isDll: true),
            sections: new[] { Section(".rsrc", SectionFlag.MemRead) },
            imports: Array.Empty<ImportedDLL>());
        Assert.Empty(new NoImportsRule().Evaluate(Ctx(image)));
    }

    // --- Sections ----------------------------------------------------------

    [Fact]
    public void SuspiciousSectionName_MatchingCatalog_ProducesFinding()
    {
        var sectionNames = new SuspiciousSectionNamesCatalog
        {
            Patterns = new Dictionary<string, SectionPattern>
            {
                ["upx"] = new() { Pattern = "^UPX[0-9]?$", Description = "UPX packer", Severity = "High" }
            }
        };
        var image = CreateImage(sections: new[] { Section("UPX0", SectionFlag.MemExecute | SectionFlag.MemRead) });

        var finding = Assert.Single(new SuspiciousSectionNameRule().Evaluate(Ctx(image, sectionNames: sectionNames)));
        Assert.Equal(ScanSeverity.High, finding.Severity);
        Assert.Equal("PE-SEC-004", finding.RuleId);
        Assert.Contains("UPX0", finding.Evidence);
    }

    [Fact]
    public void SuspiciousSectionName_NonMatchingName_ProducesNoFinding()
    {
        var sectionNames = new SuspiciousSectionNamesCatalog
        {
            Patterns = new Dictionary<string, SectionPattern>
            {
                ["upx"] = new() { Pattern = "^UPX[0-9]?$", Description = "UPX packer", Severity = "High" }
            }
        };
        var image = CreateImage(sections: new[] { Section(".text", SectionFlag.MemExecute | SectionFlag.MemRead) });
        Assert.Empty(new SuspiciousSectionNameRule().Evaluate(Ctx(image, sectionNames: sectionNames)));
    }

    [Fact]
    public void HighEntropySection_VeryHigh_ProducesHighFinding()
    {
        var image = CreateImage(entropy: new[]
        {
            new SectionEntropy(".text", 7.6, 4096, IsExecutable: true, IsWritable: false, IsResource: false)
        });

        var finding = Assert.Single(new HighEntropySectionRule().Evaluate(Ctx(image)));
        Assert.Equal("PE-SEC-005", finding.RuleId);
        Assert.Equal(ScanSeverity.High, finding.Severity);
    }

    [Fact]
    public void HighEntropySection_Elevated_ProducesMediumFinding()
    {
        var image = CreateImage(entropy: new[]
        {
            new SectionEntropy(".text", 7.0, 4096, IsExecutable: true, IsWritable: false, IsResource: false)
        });

        var finding = Assert.Single(new HighEntropySectionRule().Evaluate(Ctx(image)));
        Assert.Equal("PE-SEC-006", finding.RuleId);
        Assert.Equal(ScanSeverity.Medium, finding.Severity);
    }

    [Fact]
    public void HighEntropySection_ResourceSection_IsSkipped()
    {
        var image = CreateImage(entropy: new[]
        {
            new SectionEntropy(".rsrc", 7.9, 4096, IsExecutable: false, IsWritable: false, IsResource: true)
        });
        Assert.Empty(new HighEntropySectionRule().Evaluate(Ctx(image)));
    }

    [Fact]
    public void HighEntropySection_NonExecutable_IsSkipped()
    {
        var image = CreateImage(entropy: new[]
        {
            new SectionEntropy(".data", 7.9, 4096, IsExecutable: false, IsWritable: true, IsResource: false)
        });
        Assert.Empty(new HighEntropySectionRule().Evaluate(Ctx(image)));
    }

    [Fact]
    public void Overlay_AboveBothThresholds_ProducesLowFinding()
    {
        var image = CreateImage(fileSize: 200_000, overlay: new OverlayInfo(100_000, 100_000, 7.9));
        var finding = Assert.Single(new OverlayRule().Evaluate(Ctx(image)));
        Assert.Equal(ScanSeverity.Low, finding.Severity);
        Assert.Equal("PE-SEC-010", finding.RuleId);
    }

    [Fact]
    public void Overlay_BelowSizeThreshold_ProducesNoFinding()
    {
        var image = CreateImage(fileSize: 200_000, overlay: new OverlayInfo(199_000, 1_000, 7.9));
        Assert.Empty(new OverlayRule().Evaluate(Ctx(image)));
    }

    // --- Helpers -----------------------------------------------------------

    private static RuleContext Ctx(PeImage image, RiskyApiCatalog? catalog = null, SuspiciousSectionNamesCatalog? sectionNames = null) => new(
        image,
        new RuleOptions
        {
            Catalogs = new RuleCatalogs
            {
                RiskyApis = catalog ?? new RiskyApiCatalog(),
                SectionNames = sectionNames ?? new SuspiciousSectionNamesCatalog()
            }
        });

    private static RiskyApiCatalog Catalog(params (string Key, string Name, string[] Apis)[] groups) => new()
    {
        Groups = groups.ToDictionary(
            group => group.Key,
            group => new ApiGroup { Name = group.Name, Apis = new List<string>(group.Apis) })
    };

    private static HPInfo Header(
        string architecture = "x64",
        uint subsystem = 3,
        bool isDll = false,
        bool HasASLR = true,
        bool HasDEP = true,
        bool HasHighEntropyVA = true,
        bool HasControlFlowGuard = true,
        uint timeDateStamp = 1_600_000_000,
        uint checkSum = 0x1234) => new()
    {
        Architecture = architecture,
        Subsystem = (ushort)subsystem,
        SubsystemName = subsystem switch
        {
            1 => "Native",
            2 => "Windows GUI",
            10 => "EFI Application",
            _ => "Console"
        },
        IsDll = isDll,
        HasASLR = HasASLR,
        HasDEP = HasDEP,
        HasHighEntropyVA = HasHighEntropyVA,
        HasControlFlowGuard = HasControlFlowGuard,
        TimeDateStamp = timeDateStamp,
        CheckSum = checkSum
    };

    private static LoadConfigInfo LoadConfig(
        bool hasSEH = false,
        bool isCFInstrumented = true) => new(
        Size: 64,
        HasSEH: hasSEH,
        SEHandlerTable: 0,
        SEHandlerCount: 0,
        GuardCFCheckFunctionPointer: 0,
        GuardCFDispatchFunctionPointer: 0,
        GuardCFFunctionTable: 0,
        GuardCFFunctionCount: 0,
        GuardFlags: 0x00010000,
        IsCFInstrumented: isCFInstrumented,
        IsCFFunctionTablePresent: isCFInstrumented);

    private static PeImage CreateImage(
        HPInfo? header = null,
        IReadOnlyList<SingleSectionInfo>? sections = null,
        IReadOnlyList<SectionEntropy>? entropy = null,
        IReadOnlyList<ImportedDLL>? imports = null,
        CertificateInfo? signature = null,
        LoadConfigInfo? loadConfig = null,
        OverlayInfo? overlay = null,
        long fileSize = 4096) => new(
        Path: "synthetic.exe",
        FileSize: fileSize,
        Header: header ?? Header(),
        Sections: sections ?? Array.Empty<SingleSectionInfo>(),
        Entropy: entropy ?? Array.Empty<SectionEntropy>(),
        Imports: ImportParseResult.Success(imports ?? Array.Empty<ImportedDLL>()),
        DelayImports: Array.Empty<ImportedDLL>(),
        LoadConfig: loadConfig,
        Signature: signature ?? new CertificateInfo(
            SignatureState.Unsigned, null, null, null, null, null, Array.Empty<string>()),
        Overlay: overlay ?? new OverlayInfo(0, 0, 0));

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
}
