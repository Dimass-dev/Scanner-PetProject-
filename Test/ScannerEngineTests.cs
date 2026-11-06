using Core.Analysis;
using Core.Models;
using Core.Modules;
using Core.Parsing;
using Core.Rules.BuiltIn;
using Core.Scanning;
using Xunit;

namespace Scanner.Tests;

public sealed class ScannerEngineTests
{
    [Fact]
    public void LoadRuleOptions_LoadsCatalogsSuccessfully()
    {
        var options = PeScanModule.LoadRuleOptions();

        Assert.NotNull(options);
        Assert.NotNull(options.Catalogs);
        Assert.NotNull(options.Catalogs.RiskyApis);
        Assert.NotNull(options.Catalogs.SectionNames);

        // Verify catalogs deserialized with case insensitivity
        Assert.True(options.Catalogs.RiskyApis.Groups.Count > 0, "RiskyApis groups should not be empty");
        Assert.True(options.Catalogs.RiskyApis.Groups.ContainsKey("injection"));
        Assert.True(options.Catalogs.RiskyApis.Groups.ContainsKey("networking"));
        Assert.True(options.Catalogs.RiskyApis.Groups.ContainsKey("persistence"));
        Assert.True(options.Catalogs.RiskyApis.Groups.ContainsKey("antidebug"));

        Assert.True(options.Catalogs.SectionNames.Patterns.Count > 0, "SectionNames patterns should not be empty");
        Assert.True(options.Catalogs.SectionNames.Patterns.ContainsKey("upx"));

        // Verify thresholds
        Assert.Equal(65536, options.Thresholds.OverlaySizeThreshold);
        Assert.Equal(0.05, options.Thresholds.OverlayPercentageThreshold);
    }

    [Fact]
    public void OverlayScanner_ExcludesSecurityDirectoryFromOverlay()
    {
        string tempFile = Path.GetTempFileName();
        try
        {
            // Create a fake file of 4000 bytes
            byte[] fileBytes = new byte[4000];
            File.WriteAllBytes(tempFile, fileBytes);

            var sections = new List<SingleSectionInfo>
            {
                new SingleSectionInfo
                {
                    SectionName = ".text",
                    PointerToRawData = 1000,
                    SizeOfRawData = 1000
                }
            };

            // Certificate directory starts right at section end (offset 2000) and has 2000 bytes (ends at 4000)
            var header = new HPInfo
            {
                SecurityDirectoryFileOffset = 2000,
                SecurityDirectorySize = 2000
            };

            var scanner = new OverlayScanner();
            var overlay = scanner.Scan(tempFile, sections, header);

            // Overlay size should be 0 because all remaining bytes are in the certificate table
            Assert.Equal(0, overlay.Size);
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Fact]
    public void MissingSafeSehRule_SkipsBinaryWithNoSehFlag()
    {
        var rule = new MissingSafeSehRule();
        var header = new HPInfo
        {
            Architecture = "x86",
            DllCharacteristics = 0x0400 // IMAGE_DLLCHARACTERISTICS_NO_SEH
        };

        var image = new PeImage(
            Path: "dummy.dll",
            FileSize: 1000,
            Header: header,
            Sections: [],
            Entropy: [],
            Imports: Core.ImpParser.ImportParseResult.Success([]),
            DelayImports: [],
            LoadConfig: null,
            Signature: new CertificateInfo(SignatureState.Unsigned, null, null, null, null, null, []),
            Overlay: new OverlayInfo(0, 0, 0));

        var context = new Core.Rules.RuleContext(image, new Core.Rules.RuleOptions());
        var findings = rule.Evaluate(context).ToList();

        Assert.Empty(findings);
    }

    [Fact]
    public void NoImportsRule_SkipsResourceOnlyDll()
    {
        var rule = new NoImportsRule();
        var header = new HPInfo
        {
            IsDll = true
        };

        var sections = new List<SingleSectionInfo>
        {
            new SingleSectionInfo
            {
                SectionName = ".rsrc",
                Characteristics = SectionFlag.ContentInitializedData | SectionFlag.MemRead
            }
        };

        var image = new PeImage(
            Path: "resource.dll",
            FileSize: 1000,
            Header: header,
            Sections: sections,
            Entropy: [],
            Imports: Core.ImpParser.ImportParseResult.Success([]),
            DelayImports: [],
            LoadConfig: null,
            Signature: new CertificateInfo(SignatureState.Unsigned, null, null, null, null, null, []),
            Overlay: new OverlayInfo(0, 0, 0));

        var context = new Core.Rules.RuleContext(image, new Core.Rules.RuleOptions());
        var findings = rule.Evaluate(context).ToList();

        Assert.Empty(findings);
    }
}
