using Core.ImpParser;
using Core.Models;
using Core.Models.ImportDLL;
using Core.Scanning;
using Core.Sections;

namespace Core.PE;

/// <summary>PE scan module that feeds parser output into the common scan result model.</summary>
public sealed class PeAnalysisModule(
    HeaderParser headerParser,
    SectionParser sectionParser,
    ImportedParser importedParser) : IScanModule
{
    public string ModuleId => "pe-static-analysis";

    public bool Supports(ScanTargetKind targetKind) => targetKind == ScanTargetKind.PeFile;

    public Task<ScanModuleResult> ScanAsync(ScanTarget target, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(target);
        cancellationToken.ThrowIfCancellationRequested();
        if (!Supports(target.Kind))
        {
            return Task.FromResult(ScanModuleResult.Failure(ModuleId, "This module only accepts PE file targets."));
        }

        HPResult headerResult = headerParser.Parse(target.Value, cancellationToken);
        if (!headerResult.IsSuccess || headerResult.Info is null)
        {
            return Task.FromResult(ScanModuleResult.Failure(ModuleId, headerResult.ErrorMessage ?? "PE headers could not be read."));
        }

        HPInfo header = headerResult.Info;
        SingleSectionResult sectionResult = sectionParser.Parse(target.Value, header, cancellationToken);
        if (!sectionResult.IsSuccess || sectionResult.SectionInfo is null)
        {
            return Task.FromResult(ScanModuleResult.Failure(ModuleId, sectionResult.ErrorMessage ?? "PE sections could not be read."));
        }

        cancellationToken.ThrowIfCancellationRequested();
        ImportParseResult importResult = importedParser.Parse(target.Value, header, sectionResult.SectionInfo, cancellationToken);
        if (!importResult.IsSuccess)
        {
            return Task.FromResult(ScanModuleResult.Failure(ModuleId, importResult.ErrorMessage ?? "PE imports could not be read."));
        }

        var artifacts = new List<ScanArtifact>
        {
            new("pe.header", Path.GetFileName(target.Value), new Dictionary<string, string>
            {
                ["Architecture"] = header.Architecture,
                ["Machine"] = $"0x{header.Machine:X4}",
                ["OptionalHeader"] = header.IsPE32Plus ? "PE32+" : "PE32",
                ["Sections"] = header.NumberOfSections.ToString(),
                ["ASLR"] = header.HasASLR.ToString(),
                ["DEP"] = header.HasDEP.ToString(),
                ["HighEntropyVA"] = header.HasHighEntropyVA.ToString(),
                ["ControlFlowGuard"] = header.HasControlFlowGuard.ToString()
            })
        };

        foreach (SingleSectionInfo section in sectionResult.SectionInfo)
        {
            artifacts.Add(new ScanArtifact("pe.section", section.SectionName, new Dictionary<string, string>
            {
                ["VirtualAddress"] = $"0x{section.VirtualAddress:X8}",
                ["VirtualSize"] = $"0x{section.VirtualSize:X8}",
                ["RawOffset"] = $"0x{section.PointerToRawData:X8}",
                ["RawSize"] = $"0x{section.SizeOfRawData:X8}",
                ["Characteristics"] = $"0x{(uint)section.Characteristics:X8}"
            }));
        }

        foreach (ImportedDLL library in importResult.Libraries)
        {
            artifacts.Add(new ScanArtifact("pe.import-library", library.DLLName, new Dictionary<string, string>
            {
                ["NameRVA"] = $"0x{library.NameRVA:X8}",
                ["OriginalFirstThunk"] = $"0x{library.OriginalFirstThunk:X8}",
                ["FirstThunk"] = $"0x{library.FirstThunk:X8}",
                ["FunctionCount"] = library.Functions.Count.ToString()
            }));

            foreach (ImportedFunction function in library.Functions)
            {
                var properties = new Dictionary<string, string>();
                if (function.Hint is ushort hint)
                {
                    properties["Hint"] = hint.ToString();
                }

                if (function.Ordinal is ushort ordinal)
                {
                    properties["Ordinal"] = ordinal.ToString();
                }

                artifacts.Add(new ScanArtifact("pe.import-function", function.DisplayName, properties));
            }
        }

        return Task.FromResult(ScanModuleResult.Success(ModuleId, artifacts: artifacts));
    }
}
