using Core.Models;
using Core.Scanning;
using System.Text.RegularExpressions;

namespace Core.Rules.BuiltIn;

/// <summary>PE-SEC-001: Section with Write+Execute permissions.</summary>
public sealed class WritableExecutableSectionRule : IRule
{
    public string Id => "PE-SEC-001";
    public string Category => "Sections";
    public string Title => "Writable and executable section (RWX)";

    public IEnumerable<ScanFinding> Evaluate(RuleContext context)
    {
        foreach (var section in context.Image.Sections)
        {
            bool isWritable = section.Flags.HasFlag(SectionFlag.MemWrite);
            bool isExecutable = section.Flags.HasFlag(SectionFlag.MemExecute);

            if (isWritable && isExecutable)
            {
                yield return new ScanFinding(
                    RuleId: Id,
                    Title: Title,
                    Category: Category,
                    Severity: ScanSeverity.Critical,
                    Description: $"Section '{section.Name}' has both WRITE and EXECUTE permissions. This is extremely unusual and often indicates code injection or self-modifying code.",
                    Evidence: $"Section: {section.Name}, Characteristics: 0x{section.Characteristics:X8}",
                    Recommendation: "Investigate this binary for malware. Legitimate software rarely uses RWX sections.",
                    StandardReference: "CWE-766: Critical Data Element Declared Public");
            }
        }
    }
}

/// <summary>PE-SEC-002: Entry point in writable or non-executable section.</summary>
public sealed class SuspiciousEntryPointRule : IRule
{
    public string Id => "PE-SEC-002";
    public string Category => "Sections";
    public string Title => "Suspicious entry point location";

    public IEnumerable<ScanFinding> Evaluate(RuleContext context)
    {
        uint entryPoint = context.Image.Header.AddressOfEntryPoint;
        if (entryPoint == 0)
            yield break;

        // Find section containing entry point
        SingleSectionInfo? entrySection = null;
        foreach (var section in context.Image.Sections)
        {
            uint sectionStart = section.VirtualAddress;
            uint sectionSize = section.VirtualSize == 0 ? section.SizeOfRawData : section.VirtualSize;
            uint sectionEnd = sectionStart + sectionSize;

            if (entryPoint >= sectionStart && entryPoint < sectionEnd)
            {
                entrySection = section;
                break;
            }
        }

        if (entrySection == null)
        {
            yield return new ScanFinding(
                RuleId: Id,
                Title: "Entry point outside all sections",
                Category: Category,
                Severity: ScanSeverity.High,
                Description: $"The entry point (RVA: 0x{entryPoint:X}) is not within any section.",
                Evidence: $"AddressOfEntryPoint: 0x{entryPoint:X}, no matching section",
                Recommendation: "This is highly suspicious. The file may be packed or malformed.",
                StandardReference: null);
            yield break;
        }

        bool isExecutable = entrySection.Flags.HasFlag(SectionFlag.MemExecute);
        bool isWritable = entrySection.Flags.HasFlag(SectionFlag.MemWrite);

        if (!isExecutable)
        {
            yield return new ScanFinding(
                RuleId: Id,
                Title: "Entry point in non-executable section",
                Category: Category,
                Severity: ScanSeverity.High,
                Description: $"The entry point is in section '{entrySection.Name}' which is not marked as executable.",
                Evidence: $"Section: {entrySection.Name}, EntryPoint: 0x{entryPoint:X}, Characteristics: 0x{entrySection.Characteristics:X8}",
                Recommendation: "This may indicate packing or malicious modification.",
                StandardReference: null);
        }

        if (isWritable)
        {
            yield return new ScanFinding(
                RuleId: Id,
                Title: "Entry point in writable section",
                Category: Category,
                Severity: ScanSeverity.High,
                Description: $"The entry point is in section '{entrySection.Name}' which is writable.",
                Evidence: $"Section: {entrySection.Name}, EntryPoint: 0x{entryPoint:X}",
                Recommendation: "Writable code sections are unusual and may indicate self-modifying code.",
                StandardReference: null);
        }
    }
}

/// <summary>PE-SEC-004: Suspicious section names (packers).</summary>
public sealed class SuspiciousSectionNameRule : IRule
{
    public string Id => "PE-SEC-004";
    public string Category => "Sections";
    public string Title => "Suspicious section name";

    public IEnumerable<ScanFinding> Evaluate(RuleContext context)
    {
        var catalog = context.Options.Catalogs.SectionNames;

        foreach (var section in context.Image.Sections)
        {
            foreach (var (key, pattern) in catalog.Patterns)
            {
                if (Regex.IsMatch(section.Name, pattern.Pattern, RegexOptions.IgnoreCase))
                {
                    var severity = pattern.Severity switch
                    {
                        "Critical" => ScanSeverity.Critical,
                        "High" => ScanSeverity.High,
                        "Medium" => ScanSeverity.Medium,
                        "Low" => ScanSeverity.Low,
                        _ => ScanSeverity.Informational
                    };

                    yield return new ScanFinding(
                        RuleId: Id,
                        Title: Title,
                        Category: Category,
                        Severity: severity,
                        Description: $"Section '{section.Name}' matches known packer/protector pattern: {pattern.Description}",
                        Evidence: $"Section: {section.Name}, Pattern: {key}",
                        Recommendation: "This file appears to be packed or protected. Packed files may hide malicious code.",
                        StandardReference: null);
                }
            }
        }
    }
}

/// <summary>PE-SEC-005/006: High entropy in executable sections.</summary>
public sealed class HighEntropySectionRule : IRule
{
    public string Id => "PE-SEC-005";
    public string Category => "Sections";
    public string Title => "High entropy section";

    public IEnumerable<ScanFinding> Evaluate(RuleContext context)
    {
        var thresholds = context.Options.Thresholds;

        foreach (var entropy in context.Image.Entropy)
        {
            // Skip resource sections (they naturally have high entropy)
            if (entropy.IsResource)
                continue;

            // Only check executable sections
            if (!entropy.IsExecutable)
                continue;

            if (entropy.Entropy >= thresholds.HighEntropyThreshold)
            {
                yield return new ScanFinding(
                    RuleId: "PE-SEC-005",
                    Title: "Very high entropy in executable section",
                    Category: Category,
                    Severity: ScanSeverity.High,
                    Description: $"Section '{entropy.Name}' has very high entropy ({entropy.Entropy:F2}), suggesting encryption or compression.",
                    Evidence: $"Section: {entropy.Name}, Entropy: {entropy.Entropy:F2}, Size: {entropy.RawSize} bytes",
                    Recommendation: "High entropy in executable sections often indicates packing or encryption. Investigate further.",
                    StandardReference: null);
            }
            else if (entropy.Entropy >= thresholds.MediumEntropyThreshold)
            {
                yield return new ScanFinding(
                    RuleId: "PE-SEC-006",
                    Title: "Elevated entropy in executable section",
                    Category: Category,
                    Severity: ScanSeverity.Medium,
                    Description: $"Section '{entropy.Name}' has elevated entropy ({entropy.Entropy:F2}).",
                    Evidence: $"Section: {entropy.Name}, Entropy: {entropy.Entropy:F2}, Size: {entropy.RawSize} bytes",
                    Recommendation: "This may indicate compression or obfuscation.",
                    StandardReference: null);
            }
        }
    }
}

/// <summary>PE-SEC-010: Large overlay detected.</summary>
public sealed class OverlayRule : IRule
{
    public string Id => "PE-SEC-010";
    public string Category => "Sections";
    public string Title => "Large overlay detected";

    public IEnumerable<ScanFinding> Evaluate(RuleContext context)
    {
        var overlay = context.Image.Overlay;
        var thresholds = context.Options.Thresholds;

        if (overlay.Size == 0)
            yield break;

        double percentage = (double)overlay.Size / context.Image.FileSize;

        if (overlay.Size > thresholds.OverlaySizeThreshold &&
            percentage > thresholds.OverlayPercentageThreshold)
        {
            yield return new ScanFinding(
                RuleId: Id,
                Title: Title,
                Category: Category,
                Severity: ScanSeverity.Low,
                Description: $"File has {overlay.Size} bytes ({percentage:P1}) of overlay data after the last section.",
                Evidence: $"Overlay offset: 0x{overlay.Offset:X}, Size: {overlay.Size} bytes, Entropy: {overlay.Entropy:F2}",
                Recommendation: "Overlay data can be used to hide additional payloads. Investigate the content.",
                StandardReference: null);
        }
    }
}
