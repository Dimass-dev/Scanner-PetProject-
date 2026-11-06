using Core.Scanning;

namespace Core.Rules.BuiltIn;

/// <summary>PE-MIT-001: Missing ASLR (DynamicBase).</summary>
public sealed class MissingAslrRule : IRule
{
    public string Id => "PE-MIT-001";
    public string Category => "Mitigations";
    public string Title => "Missing ASLR (Address Space Layout Randomization)";

    public IEnumerable<ScanFinding> Evaluate(RuleContext context)
    {
        if (context.Image.Header.HasASLR)
        {
            yield break;
        }

        var severity = context.Image.Header.IsDll ? ScanSeverity.Medium : ScanSeverity.High;

        yield return new ScanFinding(
            RuleId: Id,
            Title: Title,
            Category: Category,
            Severity: severity,
            Description: "The executable does not have ASLR (Address Space Layout Randomization) enabled. ASLR randomizes memory addresses to make exploitation more difficult.",
            Evidence: $"DllCharacteristics: 0x{context.Image.Header.DllCharacteristics:X4} (DYNAMIC_BASE flag not set)",
            Recommendation: "Recompile with /DYNAMICBASE linker flag enabled.",
            StandardReference: "CWE-693: Protection Mechanism Failure");
    }
}

/// <summary>PE-MIT-002: Missing DEP (NX_COMPAT).</summary>
public sealed class MissingDepRule : IRule
{
    public string Id => "PE-MIT-002";
    public string Category => "Mitigations";
    public string Title => "Missing DEP (Data Execution Prevention)";

    public IEnumerable<ScanFinding> Evaluate(RuleContext context)
    {
        if (context.Image.Header.HasDEP)
        {
            yield break;
        }

        var severity = context.Image.Header.IsDll ? ScanSeverity.Medium : ScanSeverity.High;

        yield return new ScanFinding(
            RuleId: Id,
            Title: Title,
            Category: Category,
            Severity: severity,
            Description: "The executable does not have DEP (Data Execution Prevention) enabled. DEP prevents code execution from data pages.",
            Evidence: $"DllCharacteristics: 0x{context.Image.Header.DllCharacteristics:X4} (NX_COMPAT flag not set)",
            Recommendation: "Recompile with /NXCOMPAT linker flag enabled.",
            StandardReference: "CWE-693: Protection Mechanism Failure");
    }
}

/// <summary>PE-MIT-003: Missing CFG (Control Flow Guard).</summary>
public sealed class MissingCfgRule : IRule
{
    public string Id => "PE-MIT-003";
    public string Category => "Mitigations";
    public string Title => "Missing Control Flow Guard (CFG)";

    public IEnumerable<ScanFinding> Evaluate(RuleContext context)
    {
        if (context.Image.Header.HasControlFlowGuard)
        {
            yield break;
        }

        yield return new ScanFinding(
            RuleId: Id,
            Title: Title,
            Category: Category,
            Severity: ScanSeverity.Low,
            Description: "The executable does not have Control Flow Guard (CFG) enabled. CFG validates indirect call targets to prevent exploitation.",
            Evidence: $"DllCharacteristics: 0x{context.Image.Header.DllCharacteristics:X4} (GUARD_CF flag not set)",
            Recommendation: "Recompile with /guard:cf linker flag enabled (requires Visual Studio 2015 or later).",
            StandardReference: "CWE-693: Protection Mechanism Failure");
    }
}

/// <summary>PE-MIT-004: Missing SafeSEH on x86.</summary>
public sealed class MissingSafeSehRule : IRule
{
    private const ushort DllCharacteristicsNoSeh = 0x0400;

    public string Id => "PE-MIT-004";
    public string Category => "Mitigations";
    public string Title => "Missing SafeSEH (x86)";

    public IEnumerable<ScanFinding> Evaluate(RuleContext context)
    {
        // Only applies to x86
        if (context.Image.Header.Architecture != "x86")
        {
            yield break;
        }

        // If binary explicitly does not use SEH, SafeSEH is not expected
        if ((context.Image.Header.DllCharacteristics & DllCharacteristicsNoSeh) != 0)
        {
            yield break;
        }

        // Check if LoadConfig has SafeSEH
        if (context.Image.LoadConfig?.HasSEH == true)
        {
            yield break;
        }

        yield return new ScanFinding(
            RuleId: Id,
            Title: Title,
            Category: Category,
            Severity: ScanSeverity.Medium,
            Description: "The x86 executable does not have SafeSEH enabled. SafeSEH validates exception handlers to prevent SEH overwrites.",
            Evidence: "LoadConfig directory missing or SEHandlerTable is empty",
            Recommendation: "Recompile with /SAFESEH linker flag enabled.",
            StandardReference: "CWE-693: Protection Mechanism Failure");
    }
}

/// <summary>PE-MIT-005: Missing HighEntropyVA on x64.</summary>
public sealed class MissingHighEntropyVaRule : IRule
{
    public string Id => "PE-MIT-005";
    public string Category => "Mitigations";
    public string Title => "Missing High Entropy Virtual Addresses (x64)";

    public IEnumerable<ScanFinding> Evaluate(RuleContext context)
    {
        // Only applies to x64
        if (context.Image.Header.Architecture != "x64")
        {
            yield break;
        }

        if (context.Image.Header.HasHighEntropyVA)
        {
            yield break;
        }

        yield return new ScanFinding(
            RuleId: Id,
            Title: Title,
            Category: Category,
            Severity: ScanSeverity.Low,
            Description: "The x64 executable does not have High Entropy VA enabled. This reduces the effectiveness of ASLR on 64-bit systems.",
            Evidence: $"DllCharacteristics: 0x{context.Image.Header.DllCharacteristics:X4} (HIGH_ENTROPY_VA flag not set)",
            Recommendation: "Recompile with /HIGHENTROPYVA linker flag enabled.",
            StandardReference: "CWE-693: Protection Mechanism Failure");
    }
}

/// <summary>PE-MIT-006: CFG flag set but not instrumented.</summary>
public sealed class CfgMismatchRule : IRule
{
    public string Id => "PE-MIT-006";
    public string Category => "Mitigations";
    public string Title => "CFG flag inconsistency";

    public IEnumerable<ScanFinding> Evaluate(RuleContext context)
    {
        if (!context.Image.Header.HasControlFlowGuard)
        {
            yield break;
        }

        // Check if LoadConfig has CFG instrumentation
        if (context.Image.LoadConfig?.IsCFInstrumented == false)
        {
            yield return new ScanFinding(
                RuleId: Id,
                Title: Title,
                Category: Category,
                Severity: ScanSeverity.Informational,
                Description: "The GUARD_CF DllCharacteristic is set, but LoadConfig does not indicate CFG instrumentation.",
                Evidence: $"GuardFlags: 0x{context.Image.LoadConfig.GuardFlags:X8} (CF_INSTRUMENTED not set)",
                Recommendation: "Verify that the binary was properly compiled with /guard:cf.",
                StandardReference: null);
        }
    }
}
