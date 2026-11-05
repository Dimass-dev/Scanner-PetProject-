using Core.Analysis;
using Core.Scanning;

namespace Core.Rules.BuiltIn;

/// <summary>PE-HDR-001: Non-standard subsystem.</summary>
public sealed class UnusualSubsystemRule : IRule
{
    public string Id => "PE-HDR-001";
    public string Category => "Header";
    public string Title => "Non-standard subsystem";

    public IEnumerable<ScanFinding> Evaluate(RuleContext context)
    {
        var subsystem = context.Image.Header.Subsystem;

        // Standard subsystems: 2 (GUI), 3 (Console)
        if (subsystem == 2 || subsystem == 3)
            yield break;

        // Native (1), EFI (10-14) are unusual
        if (subsystem == 1 || (subsystem >= 10 && subsystem <= 14))
        {
            yield return new ScanFinding(
                RuleId: Id,
                Title: Title,
                Category: Category,
                Severity: ScanSeverity.Medium,
                Description: $"File uses non-standard subsystem: {context.Image.Header.SubsystemName} ({subsystem}).",
                Evidence: $"Subsystem: {subsystem} ({context.Image.Header.SubsystemName})",
                Recommendation: "Native drivers and EFI applications require elevated privileges and should be scrutinized.",
                StandardReference: null);
        }
    }
}

/// <summary>PE-HDR-002: Suspicious timestamp.</summary>
public sealed class SuspiciousTimestampRule : IRule
{
    public string Id => "PE-HDR-002";
    public string Category => "Header";
    public string Title => "Suspicious timestamp";

    public IEnumerable<ScanFinding> Evaluate(RuleContext context)
    {
        uint timestamp = context.Image.Header.TimeDateStamp;

        // Null timestamp
        if (timestamp == 0)
        {
            yield return new ScanFinding(
                RuleId: Id,
                Title: "Null timestamp",
                Category: Category,
                Severity: ScanSeverity.Low,
                Description: "The PE timestamp is zero, indicating the timestamp was deliberately cleared.",
                Evidence: "TimeDateStamp: 0",
                Recommendation: "Cleared timestamps can indicate an attempt to hide compilation time.",
                StandardReference: null);
            yield break;
        }

        // Convert Unix timestamp to DateTime
        var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var compilationTime = epoch.AddSeconds(timestamp);
        var now = DateTime.UtcNow;

        // Future timestamp
        if (compilationTime > now)
        {
            yield return new ScanFinding(
                RuleId: Id,
                Title: "Future timestamp",
                Category: Category,
                Severity: ScanSeverity.Low,
                Description: $"The PE timestamp is in the future: {compilationTime:yyyy-MM-dd HH:mm:ss} UTC.",
                Evidence: $"TimeDateStamp: {timestamp} ({compilationTime:yyyy-MM-dd})",
                Recommendation: "Future timestamps may indicate timestamp manipulation.",
                StandardReference: null);
        }
    }
}

/// <summary>PE-HDR-003: Invalid checksum.</summary>
public sealed class InvalidChecksumRule : IRule
{
    public string Id => "PE-HDR-003";
    public string Category => "Header";
    public string Title => "Invalid PE checksum";

    public IEnumerable<ScanFinding> Evaluate(RuleContext context)
    {
        uint checksum = context.Image.Header.CheckSum;

        // Zero checksum is common for user-mode apps (only required for drivers)
        if (checksum == 0)
        {
            // Only flag if it's a driver (Native subsystem)
            if (context.Image.Header.Subsystem == 1)
            {
                yield return new ScanFinding(
                    RuleId: Id,
                    Title: "Missing checksum in driver",
                    Category: Category,
                    Severity: ScanSeverity.Low,
                    Description: "Native driver has zero checksum. Windows requires valid checksums for kernel-mode binaries.",
                    Evidence: "CheckSum: 0, Subsystem: Native",
                    Recommendation: "Drivers should have valid checksums.",
                    StandardReference: null);
            }
        }
        // Note: Actual checksum validation would require calculating the checksum from file data
        // This is expensive and typically done by the OS loader, not static analysis
    }
}

/// <summary>PE-SIG-001: Invalid signature.</summary>
public sealed class InvalidSignatureRule : IRule
{
    public string Id => "PE-SIG-001";
    public string Category => "Signature";
    public string Title => "Invalid code signature";

    public IEnumerable<ScanFinding> Evaluate(RuleContext context)
    {
        var sig = context.Image.Signature;

        if (sig.State == SignatureState.Invalid)
        {
            yield return new ScanFinding(
                RuleId: Id,
                Title: Title,
                Category: Category,
                Severity: ScanSeverity.High,
                Description: "The file has an invalid Authenticode signature. The signature verification failed.",
                Evidence: string.Join("; ", sig.ChainErrors),
                Recommendation: "Invalid signatures indicate tampering or corruption. Do not trust this file.",
                StandardReference: null);
        }
    }
}

/// <summary>PE-SIG-002: Untrusted or expired signature.</summary>
public sealed class UntrustedSignatureRule : IRule
{
    public string Id => "PE-SIG-002";
    public string Category => "Signature";
    public string Title => "Untrusted or expired signature";

    public IEnumerable<ScanFinding> Evaluate(RuleContext context)
    {
        var sig = context.Image.Signature;

        if (sig.State == SignatureState.Untrusted)
        {
            yield return new ScanFinding(
                RuleId: Id,
                Title: "Untrusted signature",
                Category: Category,
                Severity: ScanSeverity.Low,
                Description: $"The file is signed but the certificate chain is not trusted. Signer: {sig.SubjectName}",
                Evidence: $"Subject: {sig.SubjectName}, Issuer: {sig.IssuerName}",
                Recommendation: "Verify the signer's identity before trusting this file.",
                StandardReference: null);
        }
        else if (sig.State == SignatureState.Expired)
        {
            yield return new ScanFinding(
                RuleId: Id,
                Title: "Expired signature",
                Category: Category,
                Severity: ScanSeverity.Low,
                Description: $"The file's signature has expired. Valid period: {sig.NotBefore:yyyy-MM-dd} to {sig.NotAfter:yyyy-MM-dd}.",
                Evidence: $"NotAfter: {sig.NotAfter:yyyy-MM-dd}",
                Recommendation: "Expired signatures may indicate an old or abandoned binary.",
                StandardReference: null);
        }
    }
}

/// <summary>PE-SIG-003: Unsigned binary.</summary>
public sealed class UnsignedBinaryRule : IRule
{
    public string Id => "PE-SIG-003";
    public string Category => "Signature";
    public string Title => "Unsigned binary";

    public IEnumerable<ScanFinding> Evaluate(RuleContext context)
    {
        var sig = context.Image.Signature;

        if (sig.State == SignatureState.Unsigned)
        {
            // Lower severity for this rule - many legitimate apps are unsigned
            yield return new ScanFinding(
                RuleId: Id,
                Title: Title,
                Category: Category,
                Severity: ScanSeverity.Low,
                Description: "The file does not have an Authenticode signature.",
                Evidence: "No signature present",
                Recommendation: "Unsigned binaries cannot be verified. Consider code signing.",
                StandardReference: null);
        }
    }
}
