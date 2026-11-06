using Core.ImpParser;
using Core.Models;
using Core.Models.ImportDLL;

namespace Core.Analysis;

/// <summary>
/// Immutable aggregate representing a parsed PE file.
/// All data is collected in a single pass through the file.
/// </summary>
public sealed record PeImage(
    string Path,
    long FileSize,
    HPInfo Header,
    IReadOnlyList<SingleSectionInfo> Sections,
    IReadOnlyList<SectionEntropy> Entropy,
    ImportParseResult Imports,
    IReadOnlyList<ImportedDLL> DelayImports,
    LoadConfigInfo? LoadConfig,
    CertificateInfo Signature,
    OverlayInfo Overlay);

/// <summary>Entropy information for a single section.</summary>
public sealed record SectionEntropy(
    string Name,
    double Entropy,
    uint RawSize,
    bool IsExecutable,
    bool IsWritable,
    bool IsResource);

/// <summary>Load configuration directory information (SafeSEH, CFG flags).</summary>
public sealed record LoadConfigInfo(
    uint Size,
    bool HasSEH,
    uint SEHandlerTable,
    uint SEHandlerCount,
    uint GuardCFCheckFunctionPointer,
    uint GuardCFDispatchFunctionPointer,
    uint GuardCFFunctionTable,
    uint GuardCFFunctionCount,
    uint GuardFlags,
    bool IsCFInstrumented,
    bool IsCFFunctionTablePresent);

/// <summary>Certificate and signature verification result.</summary>
public sealed record CertificateInfo(
    SignatureState State,
    string? SubjectName,
    string? IssuerName,
    DateTime? NotBefore,
    DateTime? NotAfter,
    string? Thumbprint,
    IReadOnlyList<string> ChainErrors);

public enum SignatureState
{
    Unsigned,
    Valid,
    Invalid,
    Untrusted,
    Expired
}

/// <summary>Overlay data (after last section).</summary>
public sealed record OverlayInfo(
    long Offset,
    long Size,
    double Entropy);

// ImportParseResult moved to Core.ImpParser namespace
