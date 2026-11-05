namespace Server.Options;

/// <summary>
/// Configuration options for the scanner service.
/// </summary>
public sealed class ScannerOptions
{
    public const string SectionName = "Scanner";

    /// <summary>Maximum size of a single file (bytes).</summary>
    public long MaxFileBytes { get; set; } = 100 * 1024 * 1024; // 100 MB

    /// <summary>Maximum size of an archive (bytes).</summary>
    public long MaxArchiveBytes { get; set; } = 200 * 1024 * 1024; // 200 MB

    /// <summary>Maximum total uncompressed size (bytes).</summary>
    public long MaxUncompressedBytes { get; set; } = 1024 * 1024 * 1024; // 1 GB

    /// <summary>Maximum number of entries in an archive.</summary>
    public int MaxEntries { get; set; } = 500;

    /// <summary>Maximum compression ratio (uncompressed/compressed).</summary>
    public int MaxCompressionRatio { get; set; } = 100;

    /// <summary>Maximum size of a single archive entry (bytes).</summary>
    public long MaxEntryBytes { get; set; } = 100 * 1024 * 1024; // 100 MB

    /// <summary>Maximum scan time (seconds).</summary>
    public int MaxScanSeconds { get; set; } = 120;

    /// <summary>Maximum number of parallel scans.</summary>
    public int MaxParallelScans { get; set; } = 4;

    /// <summary>Base path for temporary storage (null = use system temp).</summary>
    public string? TempStorageBasePath { get; set; }

    /// <summary>Base path for rule catalogs (null = use default).</summary>
    public string? CatalogBasePath { get; set; }
}
