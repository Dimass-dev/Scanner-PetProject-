using Core.Scanning;
using Server.Options;

namespace Server.Services;

/// <summary>
/// Orchestrates scanning of individual PE files.
/// </summary>
public sealed class FileScanService
{
    private readonly ScanCoordinator _coordinator;
    private readonly ScannerOptions _options;

    public FileScanService(ScanCoordinator coordinator, ScannerOptions options)
    {
        _coordinator = coordinator;
        _options = options;
    }

    /// <summary>Scan a single PE file.</summary>
    public async Task<ScanReport> ScanFileAsync(string filePath, CancellationToken cancellationToken = default)
    {
        // Validate file
        var fileInfo = new FileInfo(filePath);
        if (!fileInfo.Exists)
        {

            throw new FileNotFoundException("File not found", filePath);
        }


        if (fileInfo.Length > _options.MaxFileBytes)
        {

            throw new InvalidOperationException($"File too large: {fileInfo.Length} bytes (max: {_options.MaxFileBytes})");
        }

        // Verify PE magic bytes

        if (!IsPeFile(filePath))
        {

            throw new InvalidOperationException("File is not a valid PE file (missing MZ signature)");
        }

        // Create scan target

        var target = ScanTarget.ForPeFile(filePath);

        // Scan with timeout
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(TimeSpan.FromSeconds(_options.MaxScanSeconds));

        try
        {
            return await _coordinator.ScanAsync(target, cts.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException($"Scan exceeded time limit of {_options.MaxScanSeconds} seconds");
        }
    }

    private bool IsPeFile(string filePath)
    {
        try
        {
            using var file = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            Span<byte> magic = stackalloc byte[2];

            if (file.Read(magic) < 2)
            {

                return false;
            }


            return magic[0] == 0x4D && magic[1] == 0x5A; // "MZ"
        }
        catch
        {
            return false;
        }
    }
}
