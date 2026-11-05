using Core.Scanning;
using Server.Options;

namespace Server.Services;

/// <summary>
/// Handles scanning of ZIP archives with parallel processing.
/// </summary>
public sealed class ArchiveService
{
    private readonly FileScanService _fileScanService;
    private readonly TempStorage _tempStorage;
    private readonly ScannerOptions _options;

    public ArchiveService(
        FileScanService fileScanService,
        TempStorage tempStorage,
        ScannerOptions options)
    {
        _fileScanService = fileScanService;
        _tempStorage = tempStorage;
        _options = options;
    }

    /// <summary>Scan all PE files in a ZIP archive.</summary>
    public async Task<ArchiveScanResult> ScanArchiveAsync(
        string archivePath,
        CancellationToken cancellationToken = default)
    {
        var fileInfo = new FileInfo(archivePath);
        if (!fileInfo.Exists)
        {

            throw new FileNotFoundException("Archive not found", archivePath);
        }


        if (fileInfo.Length > _options.MaxArchiveBytes)
        {

            throw new InvalidOperationException($"Archive too large: {fileInfo.Length} bytes (max: {_options.MaxArchiveBytes})");
        }

        // Create temporary extraction directory

        string extractPath = _tempStorage.CreateScanDirectory();

        try
        {
            // Extract archive
            var extractResult = await _tempStorage.ExtractArchiveAsync(
                archivePath,
                extractPath,
                cancellationToken);

            if (!extractResult.IsSuccess)
            {
                return new ArchiveScanResult(
                    ExtractedFileCount: 0,
                    ScannedFileCount: 0,
                    FileReports: Array.Empty<FileScanResult>(),
                    ExtractionErrors: Array.Empty<string>(),
                    ErrorMessage: extractResult.ErrorMessage);
            }

            // Filter PE files
            var peFiles = extractResult.ExtractedFiles
                .Where(f => IsPeFile(f))
                .ToList();

            // Scan files in parallel
            var scanResults = new List<FileScanResult>();
            var semaphore = new SemaphoreSlim(_options.MaxParallelScans);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(_options.MaxScanSeconds));

            var tasks = peFiles.Select(async filePath =>
            {
                await semaphore.WaitAsync(cts.Token);
                try
                {
                    string relativePath = Path.GetRelativePath(extractPath, filePath);
                    ScanReport report;
                    string? error = null;

                    try
                    {
                        report = await _fileScanService.ScanFileAsync(filePath, cts.Token);
                    }
                    catch (Exception ex)
                    {
                        error = ex.Message;
                        report = new ScanReport(
                            Target: ScanTarget.ForPeFile(filePath),
                            Modules: new[] { ScanModuleResult.Failure("archive-scan", ex.Message) });
                    }

                    return new FileScanResult(relativePath, new FileInfo(filePath).Length, report, error);
                }
                finally
                {
                    semaphore.Release();
                }
            });

            scanResults.AddRange(await Task.WhenAll(tasks));

            return new ArchiveScanResult(
                ExtractedFileCount: extractResult.ExtractedFiles.Count,
                ScannedFileCount: peFiles.Count,
                FileReports: scanResults,
                ExtractionErrors: extractResult.Errors,
                ErrorMessage: null);
        }
        finally
        {
            // Cleanup
            _tempStorage.DeleteScanDirectory(extractPath);
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

/// <summary>Result of archive scan.</summary>
public sealed record ArchiveScanResult(
    int ExtractedFileCount,
    int ScannedFileCount,
    IReadOnlyList<FileScanResult> FileReports,
    IReadOnlyList<string> ExtractionErrors,
    string? ErrorMessage);

/// <summary>Result of scanning a single file from archive.</summary>
public sealed record FileScanResult(
    string RelativePath,
    long FileSize,
    ScanReport Report,
    string? Error);
