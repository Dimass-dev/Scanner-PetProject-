using Server.Options;
using System.IO.Compression;

namespace Server.Services;

/// <summary>
/// Manages temporary file storage with automatic cleanup.
/// Implements secure ZIP extraction with Zip Slip protection.
/// </summary>
public sealed class TempStorage : IDisposable
{
    private readonly ScannerOptions _options;
    private readonly string _basePath;
    private readonly List<string> _activePaths = new();
    private readonly object _lock = new();

    public TempStorage(ScannerOptions options)
    {
        _options = options;
        _basePath = options.TempStorageBasePath ?? Path.Combine(Path.GetTempPath(), "scanner");

        if (!Directory.Exists(_basePath))
        {
            Directory.CreateDirectory(_basePath);
        }

        // Start background cleanup task
        _ = Task.Run(CleanupOldFiles);
    }

    /// <summary>Create a temporary directory for a scan session.</summary>
    public string CreateScanDirectory()
    {
        string scanId = Guid.NewGuid().ToString("N");
        string scanPath = Path.Combine(_basePath, scanId);

        Directory.CreateDirectory(scanPath);

        lock (_lock)
        {
            _activePaths.Add(scanPath);
        }

        return scanPath;
    }

    /// <summary>Safely extract ZIP archive with Zip Slip and Zip Bomb protection.</summary>
    public async Task<ExtractResult> ExtractArchiveAsync(
        string archivePath,
        string destinationPath,
        CancellationToken cancellationToken = default)
    {
        var errors = new List<string>();
        var extractedFiles = new List<string>();
        long totalUncompressed = 0;

        try
        {
            using var archive = ZipFile.OpenRead(archivePath);

            if (archive.Entries.Count > _options.MaxEntries)
            {
                return ExtractResult.Fail($"Archive contains too many entries ({archive.Entries.Count} > {_options.MaxEntries})");
            }

            string canonicalDest = Path.GetFullPath(destinationPath);

            foreach (var entry in archive.Entries)
            {
                cancellationToken.ThrowIfCancellationRequested();

                // Skip directories
                if (entry.FullName.EndsWith('/') || entry.FullName.EndsWith('\\'))
                {
                    continue;
                }

                // Validate entry name
                var validation = ValidateEntryName(entry.FullName);
                if (!validation.IsValid)
                {
                    errors.Add($"{entry.FullName}: {validation.Error}");
                    continue;
                }

                // Check compression ratio
                if (entry.CompressedLength > 0)
                {
                    double ratio = (double)entry.Length / entry.CompressedLength;
                    if (ratio > _options.MaxCompressionRatio)
                    {
                        errors.Add($"{entry.FullName}: Compression ratio too high ({ratio:F0}:1)");
                        continue;
                    }
                }

                // Check entry size
                if (entry.Length > _options.MaxEntryBytes)
                {
                    errors.Add($"{entry.FullName}: Entry too large ({entry.Length} bytes)");
                    continue;
                }

                // Check total uncompressed size
                totalUncompressed += entry.Length;
                if (totalUncompressed > _options.MaxUncompressedBytes)
                {
                    return ExtractResult.Fail($"Total uncompressed size exceeds limit ({totalUncompressed} > {_options.MaxUncompressedBytes})");
                }

                // Zip Slip protection
                string fullPath = Path.GetFullPath(Path.Combine(destinationPath, entry.FullName));
                if (!fullPath.StartsWith(canonicalDest + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) &&
                    !fullPath.Equals(canonicalDest, StringComparison.OrdinalIgnoreCase))
                {
                    errors.Add($"{entry.FullName}: Path traversal attempt detected");
                    continue;
                }

                // Create directory
                string? directory = Path.GetDirectoryName(fullPath);
                if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                // Extract with streaming and size verification
                try
                {
                    bool sizeExceeded = false;
                    using (var entryStream = entry.Open())
                    {
                        using (var fileStream = new FileStream(fullPath, FileMode.Create, FileAccess.Write))
                        {
                            long bytesWritten = 0;
                            byte[] buffer = new byte[81920]; // 80 KB buffer

                            int bytesRead;
                            while ((bytesRead = await entryStream.ReadAsync(buffer, cancellationToken)) > 0)
                            {
                                await fileStream.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken);
                                bytesWritten += bytesRead;

                                // Verify actual size doesn't exceed declared size
                                if (bytesWritten > entry.Length + 1024) // 1KB tolerance
                                {
                                    sizeExceeded = true;
                                    break;
                                }
                            }
                        }
                    }

                    if (sizeExceeded)
                    {
                        if (File.Exists(fullPath))
                            File.Delete(fullPath);
                        errors.Add($"{entry.FullName}: Actual size exceeds declared size");
                    }
                    else
                    {
                        extractedFiles.Add(fullPath);
                    }
                }
                catch (Exception ex)
                {
                    errors.Add($"{entry.FullName}: Extraction failed - {ex.Message}");
                }
            }

            return ExtractResult.Success(extractedFiles, errors);
        }
        catch (Exception ex)
        {
            return ExtractResult.Fail($"Archive extraction failed: {ex.Message}");
        }
    }

    private static (bool IsValid, string? Error) ValidateEntryName(string entryName)
    {
        // Reject absolute paths
        if (Path.IsPathRooted(entryName))
        {
            return (false, "Absolute paths are not allowed");
        }

        // Reject path traversal
        if (entryName.Contains(".."))
        {
            return (false, "Path traversal sequences (..) are not allowed");
        }

        // Reject excessive path length
        if (entryName.Length > 260)
        {
            return (false, "Path too long");
        }

        // Reject invalid characters
        char[] invalidChars = Path.GetInvalidFileNameChars();
        foreach (var part in entryName.Split('/', '\\'))
        {
            if (part.IndexOfAny(invalidChars) >= 0)
            {
                return (false, "Invalid characters in path");
            }
        }

        return (true, null);
    }

    /// <summary>Delete a scan directory.</summary>
    public void DeleteScanDirectory(string scanPath)
    {
        try
        {
            if (Directory.Exists(scanPath))
            {
                Directory.Delete(scanPath, recursive: true);
            }

            lock (_lock)
            {
                _activePaths.Remove(scanPath);
            }
        }
        catch
        {
            // Log but don't throw - cleanup will handle it
        }
    }

    /// <summary>Background task to clean up old temporary directories.</summary>
    private async Task CleanupOldFiles()
    {
        while (true)
        {
            await Task.Delay(TimeSpan.FromMinutes(10));

            try
            {
                if (!Directory.Exists(_basePath))
                {
                    continue;
                }

                var cutoff = DateTime.UtcNow.AddHours(-1);

                foreach (var dir in Directory.GetDirectories(_basePath))
                {
                    try
                    {
                        var dirInfo = new DirectoryInfo(dir);
                        if (dirInfo.CreationTimeUtc < cutoff)
                        {
                            Directory.Delete(dir, recursive: true);
                        }
                    }
                    catch
                    {
                        // Continue to next directory
                    }
                }
            }
            catch
            {
                // Continue loop
            }
        }
    }

    public void Dispose()
    {
        // Cleanup all active paths
        lock (_lock)
        {
            foreach (var path in _activePaths.ToList())
            {
                DeleteScanDirectory(path);
            }
        }
    }
}

/// <summary>Result of archive extraction.</summary>
public sealed record ExtractResult(
    bool IsSuccess,
    IReadOnlyList<string> ExtractedFiles,
    IReadOnlyList<string> Errors,
    string? ErrorMessage)
{
    public static ExtractResult Success(IReadOnlyList<string> files, IReadOnlyList<string> errors) =>
        new(true, files, errors, null);

    public static ExtractResult Fail(string error) =>
        new(false, Array.Empty<string>(), Array.Empty<string>(), error);
}
