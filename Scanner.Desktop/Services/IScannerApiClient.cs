using Scanner.Desktop.Models;

namespace Scanner.Desktop.Services;

public interface IScannerApiClient
{
    Task<ScanResult?> ScanFileAsync(string filePath, CancellationToken cancellationToken = default);
    Task<ArchiveScanResult?> ScanArchiveAsync(string archivePath, CancellationToken cancellationToken = default);
    Task<bool> CheckHealthAsync(CancellationToken cancellationToken = default);
}
