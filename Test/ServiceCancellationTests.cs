using Core.Scanning;
using Server.Options;
using Server.Services;
using Xunit;

namespace Scanner.Tests;

public sealed class ServiceCancellationTests
{
    [Fact]
    public async Task ScanFileAsync_ExceededDeadline_ThrowsTimeoutException()
    {
        string path = WritePeFile();
        try
        {
            var service = CreateService(maxScanSeconds: 1);

            await Assert.ThrowsAsync<TimeoutException>(() => service.ScanFileAsync(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ScanFileAsync_ClientCancellation_ThrowsOperationCanceledException()
    {
        string path = WritePeFile();
        try
        {
            var service = CreateService(maxScanSeconds: 30);
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));

            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => service.ScanFileAsync(path, cts.Token));
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static FileScanService CreateService(int maxScanSeconds)
    {
        var coordinator = new ScanCoordinator(new IScanModule[] { new BlockingModule() });
        return new FileScanService(coordinator, new ScannerOptions
        {
            MaxScanSeconds = maxScanSeconds,
            MaxFileBytes = 1024 * 1024
        });
    }

    private static string WritePeFile()
    {
        string path = Path.Combine(Path.GetTempPath(), $"scanner-timeout-{Guid.NewGuid():N}.exe");
        File.WriteAllBytes(path, PeBuilder.CreatePe64());
        return path;
    }

    private sealed class BlockingModule : IScanModule
    {
        public string ModuleId => "blocking";

        public bool Supports(ScanTargetKind targetKind) => true;

        public async Task<ScanModuleResult> ScanAsync(
            ScanTarget target,
            CancellationToken cancellationToken = default)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return ScanModuleResult.Success("blocking");
        }
    }
}
