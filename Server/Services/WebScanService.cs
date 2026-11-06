using Core.Scanning;
using Core.Web;

namespace Server.Services;

public sealed class WebScanService(ScanCoordinator coordinator, WebScannerOptions options)
{
    private readonly WebTargetPolicy _policy = new(options);

    public async Task<ScanReport> ScanAsync(
        string targetUrl,
        string? openApiDocument = null,
        bool enableLimitedActive = false,
        bool confirmedActiveTest = false,
        CancellationToken cancellationToken = default)
    {
        if (enableLimitedActive && !confirmedActiveTest)
        {
            throw new InvalidOperationException("Limited active checks require explicit confirmation that this target is approved for testing.");
        }

        if (!Uri.TryCreate(targetUrl, UriKind.Absolute, out Uri? target))
        {
            throw new InvalidOperationException("A valid HTTP(S) target URL is required.");
        }

        if (!_policy.TryValidate(target, out string error))
        {
            throw new InvalidOperationException(error);
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(options.MaxScanSeconds, 1, 300)));
        try
        {
            return await coordinator.ScanAsync(ScanTarget.ForWebApplication(target.AbsoluteUri, openApiDocument, enableLimitedActive), timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("The web scan exceeded its configured time limit.");
        }
    }
}
