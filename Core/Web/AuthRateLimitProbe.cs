using System.Net;
using System.Text;
using System.Text.Json;

namespace Core.Web;

public sealed record AuthRateLimitProbeRequest(
    string TargetUrl,
    string LoginPath,
    string TestUsername,
    int Attempts,
    bool ConfirmedControlledTestAccount);

public sealed record AuthRateLimitProbeResult(
    string Status,
    int AttemptsSent,
    int RateLimitedResponses,
    bool AccountLockoutObserved,
    IReadOnlyList<int> HttpStatusCodes,
    string Summary);

/// <summary>Sends a small, bounded set of failed logins using generated random passwords to a confirmed test account.</summary>
public sealed class AuthRateLimitProbe(WebScannerOptions options, HttpClient httpClient)
{
    private readonly WebTargetPolicy _policy = new(options);

    public async Task<AuthRateLimitProbeResult> RunAsync(AuthRateLimitProbeRequest request, CancellationToken cancellationToken = default)
    {
        if (!request.ConfirmedControlledTestAccount)
            throw new InvalidOperationException("Confirm that this is a dedicated test account on a system you may assess.");
        if (!Uri.TryCreate(request.TargetUrl, UriKind.Absolute, out Uri? target))
            throw new InvalidOperationException("A valid allowlisted HTTP(S) target is required.");
        if (!_policy.TryValidate(target, out string scopeError))
            throw new InvalidOperationException(scopeError);
        bool loopbackTarget = target.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
            IPAddress.TryParse(target.Host, out IPAddress? targetAddress) && IPAddress.IsLoopback(targetAddress);
        if (target.Scheme != Uri.UriSchemeHttps && !loopbackTarget)
            throw new InvalidOperationException("Login throttling checks require HTTPS for non-loopback targets.");
        if (string.IsNullOrWhiteSpace(request.TestUsername) || request.TestUsername.Length > 128)
            throw new InvalidOperationException("A test account name of 1 to 128 characters is required.");
        if (request.Attempts is < 1 || request.Attempts > Math.Clamp(options.MaxAuthProbeAttempts, 1, 5))
            throw new InvalidOperationException($"Attempt count must be from 1 to {Math.Clamp(options.MaxAuthProbeAttempts, 1, 5)}.");
        if (!request.LoginPath.StartsWith('/') || request.LoginPath.StartsWith("//", StringComparison.Ordinal) ||
            request.LoginPath.Contains('?') || request.LoginPath.Contains('#') || request.LoginPath.Contains('\\') ||
            !Uri.TryCreate(target, request.LoginPath, out Uri? loginUri) || !WebTargetPolicy.SameOrigin(target, loginUri))
            throw new InvalidOperationException("Login path must be an absolute path on the same approved origin, without query or fragment.");

        var statusCodes = new List<int>(request.Attempts);
        int rateLimited = 0;
        bool lockedOut = false;
        int delayMs = 1000 / Math.Clamp(options.RequestsPerSecond, 1, 10);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(options.MaxScanSeconds, 1, 300)));
        try
        {
            for (int index = 0; index < request.Attempts; index++)
            {
                timeout.Token.ThrowIfCancellationRequested();
                if (index > 0 && delayMs > 0)
                    await Task.Delay(delayMs, timeout.Token).ConfigureAwait(false);

                string randomInvalidPassword = $"Invalid-Test-{Guid.NewGuid():N}";
                string body = JsonSerializer.Serialize(new { username = request.TestUsername, password = randomInvalidPassword });
                using var message = new HttpRequestMessage(HttpMethod.Post, loginUri)
                {
                    Content = new StringContent(body, Encoding.UTF8, "application/json")
                };
                using HttpResponseMessage response = await httpClient.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
                int status = (int)response.StatusCode;
                statusCodes.Add(status);
                if (response.StatusCode == HttpStatusCode.TooManyRequests)
                    rateLimited++;
                if (response.StatusCode == HttpStatusCode.Locked)
                {
                    lockedOut = true;
                    break;
                }
                if (response.StatusCode == HttpStatusCode.TooManyRequests)
                    break;
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("The login throttling check exceeded its configured time limit.");
        }

        bool throttled = rateLimited > 0 || lockedOut;
        return new AuthRateLimitProbeResult(
            throttled ? "ThrottleObserved" : "NeedsReview",
            statusCodes.Count,
            rateLimited,
            lockedOut,
            statusCodes,
            throttled
                ? "The endpoint applied a rate limit or lockout during the bounded test. Review whether the control and recovery policy match your requirements."
                : "No rate limit or lockout was observed within this small test. This is not proof that brute-force protection is absent; review server-side controls and logs.");
    }
}
