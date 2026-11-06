using System.Net;
using System.Net.Sockets;

namespace Core.Web;

/// <summary>Creates an HTTP client that pins each connection to an IP validated against the target policy.</summary>
public static class ScopedHttpClientFactory
{
    public static HttpClient Create(WebScannerOptions options)
    {
        var policy = new WebTargetPolicy(options);
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = false,
            ConnectTimeout = TimeSpan.FromSeconds(Math.Clamp(options.TimeoutSeconds, 1, 120)),
            ConnectCallback = async (context, cancellationToken) =>
            {
                Uri requestUri = context.InitialRequestMessage.RequestUri
                    ?? throw new HttpRequestException("The request URL is missing.");

                if (!policy.TryValidate(requestUri, out string validationError))
                {
                    throw new HttpRequestException(validationError);
                }

                IPAddress[] addresses = IPAddress.TryParse(requestUri.Host, out var literalAddress)
                    ? [literalAddress]
                    : await Dns.GetHostAddressesAsync(requestUri.DnsSafeHost, cancellationToken).ConfigureAwait(false);

                addresses = policy.ValidateResolvedAddresses(requestUri, addresses);

                Exception? lastError = null;
                foreach (IPAddress address in addresses)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var client = new TcpClient(address.AddressFamily);
                    try
                    {
                        await client.ConnectAsync(address, context.DnsEndPoint.Port, cancellationToken).ConfigureAwait(false);
                        return client.GetStream();
                    }
                    catch (Exception exception) when (exception is SocketException or OperationCanceledException)
                    {
                        client.Dispose();
                        lastError = exception;
                        if (exception is OperationCanceledException)
                        {
                            throw;
                        }
                    }
                }

                throw new HttpRequestException("Could not connect to an approved target address.", lastError);
            }
        };

        return new HttpClient(handler, disposeHandler: true)
        {
            Timeout = TimeSpan.FromSeconds(Math.Clamp(options.TimeoutSeconds, 1, 120))
        };
    }
}
