using System.Net;
using System.Net.Sockets;

namespace Core.Web;

/// <summary>Validates exact configured origins and the IP addresses used to connect to them.</summary>
public sealed class WebTargetPolicy(WebScannerOptions options)
{
    public bool TryValidate(Uri? target, out string error)
    {
        if (target is null || !target.IsAbsoluteUri ||
            (target.Scheme != Uri.UriSchemeHttp && target.Scheme != Uri.UriSchemeHttps))
        {
            error = "Only absolute HTTP and HTTPS URLs are accepted.";
            return false;
        }

        if (!string.IsNullOrEmpty(target.UserInfo) || !string.IsNullOrEmpty(target.Fragment))
        {
            error = "URLs containing credentials or fragments are not accepted.";
            return false;
        }

        if (!IsOriginAllowed(target))
        {
            error = "The target origin is not in the WebScanner:AllowedOrigins allowlist.";
            return false;
        }

        error = string.Empty;
        return true;
    }

    public bool IsOriginAllowed(Uri uri) => options.AllowedOrigins
        .Select(TryParseOrigin)
        .Where(origin => origin is not null)
        .Any(origin => SameOrigin(origin!, uri));

    public bool IsAddressAllowed(Uri uri, IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();

        bool isLoopbackHost = uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
            IPAddress.TryParse(uri.Host, out var targetIp) && IPAddress.IsLoopback(targetIp);

        if (isLoopbackHost)
            return IPAddress.IsLoopback(address);

        if (!options.AllowPrivateNetworkTargets && IsNonPublicAddress(address))
            return false;

        return true;
    }

    public IPAddress[] ValidateResolvedAddresses(Uri uri, IEnumerable<IPAddress> addresses)
    {
        if (!TryValidate(uri, out string error))
            throw new HttpRequestException(error);

        IPAddress[] resolved = addresses.ToArray();
        if (resolved.Length == 0 || resolved.Any(address => !IsAddressAllowed(uri, address)))
            throw new HttpRequestException("The target hostname resolves to a blocked address.");

        return resolved;
    }

    public static bool SameOrigin(Uri left, Uri right) =>
        left.Scheme.Equals(right.Scheme, StringComparison.OrdinalIgnoreCase) &&
        left.IdnHost.Equals(right.IdnHost, StringComparison.OrdinalIgnoreCase) &&
        left.Port == right.Port;

    public static bool IsNonPublicAddress(IPAddress address)
    {
        if (IPAddress.IsLoopback(address) || address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6Multicast)
            return true;

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            byte[] v6Bytes = address.GetAddressBytes();
            return v6Bytes[0] == 0x00 || (v6Bytes[0] & 0xFE) == 0xFC ||
                v6Bytes[0] == 0xFE && (v6Bytes[1] & 0xC0) == 0x80 ||
                v6Bytes[0] == 0xFF ||
                v6Bytes[0] == 0x20 && v6Bytes[1] == 0x01 && v6Bytes[2] == 0x0D && v6Bytes[3] == 0xB8;
        }

        if (address.AddressFamily != AddressFamily.InterNetwork)
            return true;

        byte[] bytes = address.GetAddressBytes();
        return bytes[0] == 0 || bytes[0] >= 224 ||
            bytes[0] == 10 ||
            bytes[0] == 172 && bytes[1] is >= 16 and <= 31 ||
            bytes[0] == 192 && bytes[1] == 168 ||
            bytes[0] == 192 && bytes[1] == 0 && bytes[2] == 0 ||
            bytes[0] == 192 && bytes[1] == 0 && bytes[2] == 2 ||
            bytes[0] == 192 && bytes[1] == 88 && bytes[2] == 99 ||
            bytes[0] == 198 && bytes[1] is 18 or 19 ||
            bytes[0] == 198 && bytes[1] == 51 && bytes[2] == 100 ||
            bytes[0] == 203 && bytes[1] == 0 && bytes[2] == 113 ||
            bytes[0] == 169 && bytes[1] == 254 ||
            bytes[0] == 100 && bytes[1] is >= 64 and <= 127;
    }

    private static Uri? TryParseOrigin(string origin)
    {
        if (!Uri.TryCreate(origin, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) ||
            !string.IsNullOrEmpty(uri.UserInfo) || uri.AbsolutePath != "/" ||
            !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
            return null;

        return uri;
    }
}
