using System.IO;
using System.Text.Json;

namespace Scanner.Desktop.Services;

/// <summary>Client settings loaded from appsettings.json next to the executable.</summary>
public sealed class DesktopSettings
{
    public const string DefaultServerBaseUrl = "http://localhost:5290";

    public string ServerBaseUrl { get; init; } = DefaultServerBaseUrl;

    public static DesktopSettings Load()
    {
        try
        {
            string path = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
            if (!File.Exists(path))
            {
                return new DesktopSettings();
            }

            var options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                ReadCommentHandling = JsonCommentHandling.Skip
            };
            return JsonSerializer.Deserialize<DesktopSettings>(File.ReadAllText(path), options) ?? new DesktopSettings();
        }
        catch
        {
            // A broken settings file must never keep the app from starting.
            return new DesktopSettings();
        }
    }

    /// <summary>Returns an absolute http(s) base URL, falling back to the default.</summary>
    public Uri ResolveServerBaseAddress()
    {
        if (Uri.TryCreate(ServerBaseUrl, UriKind.Absolute, out Uri? address)
            && (address.Scheme == Uri.UriSchemeHttp || address.Scheme == Uri.UriSchemeHttps))
        {
            return address;
        }

        return new Uri(DefaultServerBaseUrl);
    }
}
