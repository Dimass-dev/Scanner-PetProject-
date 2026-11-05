namespace Core.Web;

/// <summary>Conservative limits and explicitly approved web origins for a scan.</summary>
public sealed class WebScannerOptions
{
    public List<string> AllowedOrigins { get; set; } =
    [
        "http://localhost:5290",
        "http://127.0.0.1:5290",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://localhost:7268",
        "https://127.0.0.1:7268"
    ];

    public bool AllowPrivateNetworkTargets { get; set; }
    public int MaxPages { get; set; } = 8;
    public int MaxRequests { get; set; } = 20;
    public int MaxRedirects { get; set; } = 2;
    public int MaxResponseBytes { get; set; } = 1_048_576;
    public int RequestsPerSecond { get; set; } = 2;
    public int TimeoutSeconds { get; set; } = 20;
    public int MaxScanSeconds { get; set; } = 60;
    public int MaxAuthProbeAttempts { get; set; } = 5;
    public int MaxActiveProbes { get; set; } = 3;
}
