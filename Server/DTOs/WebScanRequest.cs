namespace Server.DTOs;

public sealed record WebScanRequest(
    string TargetUrl,
    string? OpenApiDocument = null,
    bool EnableLimitedActive = false,
    bool ConfirmedActiveTest = false);
