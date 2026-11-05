namespace Server.DTOs;

public sealed record AuthRateLimitRequest(
    string TargetUrl,
    string LoginPath,
    string TestUsername,
    int Attempts,
    bool ConfirmedControlledTestAccount);
