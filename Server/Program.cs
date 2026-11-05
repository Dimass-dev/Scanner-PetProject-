using Core.Modules;
using Core.Scanning;
using Core.Web;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
using Server.DTOs;
using Server.Services;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;

var builder = WebApplication.CreateBuilder(args);
builder.Logging.ClearProviders();
builder.Logging.AddConsole();

// Configuration
builder.Services.AddOptions<Server.Options.ScannerOptions>()
    .Bind(builder.Configuration.GetSection(Server.Options.ScannerOptions.SectionName))
    .ValidateDataAnnotations()
    .ValidateOnStart();

var scannerOptions = builder.Configuration
    .GetSection(Server.Options.ScannerOptions.SectionName)
    .Get<Server.Options.ScannerOptions>() ?? new();

// Kestrel defaults to ~30 MB, which would reject the configured 200 MB archive upload.
const long multipartOverheadBytes = 1024 * 1024;
long maxRequestBodyBytes = scannerOptions.MaxArchiveBytes + multipartOverheadBytes;

builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = maxRequestBodyBytes;
});

builder.Services.Configure<FormOptions>(options =>
{
    options.MultipartBodyLengthLimit = maxRequestBodyBytes;
});

// Core services
builder.Services.AddSingleton(scannerOptions);
builder.Services.AddSingleton<TempStorage>();

// Scanner infrastructure
var peScanModule = PeScanModule.CreateDefault(scannerOptions.CatalogBasePath);
var webScannerOptions = builder.Configuration.GetSection("WebScanner").Get<WebScannerOptions>() ?? new WebScannerOptions();
var webHttpClient = ScopedHttpClientFactory.Create(webScannerOptions);
var webScanModule = new Core.Modules.WebScanModule(webScannerOptions, webHttpClient);
var coordinator = new ScanCoordinator(new IScanModule[] { peScanModule, webScanModule });

builder.Services.AddSingleton(coordinator);
builder.Services.AddSingleton(webScannerOptions);
builder.Services.AddSingleton(webHttpClient);
builder.Services.AddSingleton<Core.Web.AuthRateLimitProbe>();
builder.Services.AddSingleton<FileScanService>();
builder.Services.AddSingleton<WebScanService>();
builder.Services.AddSingleton<ArchiveService>();

// Rate limiting configuration
var permitLimit = builder.Configuration.GetValue<int>("RateLimit:PermitLimit", 10);
var windowSeconds = builder.Configuration.GetValue<int>("RateLimit:WindowSeconds", 60);

builder.Services.AddRateLimiter(options =>
{
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
    {
        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = permitLimit,
                Window = TimeSpan.FromSeconds(windowSeconds),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 2
            });
    });

    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
});

// CORS
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.WithOrigins("http://localhost:5173", "http://localhost:3000")
            .AllowAnyMethod()
            .AllowAnyHeader();
    });
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddOpenApi();

var app = builder.Build();

// Middleware
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

if (!app.Environment.IsDevelopment() || app.Urls.Any(url =>
        Uri.TryCreate(url, UriKind.Absolute, out Uri? address) && address.Scheme == Uri.UriSchemeHttps))
{
    app.UseHttpsRedirection();
}
app.UseCors();
app.UseRateLimiter();

// This desktop-oriented scanner is local-only by default. Do not expose scan endpoints on a LAN.
app.Use(async (context, next) =>
{
    if (context.Request.Path.StartsWithSegments("/api/scan"))
    {
        System.Net.IPAddress? remoteAddress = context.Connection.RemoteIpAddress;
        if (remoteAddress is null || !System.Net.IPAddress.IsLoopback(remoteAddress.IsIPv4MappedToIPv6 ? remoteAddress.MapToIPv4() : remoteAddress))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsJsonAsync(new { error = "Scan API is available only from the local machine." });
            return;
        }
    }

    await next();
});

// Exception handling
app.Use(async (context, next) =>
{
    try
    {
        await next();
    }
    catch (Exception ex)
    {
        int statusCode = ex switch
        {
            FileNotFoundException => StatusCodes.Status404NotFound,
            InvalidOperationException => StatusCodes.Status400BadRequest,
            TimeoutException => StatusCodes.Status408RequestTimeout,
            _ => StatusCodes.Status500InternalServerError
        };

        context.Response.StatusCode = statusCode;

        string errorMessage = app.Environment.IsDevelopment() || statusCode != StatusCodes.Status500InternalServerError
            ? ex.Message
            : "An unexpected server error occurred.";

        await context.Response.WriteAsJsonAsync(new { error = errorMessage });
    }
});

// Endpoints
app.MapPost("/api/scan/file", async (
    [FromForm] IFormFile file,
    FileScanService scanService,
    TempStorage tempStorage,
    Server.Options.ScannerOptions scannerOptions,
    CancellationToken cancellationToken) =>
{
    if (file == null || file.Length == 0)
    {
        return Results.BadRequest(new { error = "No file provided" });
    }

    if (file.Length > scannerOptions.MaxFileBytes)
    {
        return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
    }

    string tempDir = tempStorage.CreateScanDirectory();
    string tempPath = Path.Combine(tempDir, $"{Guid.NewGuid():N}.bin");

    try
    {
        using (var stream = new FileStream(tempPath, FileMode.Create))
        {
            await file.CopyToAsync(stream, cancellationToken);
        }

        var report = await scanService.ScanFileAsync(tempPath, cancellationToken);
        var response = ScanFileResponse.FromReport(Guid.NewGuid().ToString(), file.FileName, tempPath, report, file.Length);

        return Results.Ok(response);
    }
    finally
    {
        tempStorage.DeleteScanDirectory(tempDir);
    }
})
.DisableAntiforgery();

app.MapPost("/api/scan/archive", async (
    [FromForm] IFormFile file,
    ArchiveService archiveService,
    TempStorage tempStorage,
    Server.Options.ScannerOptions scannerOptions,
    CancellationToken cancellationToken) =>
{
    if (file == null || file.Length == 0)
    {
        return Results.BadRequest(new { error = "No file provided" });
    }

    if (file.Length > scannerOptions.MaxArchiveBytes)
    {
        return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
    }

    if (!file.FileName.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
    {
        return Results.StatusCode(StatusCodes.Status415UnsupportedMediaType);
    }

    string tempDir = tempStorage.CreateScanDirectory();
    string tempPath = Path.Combine(tempDir, $"{Guid.NewGuid():N}.zip");

    try
    {
        using (var stream = new FileStream(tempPath, FileMode.Create))
        {
            await file.CopyToAsync(stream, cancellationToken);
        }

        var result = await archiveService.ScanArchiveAsync(tempPath, cancellationToken);
        var response = ArchiveScanResponse.FromResult(Guid.NewGuid().ToString(), file.FileName, result);

        return Results.Ok(response);
    }
    finally
    {
        tempStorage.DeleteScanDirectory(tempDir);
    }
})
.DisableAntiforgery();

app.MapPost("/api/scan/web", async (
    WebScanRequest request,
    WebScanService webScanService,
    CancellationToken cancellationToken) =>
{
    if (string.IsNullOrWhiteSpace(request.TargetUrl))
        return Results.BadRequest(new { error = "TargetUrl is required." });

    if (request.OpenApiDocument?.Length > 1_048_576)
        return Results.BadRequest(new { error = "OpenAPI document exceeds the 1 MiB limit." });

    var report = await webScanService.ScanAsync(
        request.TargetUrl,
        request.OpenApiDocument,
        request.EnableLimitedActive,
        request.ConfirmedActiveTest,
        cancellationToken);
    var targetUri = new Uri(request.TargetUrl);
    return Results.Ok(WebScanResponse.FromReport(Guid.NewGuid().ToString(), targetUri.GetLeftPart(UriPartial.Authority), report));
});

app.MapPost("/api/scan/web/auth-rate-limit", async (
    AuthRateLimitRequest request,
    Core.Web.AuthRateLimitProbe probe,
    CancellationToken cancellationToken) =>
{
    var probeRequest = new Core.Web.AuthRateLimitProbeRequest(
        request.TargetUrl,
        request.LoginPath,
        request.TestUsername,
        request.Attempts,
        request.ConfirmedControlledTestAccount);
    return Results.Ok(await probe.RunAsync(probeRequest, cancellationToken));
});

app.MapGet("/api/scan/health", () => Results.Ok(new
{
    status = "healthy",
    timestamp = DateTime.UtcNow,
    version = "0.1.0"
}));

app.Run();
