using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using Scanner.Desktop.Models;

namespace Scanner.Desktop.Services;

public class ScannerApiClient : IScannerApiClient
{
    private readonly HttpClient _httpClient;
    private readonly JsonSerializerOptions _jsonOptions;

    public ScannerApiClient(HttpClient httpClient, DesktopSettings settings)
    {
        _httpClient = httpClient;
        _httpClient.BaseAddress = settings.ResolveServerBaseAddress();
        _httpClient.Timeout = TimeSpan.FromMinutes(5);

        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        };
    }

    public async Task<ScanResult?> ScanFileAsync(string filePath, CancellationToken cancellationToken = default)
    {
        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException("File not found", filePath);
        }

        using var content = new MultipartFormDataContent();
        await using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var fileContent = new StreamContent(stream);
        fileContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
        content.Add(fileContent, "file", Path.GetFileName(filePath));

        using var response = await _httpClient.PostAsync("/api/scan/file", content, cancellationToken);
        await EnsureSuccessAsync(response, "File", cancellationToken);

        return await response.Content.ReadFromJsonAsync<ScanResult>(_jsonOptions, cancellationToken);
    }

    public async Task<ArchiveScanResult?> ScanArchiveAsync(string archivePath, CancellationToken cancellationToken = default)
    {
        if (!File.Exists(archivePath))
        {
            throw new FileNotFoundException("Archive not found", archivePath);
        }

        using var content = new MultipartFormDataContent();
        await using var stream = new FileStream(archivePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var fileContent = new StreamContent(stream);
        fileContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/zip");
        content.Add(fileContent, "file", Path.GetFileName(archivePath));

        using var response = await _httpClient.PostAsync("/api/scan/archive", content, cancellationToken);
        await EnsureSuccessAsync(response, "Archive", cancellationToken);

        return await response.Content.ReadFromJsonAsync<ArchiveScanResult>(_jsonOptions, cancellationToken);
    }

    private async Task EnsureSuccessAsync(
        HttpResponseMessage response,
        string resourceName,
        CancellationToken cancellationToken)
    {
        if (response.IsSuccessStatusCode)
        {
            return;
        }

        string? serverError = null;
        try
        {
            ApiError? error = await response.Content.ReadFromJsonAsync<ApiError>(_jsonOptions, cancellationToken);
            serverError = error?.Error;
        }
        catch
        {
            // The server did not return a JSON error body.
        }

        string message = response.StatusCode switch
        {
            HttpStatusCode.RequestEntityTooLarge => $"{resourceName} is too large for the configured limit.",
            HttpStatusCode.UnsupportedMediaType => $"{resourceName} type is not supported.",
            HttpStatusCode.TooManyRequests => "Rate limit exceeded. Please wait and try again.",
            HttpStatusCode.RequestTimeout => "The scan exceeded the server time limit.",
            HttpStatusCode.Forbidden => "The scan API is available only from the local machine.",
            HttpStatusCode.NotFound => serverError ?? "The requested file or endpoint was not found.",
            _ => serverError ?? $"Server returned HTTP {(int)response.StatusCode} ({response.ReasonPhrase})."
        };

        throw new InvalidOperationException(message);
    }

    public async Task<bool> CheckHealthAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var response = await _httpClient.GetAsync("/api/scan/health", cancellationToken);
            return response.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }

    private sealed record ApiError(string? Error);
}
