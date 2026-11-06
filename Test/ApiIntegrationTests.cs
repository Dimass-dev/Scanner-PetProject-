using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Xunit;

namespace Scanner.Tests;

public sealed class ApiIntegrationTests
{
    [Fact]
    public async Task Health_ReturnsHealthy()
    {
        await using var factory = new ScannerApiFactory();
        using HttpClient client = factory.CreateClient();

        using HttpResponseMessage response = await client.GetAsync("/api/scan/health");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using JsonDocument document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("healthy", document.RootElement.GetProperty("status").GetString());
    }

    [Fact]
    public async Task ScanFile_ValidPe_ReturnsReportAndFileSize()
    {
        await using var factory = new ScannerApiFactory();
        using HttpClient client = factory.CreateClient();

        byte[] pe = PeBuilder.CreatePe64();
        using HttpResponseMessage response = await client.PostAsync(
            "/api/scan/file",
            CreateFileContent(pe, "sample.exe"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using JsonDocument document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        JsonElement root = document.RootElement;
        Assert.Equal("sample.exe", root.GetProperty("fileName").GetString());
        Assert.Equal(pe.Length, root.GetProperty("fileSize").GetInt64());
        Assert.True(root.TryGetProperty("risk", out _));
        Assert.True(root.TryGetProperty("findings", out _));
    }

    [Fact]
    public async Task ScanFile_BadMagic_ReturnsBadRequest()
    {
        await using var factory = new ScannerApiFactory();
        using HttpClient client = factory.CreateClient();

        using HttpResponseMessage response = await client.PostAsync(
            "/api/scan/file",
            CreateFileContent("not a pe"u8.ToArray(), "sample.exe"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task ScanFile_TooLarge_ReturnsPayloadTooLarge()
    {
        await using var factory = new ScannerApiFactory(new Dictionary<string, string?>
        {
            ["Scanner:MaxFileBytes"] = "1024"
        });
        using HttpClient client = factory.CreateClient();

        using HttpResponseMessage response = await client.PostAsync(
            "/api/scan/file",
            CreateFileContent(new byte[2048], "sample.exe"));

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
    }

    [Fact]
    public async Task ScanArchive_ValidZip_ScansPeEntry()
    {
        await using var factory = new ScannerApiFactory();
        using HttpClient client = factory.CreateClient();

        byte[] archive = CreateZip(("good.exe", PeBuilder.CreatePe64()));
        using HttpResponseMessage response = await client.PostAsync(
            "/api/scan/archive",
            CreateFileContent(archive, "bundle.zip"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using JsonDocument document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        JsonElement root = document.RootElement;
        Assert.Equal(1, root.GetProperty("extractedFileCount").GetInt32());
        Assert.Equal(1, root.GetProperty("scannedFileCount").GetInt32());
        Assert.Single(root.GetProperty("files").EnumerateArray());
    }

    [Fact]
    public async Task ScanArchive_ZipSlip_IsRejectedAsExtractionError()
    {
        await using var factory = new ScannerApiFactory();
        using HttpClient client = factory.CreateClient();

        byte[] archive = CreateZip(("../evil.exe", PeBuilder.CreatePe64()));
        using HttpResponseMessage response = await client.PostAsync(
            "/api/scan/archive",
            CreateFileContent(archive, "bundle.zip"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using JsonDocument document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        string[] errors = document.RootElement
            .GetProperty("extractionErrors")
            .EnumerateArray()
            .Select(e => e.GetString() ?? string.Empty)
            .ToArray();

        Assert.Contains(errors, error => error.Contains("traversal", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ScanArchive_EntryTooLarge_IsRejectedAsExtractionError()
    {
        await using var factory = new ScannerApiFactory(new Dictionary<string, string?>
        {
            ["Scanner:MaxEntryBytes"] = "100",
            ["Scanner:MaxCompressionRatio"] = "1000"
        });
        using HttpClient client = factory.CreateClient();

        byte[] archive = CreateZip(("large.exe", new byte[200]));
        using HttpResponseMessage response = await client.PostAsync(
            "/api/scan/archive",
            CreateFileContent(archive, "bundle.zip"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using JsonDocument document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        string[] errors = document.RootElement
            .GetProperty("extractionErrors")
            .EnumerateArray()
            .Select(e => e.GetString() ?? string.Empty)
            .ToArray();

        Assert.Contains(errors, error => error.Contains("too large", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ScanArchive_TooLargeArchive_ReturnsPayloadTooLarge()
    {
        await using var factory = new ScannerApiFactory(new Dictionary<string, string?>
        {
            ["Scanner:MaxArchiveBytes"] = "1024"
        });
        using HttpClient client = factory.CreateClient();

        using HttpResponseMessage response = await client.PostAsync(
            "/api/scan/archive",
            CreateFileContent(new byte[2048], "bundle.zip"));

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
    }

    [Fact]
    public async Task ScanArchive_NonZipExtension_ReturnsUnsupportedMediaType()
    {
        await using var factory = new ScannerApiFactory();
        using HttpClient client = factory.CreateClient();

        using HttpResponseMessage response = await client.PostAsync(
            "/api/scan/archive",
            CreateFileContent(PeBuilder.CreatePe64(), "bundle.txt"));

        Assert.Equal(HttpStatusCode.UnsupportedMediaType, response.StatusCode);
    }

    [Fact]
    public async Task ScanApi_FromNonLoopback_IsForbidden()
    {
        await using var factory = new ScannerApiFactory(useLoopbackRemoteAddress: false);
        using HttpClient client = factory.CreateClient();

        using HttpResponseMessage response = await client.GetAsync("/api/scan/health");
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    private static MultipartFormDataContent CreateFileContent(byte[] content, string fileName)
    {
        var fileContent = new ByteArrayContent(content);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");

        var form = new MultipartFormDataContent();
        form.Add(fileContent, "file", fileName);
        return form;
    }

    private static byte[] CreateZip(params (string Name, byte[] Content)[] entries)
    {
        using var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, content) in entries)
            {
                ZipArchiveEntry entry = archive.CreateEntry(name, CompressionLevel.Fastest);
                using Stream entryStream = entry.Open();
                entryStream.Write(content);
            }
        }

        return stream.ToArray();
    }
}
