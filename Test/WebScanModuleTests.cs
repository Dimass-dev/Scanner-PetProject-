using System.Net;
using System.Net.Http.Headers;
using Core.Modules;
using Core.Scanning;
using Core.Web;

namespace Scanner.Tests;

public sealed class WebScanModuleTests
{
    [Fact]
    public async Task ScanAsync_RejectsOriginOutsideAllowlistBeforeSendingRequests()
    {
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        using var client = new HttpClient(handler);
        var module = new WebScanModule(new WebScannerOptions { AllowedOrigins = ["http://localhost:8080"] }, client);

        ScanModuleResult result = await module.ScanAsync(ScanTarget.ForWebApplication("http://127.0.0.1:8080/"));

        Assert.Equal(ScanStatus.Failed, result.Status);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task ScanAsync_UsesOnlyGetAndFollowsBoundedSameOriginLinks()
    {
        var handler = new RecordingHandler(request =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                RequestMessage = request,
                Content = new StringContent(request.RequestUri!.AbsolutePath == "/"
                    ? "<html><a href='/about'>About</a><a href='http://127.0.0.1:9999/escape'>Outside</a></html>"
                    : "<html>About</html>")
            };
            response.Content.Headers.ContentType = new MediaTypeHeaderValue("text/html");
            response.Headers.Add("Set-Cookie", "session=secret-value; Path=/");
            response.Headers.Add("X-Powered-By", "Fixture");
            return response;
        });
        using var client = new HttpClient(handler);
        var module = new WebScanModule(new WebScannerOptions
        {
            AllowedOrigins = ["http://127.0.0.1:8080"],
            MaxPages = 4,
            MaxRequests = 8,
            RequestsPerSecond = 10
        }, client);

        ScanModuleResult result = await module.ScanAsync(ScanTarget.ForWebApplication("http://127.0.0.1:8080/"));

        Assert.Equal(ScanStatus.Succeeded, result.Status);
        Assert.Equal(2, handler.Requests.Count);
        Assert.All(handler.Requests, request => Assert.Equal(HttpMethod.Get, request.Method));
        Assert.Contains(result.Findings, finding => finding.RuleId == "WEB-COOKIE-002");
        Assert.Contains(result.Findings, finding => finding.RuleId == "WEB-INFO-001");
        Assert.DoesNotContain(result.Findings, finding => finding.Evidence?.Contains("secret-value", StringComparison.Ordinal) == true);
        Assert.Contains(result.Artifacts, artifact => artifact.Kind == "web.coverage");
    }

    [Fact]
    public async Task ScanAsync_DoesNotFollowRedirectOutsideApprovedOrigin()
    {
        var handler = new RecordingHandler(request =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.Redirect) { RequestMessage = request };
            response.Headers.Location = new Uri("http://127.0.0.1:9999/outside");
            return response;
        });
        using var client = new HttpClient(handler);
        var module = new WebScanModule(new WebScannerOptions { AllowedOrigins = ["http://127.0.0.1:8080"] }, client);

        ScanModuleResult result = await module.ScanAsync(ScanTarget.ForWebApplication("http://127.0.0.1:8080/"));

        Assert.Single(handler.Requests);
        Assert.Contains(result.Findings, finding => finding.RuleId == "WEB-SCOPE-001");
    }

    [Fact]
    public async Task ScanAsync_ReviewsOpenApiWithoutCallingDocumentedMutatingOperations()
    {
        var handler = new RecordingHandler(request => new HttpResponseMessage(HttpStatusCode.OK)
        {
            RequestMessage = request,
            Content = new StringContent("<html>API fixture</html>")
        });
        using var client = new HttpClient(handler);
        var module = new WebScanModule(new WebScannerOptions { AllowedOrigins = ["http://127.0.0.1:8080"] }, client);
        const string spec = """
            {"openapi":"3.0.3","paths":{"/public":{"get":{"responses":{"200":{"description":"ok"}}}},"/users":{"post":{"responses":{"201":{"description":"created"}}}}}}
            """;

        ScanModuleResult result = await module.ScanAsync(ScanTarget.ForWebApplication("http://127.0.0.1:8080/", spec));

        Assert.Single(handler.Requests);
        Assert.Contains(result.Findings, finding => finding.RuleId == "WEB-API-003");
        Assert.Contains(result.Findings, finding => finding.RuleId == "WEB-API-004");
        var inventory = Assert.Single(result.Artifacts, artifact => artifact.Kind == "web.openapi");
        Assert.Equal("0", inventory.Properties["LiveOperationsProbed"]);
    }

    [Fact]
    public async Task ScanAsync_LimitedActiveProbeOnlyChecksDiscoveredGetQueryForErrorDisclosure()
    {
        var handler = new RecordingHandler(request =>
        {
            bool probe = request.RequestUri!.Query.Contains("%27", StringComparison.OrdinalIgnoreCase) || request.RequestUri.Query.Contains('\'');
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                RequestMessage = request,
                Content = new StringContent(probe ? "SQLite error near token" : "<html>Catalog</html>")
            };
        });
        using var client = new HttpClient(handler);
        var module = new WebScanModule(new WebScannerOptions
        {
            AllowedOrigins = ["http://127.0.0.1:8080"],
            RequestsPerSecond = 10,
            MaxActiveProbes = 1
        }, client);

        ScanModuleResult result = await module.ScanAsync(ScanTarget.ForWebApplication("http://127.0.0.1:8080/catalog?id=1", enableLimitedActive: true));

        Assert.Equal(2, handler.Requests.Count);
        Assert.Contains(result.Findings, finding => finding.RuleId == "WEB-INJ-001");
    }

    [Fact]
    public async Task ScanAsync_LimitedActiveHtmlProbeReportsOnlyRawInertMarkerReflection()
    {
        var handler = new RecordingHandler(request =>
        {
            string query = Uri.UnescapeDataString(request.RequestUri!.Query);
            string body = "<html>fixture</html>";
            int markerStart = query.IndexOf("<scanner-probe-", StringComparison.Ordinal);
            if (markerStart >= 0)
            {
                int markerEnd = query.IndexOf('>', markerStart);
                body = $"<html>{query[markerStart..(markerEnd + 1)]}</html>";
            }
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                RequestMessage = request,
                Content = new StringContent(body)
            };
            response.Content.Headers.ContentType = new MediaTypeHeaderValue("text/html");
            return response;
        });
        using var client = new HttpClient(handler);
        var module = new WebScanModule(new WebScannerOptions
        {
            AllowedOrigins = ["http://127.0.0.1:8080"],
            RequestsPerSecond = 10,
            MaxActiveProbes = 2
        }, client);

        ScanModuleResult result = await module.ScanAsync(ScanTarget.ForWebApplication(
            "http://127.0.0.1:8080/search?q=safe", enableLimitedActive: true));

        Assert.Equal(3, handler.Requests.Count);
        Assert.Contains(result.Findings, finding => finding.RuleId == "WEB-XSS-001");
    }

    [Fact]
    public async Task ScanAsync_LimitedActiveChecksDocumentedProtectedGetWithoutCredentials()
    {
        var handler = new RecordingHandler(request => new HttpResponseMessage(HttpStatusCode.OK)
        {
            RequestMessage = request,
            Content = new StringContent("<html>fixture</html>")
        });
        using var client = new HttpClient(handler);
        var module = new WebScanModule(new WebScannerOptions
        {
            AllowedOrigins = ["http://127.0.0.1:8080"],
            RequestsPerSecond = 10,
            MaxActiveProbes = 1
        }, client);
        const string spec = """
            {"openapi":"3.0.3","security":[{"bearerAuth":[]}],"servers":[{"url":"/api"}],"paths":{"/private":{"get":{"responses":{"200":{"description":"ok"}}}}}}
            """;

        ScanModuleResult result = await module.ScanAsync(ScanTarget.ForWebApplication(
            "http://127.0.0.1:8080/", spec, enableLimitedActive: true));

        Assert.Equal(2, handler.Requests.Count);
        Assert.Contains(handler.Requests, request => request.RequestUri!.AbsolutePath == "/api/private");
        Assert.Contains(result.Findings, finding => finding.RuleId == "WEB-API-006");
    }

    [Fact]
    public async Task ScanAsync_LimitedActiveReportsDocumentedJsonSchemaMismatch()
    {
        var handler = new RecordingHandler(request =>
        {
            bool apiRoute = request.RequestUri!.AbsolutePath == "/api/user";
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                RequestMessage = request,
                Content = new StringContent(apiRoute ? "{\"id\":\"wrong-type\"}" : "<html>fixture</html>")
            };
            response.Content.Headers.ContentType = new MediaTypeHeaderValue(apiRoute ? "application/json" : "text/html");
            return response;
        });
        using var client = new HttpClient(handler);
        var module = new WebScanModule(new WebScannerOptions
        {
            AllowedOrigins = ["http://127.0.0.1:8080"],
            RequestsPerSecond = 10,
            MaxActiveProbes = 1
        }, client);
        const string spec = """
            {"openapi":"3.0.3","paths":{"/api/user":{"get":{"responses":{"200":{"description":"user","content":{"application/json":{"schema":{"type":"object","required":["id"],"properties":{"id":{"type":"integer"}}}}}}}}}}}
            """;

        ScanModuleResult result = await module.ScanAsync(ScanTarget.ForWebApplication(
            "http://127.0.0.1:8080/", spec, enableLimitedActive: true));

        Assert.Contains(result.Findings, finding => finding.RuleId == "WEB-API-009");
    }

    [Fact]
    public async Task ScanAsync_NeverFetchesExternalOpenApiReferencesOrServers()
    {
        var handler = new RecordingHandler(request => new HttpResponseMessage(HttpStatusCode.OK)
        {
            RequestMessage = request,
            Content = new StringContent("<html>fixture</html>")
        });
        using var client = new HttpClient(handler);
        var module = new WebScanModule(new WebScannerOptions { AllowedOrigins = ["http://127.0.0.1:8080"] }, client);
        const string spec = """
            {"openapi":"3.0.3","servers":[{"url":"https://external.example/api"}],"paths":{"/private":{"$ref":"https://external.example/path.json#/route"}}}
            """;

        ScanModuleResult result = await module.ScanAsync(ScanTarget.ForWebApplication("http://127.0.0.1:8080/", spec, enableLimitedActive: true));

        Assert.Single(handler.Requests);
        Assert.Contains(result.Findings, finding => finding.RuleId == "WEB-API-002");
        Assert.Contains(result.Findings, finding => finding.RuleId == "WEB-API-005");
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("10.20.30.40")]
    [InlineData("172.20.1.2")]
    [InlineData("192.168.1.10")]
    [InlineData("169.254.169.254")]
    [InlineData("100.100.100.200")]
    [InlineData("2001:db8::1")]
    public void IsNonPublicAddress_BlocksNonPublicAndMetadataRanges(string address)
    {
        Assert.True(WebTargetPolicy.IsNonPublicAddress(IPAddress.Parse(address)));
    }

    [Fact]
    public void ValidateResolvedAddresses_RejectsPrivateAddressMixedIntoPublicDnsAnswer()
    {
        var policy = new WebTargetPolicy(new WebScannerOptions { AllowedOrigins = ["https://scanner-test.example"] });
        Uri target = new("https://scanner-test.example/");

        Assert.Single(policy.ValidateResolvedAddresses(target, [IPAddress.Parse("8.8.8.8")]));
        Assert.Throws<HttpRequestException>(() => policy.ValidateResolvedAddresses(target,
        [
            IPAddress.Parse("8.8.8.8"),
            IPAddress.Parse("169.254.169.254")
        ]));
    }

    [Fact]
    public async Task AuthProbe_StopsAtRateLimitAndUsesGeneratedPasswords()
    {
        var bodies = new List<string>();
        var handler = new RecordingHandler(request =>
        {
            bodies.Add(request.Content!.ReadAsStringAsync().GetAwaiter().GetResult());
            return new HttpResponseMessage(bodies.Count == 3 ? HttpStatusCode.TooManyRequests : HttpStatusCode.Unauthorized);
        });
        using var client = new HttpClient(handler);
        var probe = new AuthRateLimitProbe(new WebScannerOptions
        {
            AllowedOrigins = ["http://127.0.0.1:8080"],
            RequestsPerSecond = 10,
            MaxAuthProbeAttempts = 5
        }, client);

        AuthRateLimitProbeResult result = await probe.RunAsync(new AuthRateLimitProbeRequest(
            "http://127.0.0.1:8080", "/api/login", "test-account", 5, true));

        Assert.Equal("ThrottleObserved", result.Status);
        Assert.Equal(3, result.AttemptsSent);
        Assert.Equal(3, handler.Requests.Count);
        Assert.All(handler.Requests, request => Assert.Equal(HttpMethod.Post, request.Method));
        Assert.NotEqual(bodies[0], bodies[1]);
        Assert.DoesNotContain("test-account", result.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AuthProbe_RequiresExplicitConfirmationBeforeSendingRequests()
    {
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.Unauthorized));
        using var client = new HttpClient(handler);
        var probe = new AuthRateLimitProbe(new WebScannerOptions { AllowedOrigins = ["http://127.0.0.1:8080"] }, client);

        await Assert.ThrowsAsync<InvalidOperationException>(() => probe.RunAsync(new AuthRateLimitProbeRequest(
            "http://127.0.0.1:8080", "/login", "test-account", 1, false)));

        Assert.Empty(handler.Requests);
    }

    private sealed class RecordingHandler(Func<HttpRequestMessage, HttpResponseMessage> responseFactory) : HttpMessageHandler
    {
        public List<HttpRequestMessage> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Requests.Add(request);
            return Task.FromResult(responseFactory(request));
        }
    }
}
