using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Core.Scanning;
using Core.Web;

namespace Core.Modules;

/// <summary>Bounded, same-origin passive checks for an explicitly allowlisted HTTP(S) target.</summary>
public sealed partial class WebScanModule(WebScannerOptions options, HttpClient httpClient) : IScanModule
{
    private readonly WebTargetPolicy _targetPolicy = new(options);

    public string ModuleId => "web-passive-baseline";
    public bool Supports(ScanTargetKind targetKind) => targetKind == ScanTargetKind.WebApplication;

    public async Task<ScanModuleResult> ScanAsync(ScanTarget target, CancellationToken cancellationToken = default)
    {
        if (target.Kind != ScanTargetKind.WebApplication)
        {
            return ScanModuleResult.Failure(ModuleId, "This module only accepts web application targets.");
        }

        if (!Uri.TryCreate(target.Value, UriKind.Absolute, out Uri? startUri))
        {
            return ScanModuleResult.Failure(ModuleId, "The target URL is invalid.");
        }

        if (!_targetPolicy.TryValidate(startUri, out string validationError))
        {
            return ScanModuleResult.Failure(ModuleId, validationError);
        }

        using var scanCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        scanCts.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(options.MaxScanSeconds, 1, 300)));

        var findings = new List<ScanFinding>();
        var artifacts = new List<ScanArtifact>();
        var queued = new Queue<(Uri Uri, int Depth)>();
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        queued.Enqueue((startUri!, 0));
        int requestCount = 0;
        int pageCount = 0;
        int skippedCount = 0;
        int activeProbesRun = 0;
        DateTimeOffset startedAt = DateTimeOffset.UtcNow;
        int delayMilliseconds = 1000 / Math.Clamp(options.RequestsPerSecond, 1, 10);

        try
        {
            while (queued.Count > 0 && pageCount < Math.Clamp(options.MaxPages, 1, 50) && requestCount < Math.Clamp(options.MaxRequests, 1, 100))
            {
                scanCts.Token.ThrowIfCancellationRequested();
                var (pageUri, depth) = queued.Dequeue();
                if (!visited.Add(pageUri.AbsoluteUri))
                {
                    continue;
                }

                if (requestCount > 0 && delayMilliseconds > 0)
                {
                    await Task.Delay(delayMilliseconds, scanCts.Token).ConfigureAwait(false);
                }

                using var request = new HttpRequestMessage(HttpMethod.Get, pageUri);
                request.Headers.UserAgent.Add(new ProductInfoHeaderValue("LocalWebSecurityScanner", "1.0"));
                HttpResponseMessage response = await httpClient.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    scanCts.Token).ConfigureAwait(false);
                requestCount++;
                int redirects = 0;
                try
                {
                    while (IsRedirect(response.StatusCode) && response.Headers.Location is not null &&
                           redirects < Math.Clamp(options.MaxRedirects, 0, 5) && requestCount < Math.Clamp(options.MaxRequests, 1, 100))
                    {
                        Uri next = response.Headers.Location.IsAbsoluteUri
                            ? response.Headers.Location
                            : new Uri(pageUri, response.Headers.Location);

                        if (!_targetPolicy.TryValidate(next, out _) || !WebTargetPolicy.SameOrigin(startUri!, next))
                        {
                            findings.Add(Finding(
                                "WEB-SCOPE-001", "Redirect leaves the approved origin", ScanSeverity.Medium,
                                "The target redirected to a URL outside the configured origin. The scanner stopped following it.",
                                pageUri.AbsolutePath, "Medium"));
                            break;
                        }

                        if (delayMilliseconds > 0)
                        {
                            await Task.Delay(delayMilliseconds, scanCts.Token).ConfigureAwait(false);
                        }

                        response.Dispose();
                        pageUri = next;
                        visited.Add(pageUri.AbsoluteUri);
                        using var redirectRequest = new HttpRequestMessage(HttpMethod.Get, pageUri);
                        redirectRequest.Headers.UserAgent.Add(new ProductInfoHeaderValue("LocalWebSecurityScanner", "1.0"));
                        response = await httpClient.SendAsync(redirectRequest, HttpCompletionOption.ResponseHeadersRead, scanCts.Token).ConfigureAwait(false);
                        requestCount++;
                        redirects++;
                    }

                    pageCount++;
                    CheckResponseHeaders(pageUri, response, findings);

                    if ((int)response.StatusCode >= 500)
                    {
                        findings.Add(Finding("WEB-ERROR-001", "Server error response", ScanSeverity.Low,
                            $"The endpoint returned HTTP {(int)response.StatusCode}.", pageUri.AbsolutePath, "High"));
                    }

                    string? contentType = response.Content.Headers.ContentType?.MediaType;
                    byte[] body = await ReadBoundedBodyAsync(response.Content, options.MaxResponseBytes, scanCts.Token).ConfigureAwait(false);
                    if (body.Length >= Math.Clamp(options.MaxResponseBytes, 1024, 10 * 1024 * 1024) ||
                        response.Content.Headers.ContentLength > options.MaxResponseBytes)
                    {
                        skippedCount++;
                    }

                    if (depth < 2 && string.Equals(contentType, "text/html", StringComparison.OrdinalIgnoreCase))
                    {
                        string html = Encoding.UTF8.GetString(body);
                        foreach (Uri link in ExtractLinks(pageUri, html))
                        {
                            if (visited.Contains(link.AbsoluteUri) || queued.Count + pageCount >= Math.Clamp(options.MaxPages, 1, 50))
                            {
                                continue;
                            }

                            if (WebTargetPolicy.SameOrigin(startUri!, link) && _targetPolicy.TryValidate(link, out _))
                            {
                                queued.Enqueue((link, depth + 1));
                            }
                        }
                    }
                }
                finally
                {
                    response.Dispose();
                }
            }

            if (target.EnableLimitedActive)
            {
                int activeBudget = Math.Clamp(options.MaxActiveProbes, 0, 5);
                foreach (string visitedUrl in visited.Where(value => Uri.TryCreate(value, UriKind.Absolute, out Uri? uri) && !string.IsNullOrEmpty(uri.Query)).Take(activeBudget))
                {
                    if (activeProbesRun >= activeBudget || requestCount >= Math.Clamp(options.MaxRequests, 1, 100))
                    {
                        break;
                    }

                    if (!Uri.TryCreate(visitedUrl, UriKind.Absolute, out Uri? candidate) ||
                        !TryCreateQueryProbe(candidate, "'", out Uri? probeUri))
                    {
                        continue;
                    }

                    if (delayMilliseconds > 0)
                    {
                        await Task.Delay(delayMilliseconds, scanCts.Token).ConfigureAwait(false);
                    }

                    using var probeRequest = new HttpRequestMessage(HttpMethod.Get, probeUri);
                    probeRequest.Headers.UserAgent.Add(new ProductInfoHeaderValue("LocalWebSecurityScanner", "1.0"));
                    using HttpResponseMessage probeResponse = await httpClient.SendAsync(
                        probeRequest, HttpCompletionOption.ResponseHeadersRead, scanCts.Token).ConfigureAwait(false);
                    requestCount++;
                    activeProbesRun++;
                    byte[] probeBody = await ReadBoundedBodyAsync(probeResponse.Content, Math.Min(options.MaxResponseBytes, 65_536), scanCts.Token).ConfigureAwait(false);
                    string errorSignature = FindDatabaseErrorSignature(Encoding.UTF8.GetString(probeBody));
                    if (errorSignature.Length > 0)
                    {
                        findings.Add(Finding("WEB-INJ-001", "Possible SQL error disclosure after malformed query input", ScanSeverity.High,
                            "A bounded GET probe produced a response containing a database error signature. Confirm the issue in the application and inspect query construction.",
                            $"GET {candidate!.AbsolutePath}?<query value modified>; HTTP {(int)probeResponse.StatusCode}; signature category: {errorSignature}", "Medium"));
                    }

                    if (activeProbesRun < activeBudget && requestCount < Math.Clamp(options.MaxRequests, 1, 100))
                    {
                        string marker = $"<scanner-probe-{Guid.NewGuid():N}>";
                        if (TryCreateQueryProbe(candidate!, marker, out Uri? reflectionUri))
                        {
                            if (delayMilliseconds > 0)
                            {
                                await Task.Delay(delayMilliseconds, scanCts.Token).ConfigureAwait(false);
                            }

                            using var reflectionRequest = new HttpRequestMessage(HttpMethod.Get, reflectionUri);
                            reflectionRequest.Headers.UserAgent.Add(new ProductInfoHeaderValue("LocalWebSecurityScanner", "1.0"));
                            using HttpResponseMessage reflectionResponse = await httpClient.SendAsync(
                                reflectionRequest, HttpCompletionOption.ResponseHeadersRead, scanCts.Token).ConfigureAwait(false);
                            requestCount++;
                            activeProbesRun++;
                            if (reflectionResponse.Content.Headers.ContentType?.MediaType?.Equals("text/html", StringComparison.OrdinalIgnoreCase) == true)
                            {
                                byte[] reflectionBody = await ReadBoundedBodyAsync(
                                    reflectionResponse.Content, Math.Min(options.MaxResponseBytes, 65_536), scanCts.Token).ConfigureAwait(false);
                                if (Encoding.UTF8.GetString(reflectionBody).Contains(marker, StringComparison.Ordinal))
                                {
                                    findings.Add(Finding("WEB-XSS-001", "Unescaped HTML marker reflected from a query value", ScanSeverity.Low,
                                        "A harmless custom-element marker was returned as raw HTML. This suggests an output-encoding issue but does not prove script execution.",
                                        $"GET {candidate!.AbsolutePath}; HTML response reflected an inert marker.", "Low"));
                                }
                            }
                        }
                    }
                }

                if (!string.IsNullOrWhiteSpace(target.OpenApiDocument))
                {
                    foreach (OpenApiGetRoute route in GetOpenApiGetRoutes(target.OpenApiDocument, startUri!))
                    {
                        if (activeProbesRun >= activeBudget || requestCount >= Math.Clamp(options.MaxRequests, 1, 100))
                        {
                            break;
                        }

                        if (!WebTargetPolicy.SameOrigin(startUri!, route.Uri) || !_targetPolicy.TryValidate(route.Uri, out _))
                        {
                            continue;
                        }

                        if (delayMilliseconds > 0)
                        {
                            await Task.Delay(delayMilliseconds, scanCts.Token).ConfigureAwait(false);
                        }

                        using var apiRequest = new HttpRequestMessage(HttpMethod.Get, route.Uri);
                        apiRequest.Headers.UserAgent.Add(new ProductInfoHeaderValue("LocalWebSecurityScanner", "1.0"));
                        using HttpResponseMessage apiResponse = await httpClient.SendAsync(
                            apiRequest, HttpCompletionOption.ResponseHeadersRead, scanCts.Token).ConfigureAwait(false);
                        requestCount++;
                        activeProbesRun++;

                        if (route.SecurityDeclared && (int)apiResponse.StatusCode is >= 200 and < 300)
                        {
                            findings.Add(Finding("WEB-API-006", "Documented protected GET returned success without credentials", ScanSeverity.Medium,
                                "The OpenAPI operation declares a security requirement, but the unauthenticated request returned a success status. Confirm authorization behavior with a controlled test account.",
                                $"GET {route.Uri.AbsolutePath}; HTTP {(int)apiResponse.StatusCode}", "Low"));
                        }
                        else if ((int)apiResponse.StatusCode >= 500)
                        {
                            findings.Add(Finding("WEB-API-007", "Documented GET returned a server error", ScanSeverity.Low,
                                "A bounded unauthenticated GET to a documented operation returned a 5xx status.",
                                $"GET {route.Uri.AbsolutePath}; HTTP {(int)apiResponse.StatusCode}", "High"));
                        }

                        if (!route.ExpectedStatusCodes.Contains(((int)apiResponse.StatusCode).ToString()) &&
                            !route.ExpectedStatusCodes.Contains($"{(int)apiResponse.StatusCode / 100}XX") &&
                            !route.ExpectedStatusCodes.Contains("default"))
                        {
                            findings.Add(Finding("WEB-API-008", "GET response status is not declared in OpenAPI", ScanSeverity.Low,
                                "The runtime status code does not match an exact, range, or default response declared for this operation.",
                                $"GET {route.Uri.AbsolutePath}; HTTP {(int)apiResponse.StatusCode}", "High"));
                        }

                        if (TryGetExpectedJsonSchema(route, (int)apiResponse.StatusCode, out JsonElement schema) &&
                            apiResponse.Content.Headers.ContentType?.MediaType?.Contains("json", StringComparison.OrdinalIgnoreCase) == true &&
                            (apiResponse.Content.Headers.ContentLength is null or <= 65_536))
                        {
                            byte[] jsonBody = await ReadBoundedBodyAsync(apiResponse.Content, Math.Min(options.MaxResponseBytes, 65_536), scanCts.Token).ConfigureAwait(false);
                            if (jsonBody.Length < Math.Min(options.MaxResponseBytes, 65_536))
                            {
                                try
                                {
                                    using JsonDocument actualJson = JsonDocument.Parse(jsonBody, new JsonDocumentOptions { MaxDepth = 32 });
                                    using JsonDocument openApiSpec = JsonDocument.Parse(target.OpenApiDocument!, new JsonDocumentOptions { MaxDepth = 64 });
                                    var schemaIssues = new List<string>();
                                    ValidateJsonAgainstSchema(actualJson.RootElement, schema, openApiSpec.RootElement, "response", 0, schemaIssues);
                                    if (schemaIssues.Count > 0)
                                    {
                                        findings.Add(Finding("WEB-API-009", "GET response does not match its OpenAPI JSON schema", ScanSeverity.Medium,
                                            "The response differed from a supported part of its documented schema. Confirm the contract and consider unimplemented schema keywords.",
                                            $"GET {route.Uri.AbsolutePath}; mismatch at {schemaIssues[0]}", "Medium"));
                                    }
                                }
                                catch (JsonException)
                                {
                                    findings.Add(Finding("WEB-API-009", "GET response is not valid JSON as documented", ScanSeverity.Medium,
                                        "The operation documented a JSON response schema, but the response body could not be parsed as JSON.",
                                        $"GET {route.Uri.AbsolutePath}; HTTP {(int)apiResponse.StatusCode}", "High"));
                                }
                            }
                        }
                    }
                }
            }

            if (queued.Count > 0)
            {
                skippedCount += queued.Count;
            }

            if (startUri!.Scheme == Uri.UriSchemeHttp)
            {
                findings.Add(Finding("WEB-TLS-001", "Target uses HTTP", ScanSeverity.Medium,
                    "The scan target uses unencrypted HTTP. Credentials and session data sent to this origin would not be protected in transit.",
                    startUri.GetLeftPart(UriPartial.Authority), "High"));
            }

            if (!string.IsNullOrWhiteSpace(target.OpenApiDocument))
            {
                AnalyzeOpenApi(target.OpenApiDocument, startUri, findings, artifacts);
            }

            artifacts.Add(new ScanArtifact("web.coverage", "Passive baseline coverage", new Dictionary<string, string>
            {
                ["Profile"] = target.EnableLimitedActive ? "PassiveBaseline+LimitedActive" : "PassiveBaseline",
                ["PagesVisited"] = pageCount.ToString(),
                ["RequestsSent"] = requestCount.ToString(),
                ["LimitedActiveProbesRun"] = activeProbesRun.ToString(),
                ["PagesSkippedOrTruncated"] = skippedCount.ToString(),
                ["DurationSeconds"] = Math.Max(0, (DateTimeOffset.UtcNow - startedAt).TotalSeconds).ToString("F1"),
                ["Scope"] = startUri.GetLeftPart(UriPartial.Authority),
                ["Limitations"] = target.EnableLimitedActive
                    ? "Limited-active mode only appends a single quote to discovered GET query values and looks for database error disclosures. It does not extract data or submit forms. GET endpoints can still have side effects; use staging."
                    : "No authentication, form submission, state-changing methods, source-code review, or active payloads were used."
            }));

            return ScanModuleResult.Success(ModuleId, findings, artifacts);
        }
        catch (OperationCanceledException) when (scanCts.IsCancellationRequested)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                throw;
            }

            return ScanModuleResult.Failure(ModuleId, $"Web scan stopped after its {options.MaxScanSeconds}-second time limit.");
        }
        catch (HttpRequestException)
        {
            string message = startUri!.Scheme == Uri.UriSchemeHttps
                ? "HTTPS connection failed. Check that the target certificate is trusted and the service is reachable."
                : "The target could not be reached using the approved network scope.";
            findings.Add(Finding("WEB-CONN-001", "Target connection failed", ScanSeverity.Medium, message, startUri.GetLeftPart(UriPartial.Authority), "High"));
            artifacts.Add(new ScanArtifact("web.coverage", "Passive baseline coverage", new Dictionary<string, string>
            {
                ["Profile"] = "PassiveBaseline",
                ["PagesVisited"] = pageCount.ToString(),
                ["RequestsSent"] = requestCount.ToString(),
                ["Limitations"] = "Scan ended before full coverage."
            }));
            return ScanModuleResult.Success(ModuleId, findings, artifacts);
        }
    }

    private static void CheckResponseHeaders(Uri uri, HttpResponseMessage response, List<ScanFinding> findings)
    {
        bool isHtml = response.Content.Headers.ContentType?.MediaType?.Equals("text/html", StringComparison.OrdinalIgnoreCase) == true;
        if (uri.Scheme == Uri.UriSchemeHttps && !response.Headers.Contains("Strict-Transport-Security"))
        {
            findings.Add(Finding("WEB-HEAD-001", "HSTS header is missing", ScanSeverity.Low,
                "HTTPS response does not include Strict-Transport-Security.", uri.AbsolutePath, "High"));
        }

        if (isHtml && !response.Headers.Contains("Content-Security-Policy"))
        {
            findings.Add(Finding("WEB-HEAD-002", "Content Security Policy is missing", ScanSeverity.Low,
                "HTML response does not include Content-Security-Policy. Review whether a policy can reduce script injection impact.", uri.AbsolutePath, "High"));
        }

        if (isHtml && !response.Headers.Contains("X-Content-Type-Options"))
        {
            findings.Add(Finding("WEB-HEAD-003", "MIME sniffing protection is missing", ScanSeverity.Low,
                "HTML response does not include X-Content-Type-Options: nosniff.", uri.AbsolutePath, "High"));
        }

        if (isHtml && !response.Headers.Contains("Referrer-Policy"))
        {
            findings.Add(Finding("WEB-HEAD-004", "Referrer-Policy is missing", ScanSeverity.Informational,
                "HTML response does not include an explicit Referrer-Policy.", uri.AbsolutePath, "High"));
        }

        if (isHtml && !response.Headers.Contains("X-Frame-Options") &&
            !(response.Headers.TryGetValues("Content-Security-Policy", out IEnumerable<string>? policies) &&
              policies.Any(policy => policy.Contains("frame-ancestors", StringComparison.OrdinalIgnoreCase))))
        {
            findings.Add(Finding("WEB-HEAD-005", "Framing restriction is missing", ScanSeverity.Low,
                "No X-Frame-Options or CSP frame-ancestors directive was found on the HTML response.", uri.AbsolutePath, "Medium"));
        }

        if (response.Headers.Server.Count > 0 || response.Headers.Contains("X-Powered-By"))
        {
            var disclosureHeaders = new List<string>();
            if (response.Headers.Server.Count > 0)
            {
                disclosureHeaders.Add("Server");
            }

            if (response.Headers.Contains("X-Powered-By"))
            {
                disclosureHeaders.Add("X-Powered-By");
            }

            findings.Add(Finding("WEB-INFO-001", "Technology disclosure headers are present", ScanSeverity.Informational,
                $"Response includes: {string.Join(", ", disclosureHeaders)}. Header values are omitted from the report.", uri.AbsolutePath, "High"));
        }

        if (response.Headers.TryGetValues("Set-Cookie", out IEnumerable<string>? cookies))
        {
            int index = 0;
            foreach (string cookie in cookies)
            {
                index++;
                string[] attributes = cookie.Split(';').Select(attribute => attribute.Trim()).ToArray();
                bool secure = attributes.Any(attribute => attribute.Equals("Secure", StringComparison.OrdinalIgnoreCase));
                bool httpOnly = attributes.Any(attribute => attribute.Equals("HttpOnly", StringComparison.OrdinalIgnoreCase));
                bool sameSite = attributes.Any(attribute => attribute.StartsWith("SameSite=", StringComparison.OrdinalIgnoreCase));
                string cookieEvidence = $"Cookie #{index}; value redacted.";

                if (uri.Scheme == Uri.UriSchemeHttps && !secure)
                {
                    findings.Add(Finding("WEB-COOKIE-001", "Cookie lacks Secure attribute", ScanSeverity.Medium,
                        "A cookie was set over HTTPS without the Secure attribute.", cookieEvidence, "High"));
                }

                if (!httpOnly)
                {
                    findings.Add(Finding("WEB-COOKIE-002", "Cookie lacks HttpOnly attribute", ScanSeverity.Low,
                        "A cookie was set without the HttpOnly attribute.", cookieEvidence, "High"));
                }

                if (!sameSite)
                {
                    findings.Add(Finding("WEB-COOKIE-003", "Cookie lacks SameSite attribute", ScanSeverity.Low,
                        "A cookie was set without an explicit SameSite attribute.", cookieEvidence, "Medium"));
                }
            }
        }
    }

    private static async Task<byte[]> ReadBoundedBodyAsync(HttpContent content, int maxBytes, CancellationToken cancellationToken)
    {
        int limit = Math.Clamp(maxBytes, 1024, 10 * 1024 * 1024);
        if (content.Headers.ContentLength is long contentLength && contentLength > limit)
        {
            return [];
        }

        await using Stream input = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var output = new MemoryStream(Math.Min(limit, 64 * 1024));
        byte[] buffer = new byte[8192];
        while (output.Length < limit)
        {
            int read = await input.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, limit - output.Length)), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            output.Write(buffer, 0, read);
        }
        return output.ToArray();
    }

    private static IEnumerable<Uri> ExtractLinks(Uri pageUri, string html)
    {
        foreach (Match match in HrefRegex().Matches(html))
        {
            string value = WebUtility.HtmlDecode(match.Groups[1].Value.Trim());
            if (value.Length == 0 || value.StartsWith('#') || value.StartsWith("javascript:", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (Uri.TryCreate(pageUri, value, out Uri? candidate) &&
                (candidate.Scheme == Uri.UriSchemeHttp || candidate.Scheme == Uri.UriSchemeHttps))
            {
                yield return candidate;
            }
        }
    }

    private static bool IsRedirect(HttpStatusCode statusCode) =>
        statusCode is HttpStatusCode.MovedPermanently or HttpStatusCode.Redirect or HttpStatusCode.SeeOther or
            HttpStatusCode.TemporaryRedirect or HttpStatusCode.PermanentRedirect;

    private static ScanFinding Finding(string id, string title, ScanSeverity severity, string description, string evidence, string confidence) =>
        new(id, title, "Web", severity, description, evidence, "Review the recommendation and confirm the finding in your application context.", "OWASP ASVS v5.0.0", confidence);

    private void AnalyzeOpenApi(string document, Uri target, List<ScanFinding> findings, List<ScanArtifact> artifacts)
    {
        try
        {
            using JsonDocument spec = JsonDocument.Parse(document, new JsonDocumentOptions { MaxDepth = 64 });
            JsonElement root = spec.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("openapi", out JsonElement versionElement) ||
                versionElement.ValueKind != JsonValueKind.String || versionElement.GetString() is not string version ||
                !version.StartsWith("3.", StringComparison.Ordinal))
            {
                findings.Add(Finding("WEB-API-001", "OpenAPI document is not a supported OpenAPI 3.x document", ScanSeverity.Low,
                    "The supplied document did not declare an OpenAPI 3.x version and could not be reviewed.", "OpenAPI document", "High"));
                return;
            }

            bool hasGlobalSecurity = root.TryGetProperty("security", out JsonElement globalSecurity) &&
                globalSecurity.ValueKind == JsonValueKind.Array && globalSecurity.GetArrayLength() > 0;
            int operationCount = 0;
            int operationsWithoutDeclaredSecurity = 0;
            int stateChangingOperations = 0;
            var methods = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var externalReferences = new List<string>();
            CollectExternalReferences(root, externalReferences);

            if (root.TryGetProperty("servers", out JsonElement servers) && servers.ValueKind == JsonValueKind.Array)
            {
                foreach (JsonElement server in servers.EnumerateArray())
                {
                    if (!server.TryGetProperty("url", out JsonElement serverUrlElement) || serverUrlElement.ValueKind != JsonValueKind.String)
                    {
                        continue;
                    }

                    string? serverUrl = serverUrlElement.GetString();
                    if (serverUrl is null || serverUrl.Contains('{'))
                    {
                        continue;
                    }

                    if (Uri.TryCreate(target, serverUrl, out Uri? serverUri) && serverUri.IsAbsoluteUri &&
                        serverUri.Scheme is "http" or "https" && !WebTargetPolicy.SameOrigin(target, serverUri))
                    {
                        findings.Add(Finding("WEB-API-002", "OpenAPI server URL is outside the scan origin", ScanSeverity.Medium,
                            "The specification advertises a different server origin. It was recorded but not contacted.",
                            serverUri.GetLeftPart(UriPartial.Authority), "High"));
                    }
                }
            }

            if (root.TryGetProperty("paths", out JsonElement paths) && paths.ValueKind == JsonValueKind.Object)
            {
                foreach (JsonProperty path in paths.EnumerateObject())
                {
                    if (path.Value.ValueKind != JsonValueKind.Object)
                    {
                        continue;
                    }

                    foreach (JsonProperty operation in path.Value.EnumerateObject())
                    {
                        if (!IsHttpOperation(operation.Name) || operation.Value.ValueKind != JsonValueKind.Object)
                        {
                            continue;
                        }

                        operationCount++;
                        methods[operation.Name] = methods.GetValueOrDefault(operation.Name) + 1;
                        if (operation.Name is "post" or "put" or "patch" or "delete")
                        {
                            stateChangingOperations++;
                        }

                        bool operationHasSecurity = operation.Value.TryGetProperty("security", out JsonElement operationSecurity)
                            ? operationSecurity.ValueKind == JsonValueKind.Array && operationSecurity.GetArrayLength() > 0
                            : hasGlobalSecurity;
                        if (!operationHasSecurity)
                        {
                            operationsWithoutDeclaredSecurity++;
                            findings.Add(Finding("WEB-API-003", "OpenAPI operation has no declared security requirement", ScanSeverity.Informational,
                                "The operation is marked public by the document or inherits no security requirement. Confirm that public access is intentional.",
                                $"{operation.Name.ToUpperInvariant()} {path.Name}", "Medium"));
                        }
                    }
                }
            }

            if (stateChangingOperations > 0)
            {
                findings.Add(Finding("WEB-API-004", "OpenAPI defines state-changing operations", ScanSeverity.Informational,
                    $"The specification documents {stateChangingOperations} POST/PUT/PATCH/DELETE operation(s). This passive review did not call them.",
                    "OpenAPI operation inventory", "High"));
            }

            if (externalReferences.Count > 0)
            {
                findings.Add(Finding("WEB-API-005", "External OpenAPI references were not loaded", ScanSeverity.Low,
                    $"The document contains {externalReferences.Count} external $ref value(s). They were not requested.",
                    string.Join(", ", externalReferences.Take(5)), "High"));
            }

            var inventory = new Dictionary<string, string>
            {
                ["OpenApiVersion"] = version,
                ["OperationCount"] = operationCount.ToString(),
                ["OperationsWithoutDeclaredSecurity"] = operationsWithoutDeclaredSecurity.ToString(),
                ["StateChangingOperationsNotCalled"] = stateChangingOperations.ToString(),
                ["ExternalReferencesNotLoaded"] = externalReferences.Count.ToString(),
                ["Methods"] = string.Join(", ", methods.OrderBy(pair => pair.Key).Select(pair => $"{pair.Key.ToUpperInvariant()}={pair.Value}")),
                ["LiveOperationsProbed"] = "0",
                ["Limitations"] = "This review inspects the supplied specification only; it does not validate endpoint authorization or response schemas at runtime."
            };
            artifacts.Add(new ScanArtifact("web.openapi", "OpenAPI specification review", inventory));
        }
        catch (JsonException)
        {
            findings.Add(Finding("WEB-API-001", "OpenAPI document is invalid JSON", ScanSeverity.Low,
                "The supplied OpenAPI document could not be parsed as JSON.", "OpenAPI document", "High"));
        }
    }

    private static void CollectExternalReferences(JsonElement element, List<string> references)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (JsonProperty property in element.EnumerateObject())
            {
                if (property.NameEquals("$ref") && property.Value.ValueKind == JsonValueKind.String)
                {
                    string reference = property.Value.GetString() ?? string.Empty;
                    if (!reference.StartsWith("#", StringComparison.Ordinal))
                    {
                        references.Add(reference);
                    }
                }
                else
                {
                    CollectExternalReferences(property.Value, references);
                }
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement child in element.EnumerateArray())
            {
                CollectExternalReferences(child, references);
            }
        }
    }

    private static bool IsHttpOperation(string name) => name is
        "get" or "put" or "post" or "delete" or "options" or "head" or "patch" or "trace";

    private static IReadOnlyList<OpenApiGetRoute> GetOpenApiGetRoutes(string document, Uri target)
    {
        var routes = new List<OpenApiGetRoute>();
        try
        {
            using JsonDocument spec = JsonDocument.Parse(document, new JsonDocumentOptions { MaxDepth = 64 });
            JsonElement root = spec.RootElement;
            bool globalSecurity = root.TryGetProperty("security", out JsonElement global) &&
                global.ValueKind == JsonValueKind.Array && global.GetArrayLength() > 0;
            string basePath = "/";

            if (root.TryGetProperty("servers", out JsonElement servers) && servers.ValueKind == JsonValueKind.Array && servers.GetArrayLength() > 0)
            {
                JsonElement firstServer = servers[0];
                if (firstServer.TryGetProperty("url", out JsonElement serverUrlElement) && serverUrlElement.ValueKind == JsonValueKind.String)
                {
                    string? serverValue = serverUrlElement.GetString();
                    if (serverValue is not null && !serverValue.Contains('{'))
                    {
                        if (Uri.TryCreate(target, serverValue, out Uri? serverUri))
                        {
                            if (serverUri.IsAbsoluteUri && !WebTargetPolicy.SameOrigin(target, serverUri))
                            {
                                return routes;
                            }

                            basePath = serverUri.AbsolutePath;
                        }
                    }
                }
            }

            if (!root.TryGetProperty("paths", out JsonElement paths) || paths.ValueKind != JsonValueKind.Object)
            {
                return routes;
            }

            foreach (JsonProperty path in paths.EnumerateObject())
            {
                if (path.Name.Contains('{') || path.Name.Contains('}') || !path.Name.StartsWith('/'))
                {
                    continue;
                }

                if (!path.Value.TryGetProperty("get", out JsonElement operation) || operation.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                bool securityDeclared = operation.TryGetProperty("security", out JsonElement operationSecurity)
                    ? operationSecurity.ValueKind == JsonValueKind.Array && operationSecurity.GetArrayLength() > 0
                    : globalSecurity;
                var expectedStatusCodes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var jsonSchemas = new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase);
                if (operation.TryGetProperty("responses", out JsonElement responses) && responses.ValueKind == JsonValueKind.Object)
                {
                    foreach (JsonProperty response in responses.EnumerateObject())
                    {
                        expectedStatusCodes.Add(response.Name);
                        if (response.Value.TryGetProperty("content", out JsonElement content) && content.ValueKind == JsonValueKind.Object)
                        {
                            foreach (JsonProperty mediaType in content.EnumerateObject())
                            {
                                if ((mediaType.Name.Equals("application/json", StringComparison.OrdinalIgnoreCase) ||
                                     mediaType.Name.EndsWith("+json", StringComparison.OrdinalIgnoreCase)) &&
                                    mediaType.Value.TryGetProperty("schema", out JsonElement responseSchema))
                                {
                                    jsonSchemas[response.Name] = responseSchema.Clone();
                                    break;
                                }
                            }
                        }
                    }
                }
                string prefix = basePath.TrimEnd('/');
                string relativePath = $"{prefix}{path.Name}";
                if (relativePath.Length == 0)
                {
                    relativePath = "/";
                }

                if (Uri.TryCreate(target.GetLeftPart(UriPartial.Authority) + relativePath, UriKind.Absolute, out Uri? routeUri))
                {
                    routes.Add(new OpenApiGetRoute(routeUri, securityDeclared, expectedStatusCodes, jsonSchemas));
                }
            }
        }
        catch (JsonException)
        {
            // The specification parse error is already reported by the passive OpenAPI review.
        }

        return routes;
    }

    private static bool TryGetExpectedJsonSchema(OpenApiGetRoute route, int statusCode, out JsonElement schema)
    {
        string status = statusCode.ToString();
        return route.JsonSchemas.TryGetValue(status, out schema) ||
            route.JsonSchemas.TryGetValue($"{statusCode / 100}XX", out schema) ||
            route.JsonSchemas.TryGetValue("default", out schema);
    }

    private static void ValidateJsonAgainstSchema(
        JsonElement actual,
        JsonElement schema,
        JsonElement openApiRoot,
        string path,
        int depth,
        List<string> issues)
    {
        if (issues.Count >= 5 || depth > 16 || schema.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        if (schema.TryGetProperty("$ref", out JsonElement referenceElement) && referenceElement.ValueKind == JsonValueKind.String)
        {
            string reference = referenceElement.GetString() ?? string.Empty;
            if (!reference.StartsWith("#/", StringComparison.Ordinal) || !TryResolveJsonPointer(openApiRoot, reference, out JsonElement resolved))
            {
                return;
            }

            schema = resolved;
        }

        if (schema.TryGetProperty("nullable", out JsonElement nullable) && nullable.ValueKind == JsonValueKind.True && actual.ValueKind == JsonValueKind.Null)
        {
            return;
        }

        if (schema.TryGetProperty("type", out JsonElement typeElement) && typeElement.ValueKind == JsonValueKind.String)
        {
            string? expectedType = typeElement.GetString();
            bool typeMatches = expectedType switch
            {
                "object" => actual.ValueKind == JsonValueKind.Object,
                "array" => actual.ValueKind == JsonValueKind.Array,
                "string" => actual.ValueKind == JsonValueKind.String,
                "integer" => actual.ValueKind == JsonValueKind.Number && actual.TryGetInt64(out _),
                "number" => actual.ValueKind == JsonValueKind.Number,
                "boolean" => actual.ValueKind is JsonValueKind.True or JsonValueKind.False,
                "null" => actual.ValueKind == JsonValueKind.Null,
                _ => true
            };
            if (!typeMatches)
            {
                issues.Add(path);
                return;
            }
        }

        if (schema.TryGetProperty("enum", out JsonElement enumValues) && enumValues.ValueKind == JsonValueKind.Array &&
            !enumValues.EnumerateArray().Any(value => JsonElement.DeepEquals(value, actual)))
        {
            issues.Add(path);
        }

        if (actual.ValueKind == JsonValueKind.Object)
        {
            if (schema.TryGetProperty("required", out JsonElement required) && required.ValueKind == JsonValueKind.Array)
            {
                foreach (JsonElement requiredName in required.EnumerateArray())
                {
                    if (requiredName.ValueKind == JsonValueKind.String && !actual.TryGetProperty(requiredName.GetString()!, out _))
                    {
                        issues.Add($"{path}.{requiredName.GetString()}");
                    }
                }
            }

            if (schema.TryGetProperty("properties", out JsonElement properties) && properties.ValueKind == JsonValueKind.Object)
            {
                foreach (JsonProperty property in properties.EnumerateObject())
                {
                    if (actual.TryGetProperty(property.Name, out JsonElement propertyValue))
                    {
                        ValidateJsonAgainstSchema(propertyValue, property.Value, openApiRoot, $"{path}.{property.Name}", depth + 1, issues);
                    }
                }
            }
        }
        else if (actual.ValueKind == JsonValueKind.Array && schema.TryGetProperty("items", out JsonElement items))
        {
            int index = 0;
            foreach (JsonElement value in actual.EnumerateArray())
            {
                ValidateJsonAgainstSchema(value, items, openApiRoot, $"{path}[{index}]", depth + 1, issues);
                if (++index >= 10 || issues.Count >= 5)
                {
                    break;
                }
            }
        }
    }

    private static bool TryResolveJsonPointer(JsonElement root, string reference, out JsonElement value)
    {
        value = root;
        string[] parts = reference[2..].Split('/');
        foreach (string rawPart in parts)
        {
            string part = rawPart.Replace("~1", "/", StringComparison.Ordinal).Replace("~0", "~", StringComparison.Ordinal);
            if (value.ValueKind == JsonValueKind.Object && value.TryGetProperty(part, out JsonElement property))
            {
                value = property;
                continue;
            }
            if (value.ValueKind == JsonValueKind.Array && int.TryParse(part, out int index) && index >= 0 && index < value.GetArrayLength())
            {
                value = value[index];
                continue;
            }
            return false;
        }
        return true;
    }

    private sealed record OpenApiGetRoute(
        Uri Uri,
        bool SecurityDeclared,
        IReadOnlySet<string> ExpectedStatusCodes,
        IReadOnlyDictionary<string, JsonElement> JsonSchemas);

    private static bool TryCreateQueryProbe(Uri source, string suffix, out Uri? result)
    {
        var parameters = source.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(part => part.Split('=', 2))
            .Select(pair => new KeyValuePair<string, string>(Uri.UnescapeDataString(pair[0]), pair.Length > 1 ? Uri.UnescapeDataString(pair[1]) : string.Empty))
            .ToList();

        int targetIndex = parameters.FindIndex(parameter => parameter.Key.Length > 0);
        if (targetIndex < 0)
        {
            result = null;
            return false;
        }

        KeyValuePair<string, string> parameter = parameters[targetIndex];
        parameters[targetIndex] = new KeyValuePair<string, string>(parameter.Key, parameter.Value + suffix);
        string query = string.Join("&", parameters.Select(item => $"{Uri.EscapeDataString(item.Key)}={Uri.EscapeDataString(item.Value)}"));
        var builder = new UriBuilder(source) { Query = query };
        result = builder.Uri;
        return true;
    }

    private static string FindDatabaseErrorSignature(string body)
    {
        string[] signatures =
        [
            "SQL syntax", "SQLSTATE", "ODBC SQL", "Unclosed quotation mark", "SQLiteException", "SQLite error", "SQLITE_ERROR",
            "ORA-"
        ];
        string? signature = signatures.FirstOrDefault(value => body.Contains(value, StringComparison.OrdinalIgnoreCase));
        if (signature is not null)
        {
            return signature;
        }

        return body.Contains("PostgreSQL", StringComparison.OrdinalIgnoreCase) &&
            body.Contains("ERROR", StringComparison.OrdinalIgnoreCase) ? "PostgreSQL error" : string.Empty;
    }

    [GeneratedRegex("<a\\b[^>]*?\\bhref\\s*=\\s*['\\\"]([^'\\\"]+)['\\\"]", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex HrefRegex();
}
