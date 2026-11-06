using System.Text.Json;
using System.Text.Json.Serialization;
using Core.Modules;
using Core.Risk;
using Core.Scanning;

namespace Scanner.ConsoleApp;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        string? filePath = null;
        bool json = false;

        foreach (string arg in args)
        {
            if (arg is "--json")
            {
                json = true;
            }
            else if (arg is "-h" or "--help")
            {
                PrintUsage();
                return 2;
            }
            else if (filePath is null)
            {
                filePath = arg;
            }
            else
            {
                PrintUsage();
                return 2;
            }
        }

        if (filePath is null)
        {
            PrintUsage();
            return 2;
        }

        if (!File.Exists(filePath))
        {
            Console.Error.WriteLine($"[-] File not found: {filePath}");
            return 2;
        }

        if (!json)
        {
            Console.WriteLine("============================================================");
            Console.WriteLine($"[+] SCANNING FILE: {Path.GetFileName(filePath)}");
            Console.WriteLine("============================================================\n");
        }

        // Create default PE scan module with all rules.
        var peModule = PeScanModule.CreateDefault();
        var coordinator = new ScanCoordinator(new[] { peModule });

        using var cancellation = new CancellationTokenSource();
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cancellation.Cancel();
        };

        ScanReport report;
        try
        {
            report = await coordinator.ScanAsync(ScanTarget.ForPeFile(filePath), cancellation.Token);
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("[-] Scan cancelled.");
            return 1;
        }

        if (json)
        {
            WriteJsonReport(report);
        }
        else
        {
            WriteTextReport(report);
        }

        return report.Status == ScanStatus.Succeeded ? 0 : 1;
    }

    private static void PrintUsage()
    {
        Console.Error.WriteLine("Usage: Scanner.Console <path-to-pe-file> [--json]");
        Console.Error.WriteLine("  --json  Write the scan report as JSON instead of formatted text.");
        Console.Error.WriteLine("  -h      Show this help. Press Ctrl+C to cancel a running scan.");
    }

    private static void WriteJsonReport(ScanReport report)
    {
        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter() }
        };
        Console.WriteLine(JsonSerializer.Serialize(report, options));
    }

    private static void WriteTextReport(ScanReport report)
    {
        foreach (ScanModuleResult module in report.Modules)
        {
            if (module.Status != ScanStatus.Succeeded)
            {
                Console.Error.WriteLine($"[-] {module.ErrorMessage}");
                continue;
            }

            Console.WriteLine("[Artifacts & Metadata]");
            foreach (ScanArtifact artifact in module.Artifacts)
            {
                Console.WriteLine($"[{artifact.Kind}] {artifact.Name}");
                foreach ((string key, string value) in artifact.Properties)
                {
                    Console.WriteLine($"  {key}: {value}");
                }
            }

            Console.WriteLine("\n[Security Findings]");
            if (module.Findings.Count == 0)
            {
                Console.WriteLine("  No security findings detected.");
                continue;
            }

            foreach (ScanFinding finding in module.Findings)
            {
                Console.WriteLine($"  * [{finding.Severity}] {finding.RuleId}: {finding.Title}");
                Console.WriteLine($"    Description: {finding.Description}");
                if (!string.IsNullOrEmpty(finding.Evidence))
                {
                    Console.WriteLine($"    Evidence: {finding.Evidence}");
                }

                if (!string.IsNullOrEmpty(finding.Recommendation))
                {
                    Console.WriteLine($"    Recommendation: {finding.Recommendation}");
                }
            }
        }

        RiskScore risk = new RiskAssessmentEngine().Assess(report.Findings);
        Console.WriteLine("\n[Risk Assessment]");
        Console.WriteLine($"  Level: {risk.Level}");
        Console.WriteLine($"  Score: {risk.Score}");
        foreach ((ScanSeverity severity, int count) in risk.Counts.Where(pair => pair.Value > 0))
        {
            Console.WriteLine($"  {severity}: {count}");
        }

        Console.WriteLine("\n============================================================");
        Console.WriteLine(report.Status == ScanStatus.Succeeded ? "[+] SCAN COMPLETE" : "[-] SCAN FAILED");
        Console.WriteLine("============================================================");
    }
}
