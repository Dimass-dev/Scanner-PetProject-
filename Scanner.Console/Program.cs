using Core.Modules;
using Core.Scanning;

namespace Scanner.ConsoleApp;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        if (args.Length > 1)
        {
            Console.Error.WriteLine("Usage: Scanner.Console [path-to-pe-file]");
            return 2;
        }

        // Keep `dotnet run` useful without arguments, matching the original demo behavior.
        string filePath = args.Length == 1
            ? args[0]
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "notepad.exe");

        Console.WriteLine("============================================================");
        Console.WriteLine($"[+] SCANNING FILE: {Path.GetFileName(filePath)}");
        if (args.Length == 0)
        {
            Console.WriteLine($"[*] No path supplied; using default: {filePath}");
        }

        Console.WriteLine("============================================================\n");

        // Create default PE scan module with all rules
        var peModule = PeScanModule.CreateDefault();
        var coordinator = new ScanCoordinator(new[] { peModule });
        ScanReport report = await coordinator.ScanAsync(ScanTarget.ForPeFile(filePath));

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

            if (module.Findings.Count > 0)
            {
                Console.WriteLine("\n[Security Findings]");
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
            else
            {
                Console.WriteLine("\n[Security Findings]");
                Console.WriteLine("  No security findings detected.");
            }
        }

        Console.WriteLine("\n============================================================");
        Console.WriteLine(report.Status == ScanStatus.Succeeded ? "[+] SCAN COMPLETE" : "[-] SCAN FAILED");
        Console.WriteLine("============================================================");
        return report.Status == ScanStatus.Succeeded ? 0 : 1;
    }
}
