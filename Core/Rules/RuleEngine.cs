using Core.Scanning;

namespace Core.Rules;

/// <summary>
/// Evaluates all rules against a PE image.
/// </summary>
public sealed class RuleEngine
{
    private readonly IReadOnlyList<IRule> _rules;

    public RuleEngine(IReadOnlyList<IRule> rules)
    {
        _rules = rules;
    }

    /// <summary>Evaluate all rules and return findings.</summary>
    public IReadOnlyList<ScanFinding> Evaluate(RuleContext context)
    {
        var findings = new List<ScanFinding>();

        foreach (var rule in _rules)
        {
            try
            {
                var ruleFindings = rule.Evaluate(context);
                findings.AddRange(ruleFindings);
            }
            catch (Exception ex)
            {
                // Log error but don't fail entire scan
                findings.Add(new ScanFinding(
                    RuleId: $"{rule.Id}-ERROR",
                    Title: $"Rule evaluation error: {rule.Id}",
                    Category: "System",
                    Severity: ScanSeverity.Informational,
                    Description: $"Failed to evaluate rule: {ex.Message}",
                    Evidence: ex.Message,
                    Recommendation: "This is an internal error and does not indicate a problem with the file.",
                    StandardReference: null));
            }
        }

        return findings;
    }
}
