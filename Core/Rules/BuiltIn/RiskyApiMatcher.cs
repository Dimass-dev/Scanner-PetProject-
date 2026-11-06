using System.Text.RegularExpressions;
using Core.Analysis;

namespace Core.Rules.BuiltIn;

/// <summary>Shared matching of imported function names against risky-API catalogs.</summary>
internal static partial class RiskyApiMatcher
{
    [GeneratedRegex("[AW]$", RegexOptions.IgnoreCase)]
    private static partial Regex ApiSuffix();

    /// <summary>Strips the trailing A/W suffix used by Win32 name variants.</summary>
    public static string Normalize(string function) => ApiSuffix().Replace(function, string.Empty);

    public static bool MatchesAnyApi(string function, IReadOnlyList<string> apis)
    {
        string normalized = Normalize(function);
        return apis.Any(api => string.Equals(api, normalized, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Collects imported functions (including delay imports) matching the catalog list.</summary>
    public static List<string> CollectMatchingApis(PeImage image, IReadOnlyList<string> apis)
    {
        var detected = new List<string>();

        if (image.Imports.IsSuccess)
        {
            foreach (var dll in image.Imports.Libraries)
            {
                foreach (var function in dll.Functions)
                {
                    string funcName = function.DisplayName;
                    if (MatchesAnyApi(funcName, apis))
                    {
                        detected.Add(funcName);
                    }
                }
            }
        }

        foreach (var dll in image.DelayImports)
        {
            foreach (var function in dll.Functions)
            {
                string funcName = function.DisplayName;
                if (MatchesAnyApi(funcName, apis))
                {
                    detected.Add(funcName);
                }
            }
        }

        return detected;
    }
}
