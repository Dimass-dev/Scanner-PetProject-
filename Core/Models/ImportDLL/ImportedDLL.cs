namespace Core.Models.ImportDLL;

public sealed class ImportedDLL
{
    public string DLLName { get; set; } = string.Empty;
    public uint OriginalFirstThunk { get; set; }
    public uint FirstThunk { get; set; }
    public uint NameRVA { get; set; }
    public List<ImportedFunction> Functions { get; init; } = [];

    // Constructor for new API
    public ImportedDLL() { }

    public ImportedDLL(string dllName, IReadOnlyList<string> functions)
    {
        DLLName = dllName;
        foreach (var funcName in functions)
        {
            if (funcName.StartsWith('#'))
            {
                if (ushort.TryParse(funcName[1..], out var ordinal))
                    Functions.Add(new ImportedFunction(null, ordinal, null));
            }
            else
            {
                Functions.Add(new ImportedFunction(funcName, null, null));
            }
        }
    }

    public IReadOnlyList<string> ImportedFunctions =>
        Functions.Select(f => f.DisplayName).ToList();
}

public sealed record ImportedFunction(string? Name, ushort? Ordinal, ushort? Hint)
{
    public string DisplayName => Name ?? $"Ordinal #{Ordinal}";
}
