using Core.ImpParser;
using Xunit;

namespace Scanner.Tests;

public sealed class ImportBudgetTests
{
    [Fact]
    public void TooManyLibraries_FailsWithClearError()
    {
        string path = SyntheticImportBuilder.WriteFile(4097, 0, out var header, out var sections);
        try
        {
            var result = new ImportedParser().Parse(path, header, sections);
            Assert.False(result.IsSuccess);
            Assert.Contains("libraries", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void TooManyFunctions_FailsBeforeAllocatingUnboundedData()
    {
        string path = SyntheticImportBuilder.WriteFile(4, 55_000, out var header, out var sections);
        try
        {
            var result = new ImportedParser().Parse(path, header, sections);
            Assert.False(result.IsSuccess);
            Assert.Contains("functions", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
