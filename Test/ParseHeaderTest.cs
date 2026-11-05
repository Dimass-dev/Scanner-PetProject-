namespace Scanner.Tests;

using Core.PE;
using Xunit;

public class HeaderParserTests
{
    private readonly HeaderParser _parser = new();

    [Fact]
    public void Parse_SyntheticPe64_SuccessfullyParsesArchitectureAndSecurityFlags()
    {
        string tempPath = PeBuilder.WriteTemporaryPeFile();
        try
        {
            var result = _parser.Parse(tempPath);

            Assert.True(result.IsSuccess, result.ErrorMessage);
            Assert.NotNull(result.Info);
            Assert.Equal("x64", result.Info.Architecture);
            Assert.True(result.Info.HasASLR);
            Assert.True(result.Info.HasDEP);
        }
        finally
        {
            File.Delete(tempPath);
        }
    }

    [Fact]
    public void Parse_InvalidSignature_ReturnsFailure()
    {
        byte[] image = PeBuilder.CreatePe64();
        "FAIL"u8.CopyTo(image.AsSpan(PeBuilder.PeOffset));

        string tempPath = PeBuilder.WriteTemporaryPeFile(image);
        try
        {
            var result = _parser.Parse(tempPath);

            Assert.False(result.IsSuccess);
            Assert.Equal("The PE signature is invalid.", result.ErrorMessage);
        }
        finally
        {
            File.Delete(tempPath);
        }
    }
}
