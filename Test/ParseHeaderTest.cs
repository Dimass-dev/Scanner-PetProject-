namespace Scanner.Tests;

using Core.PE;
using Core.Models;
using Xunit;

public class HeaderParserTests
{
    private readonly HeaderParser _parser = new();

    [Fact]
    public void Parse_CmdExe_SuccessfullyParsesArchitectureAndSecurityFlags()
    {
        var result = _parser.Parse(@"C:\Windows\System32\cmd.exe");

        Assert.True(result.IsSuccess, result.ErrorMessage);
        Assert.NotNull(result.Info);
        Assert.Equal("x64", result.Info.Architecture);
        Assert.True(result.Info.HasASLR);
        Assert.True(result.Info.HasDEP);
    }

    [Fact]
    public void Parse_InvalidSignature_ReturnsFailure()
    {
        string tempPath = Path.GetTempFileName();
        try
        {
            byte[] dummyData = new byte[256];
            dummyData[0] = 0x4D;
            dummyData[1] = 0x5A;
            dummyData[0x3C] = 0x40;

            dummyData[0x40] = (byte)'F';
            dummyData[0x41] = (byte)'A';
            dummyData[0x42] = (byte)'I';
            dummyData[0x43] = (byte)'L';

            File.WriteAllBytes(tempPath, dummyData);

            var result = _parser.Parse(tempPath);

            Assert.False(result.IsSuccess);
            Assert.Equal("Wrong signature", result.ErrorMessage);
        }
        finally
        {
            if (File.Exists(tempPath))
            {
                File.Delete(tempPath);
            }
        }
    }
}