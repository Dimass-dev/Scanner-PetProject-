using Core.PE;
using Xunit;

namespace Test;

public class HeaderParserTests
{
    [Fact]
    public void Parse_ValidExe_ReturnsSuccessWithValidOffset()
    {
        var parser = new HeaderParser();
        string systemExe = @"C:\Windows\System32\cmd.exe";
        var result = parser.Parse(systemExe);
        Assert.True(result.IsSuccess);
        Assert.True(result.PeOffset >= 64);
        Assert.Null(result.ErrorMessage);
    }

    [Fact]
    public void Parse_NonExistentFile_ReturnsFail()
    {
        var parser = new HeaderParser();
        string fakePath = @"C:\fake_file_9999.exe";
        var result = parser.Parse(fakePath);
        Assert.False(result.IsSuccess);
        Assert.NotNull(result.ErrorMessage);
    }

    [Fact]
    public void Parse_NonPeFile_ReturnsFailWithSignatureError()
    {
        var parser = new HeaderParser();
        string nonPePath = @"C:\Windows\win.ini"; 
        var result = parser.Parse(nonPePath);
        Assert.False(result.IsSuccess);
        Assert.Equal("This file does not match the executable file type", result.ErrorMessage);
    }
}