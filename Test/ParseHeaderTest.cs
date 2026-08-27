using Core.PE;
namespace Test;
public class ParseHeaderTest
{
    [Fact]
    public void CheckParseHeader_EXE_True()
    {
        var parser = new HeaderParser();
        string systemExePath = @"C:\Windows\System32\cmd.exe";
        bool result = parser.CheckDOSHeader(systemExePath);
        Assert.True(result);
    }
    [Fact]
    public void CheckParseHeader_EXE_False()
    {
        var parser = new HeaderParser();
        string systemExePath = @"C:\Windows\hzbrat\cmd.exe";
        bool result = parser.CheckDOSHeader(systemExePath);
        Assert.False(result);
    }
}
