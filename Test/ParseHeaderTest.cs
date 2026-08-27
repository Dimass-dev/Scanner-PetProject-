using Core.PE;
namespace Test;
public class ParseHeaderTest
{
    [Fact]
    public void CheckParseHeader_EXE_True()
    {
        var parser = new HeaderParser();
        string systemExePath = @"C:\Windows\System32\cmd.exe";
        int result = parser.CheckDOSHeader(systemExePath);
        Assert.True(result > 64);
    }
    [Fact]
    public void CheckParseHeader_EXE_False()
    {
        var parser = new HeaderParser();
        string systemExePath = @"C:\Windows\hzbrat\cmd.exe";
        int result = parser.CheckDOSHeader(systemExePath);
        Assert.Equal(-1,result);
    }
}
