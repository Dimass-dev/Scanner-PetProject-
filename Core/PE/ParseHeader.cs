namespace Core.PE;
public class HeaderParser
{
   public bool CheckDOSHeader(string filePath)
    {
        if(!File.Exists(filePath)) return false;
        using var file = new FileStream(filePath, FileMode.Open, FileAccess.Read);
        if(file.Length < 2) return false;
        byte[] buffer = new byte[2];
        file.ReadExactly(buffer,0,2);
        return buffer[0] == 0x4D && buffer[1] == 0x5A;
    }
}