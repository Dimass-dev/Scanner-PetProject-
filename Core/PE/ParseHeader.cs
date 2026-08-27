namespace Core.PE;
public class HeaderParser
{
   public int CheckDOSHeader(string filePath)
    {
        if(!File.Exists(filePath)) return -1;
        using var file = new FileStream(filePath, FileMode.Open, FileAccess.Read);
        if(file.Length < 64) return -1;
        byte[] buffer = new byte[2];
        file.ReadExactly(buffer,0,2);
        if(buffer[0] != 0x4D || buffer[1] != 0x5A) return -1;
        file.Seek(0x3C,SeekOrigin.Begin);
        byte[] fileOffset = new byte[4];
        file.ReadExactly(fileOffset,0,4);
        int peOffset = BitConverter.ToInt32(fileOffset,0);
        if(peOffset < 64 || peOffset > file.Length)return -1;
        return peOffset;
    }
}