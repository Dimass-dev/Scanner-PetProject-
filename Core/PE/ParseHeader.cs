namespace Core.PE;
using Core.Models;
public class HeaderParser
{
    public HPResult Parse(string filePath)
    {    
        if(!File.Exists(filePath)) return HPResult.Fail("The file is missing from this directory");
        using var file = new FileStream(filePath, FileMode.Open, FileAccess.Read);
        if(file.Length < 64) return HPResult.Fail("The file length is insufficient");
        if(!TryGetPeOffset(file,out int peoffset,out string? errorMessage))
        {
            return HPResult.Fail(errorMessage!);
        }
        if(!ValidateSignature(file,peoffset,out string? errmessage))
        {
            return HPResult.Fail(errmessage!);
        }
        return HPResult.Success(peoffset);
    }
    private bool TryGetPeOffset(FileStream file,out int peoffset,out string? errorMessage )
    {
        peoffset = -1;
        errorMessage = null;
        byte[] buffer = new byte[2];
        file.ReadExactly(buffer,0,2);
        if(buffer[0] != 0x4D || buffer[1] != 0x5A)
        {
            errorMessage = "This file does not match the executable file type";
            return false;
        }
        file.Seek(0x3C,SeekOrigin.Begin);
        byte[] fileOffset = new byte[4];
        file.ReadExactly(fileOffset,0,4);
        peoffset = BitConverter.ToInt32(fileOffset,0);
        if(peoffset < 64 || peoffset > file.Length - 4)
        {
            errorMessage = "Invalid PE header offset value";
            return false;
        }
        return true;
    }
    private bool ValidateSignature(FileStream file,int offset,out string? errmessage)
    {
        errmessage = null;
        file.Seek(offset,SeekOrigin.Begin);
        byte[] sgbuffer = new byte[4];
        file.ReadExactly(sgbuffer,0,4);
        if (!sgbuffer.AsSpan().SequenceEqual("PE\0\0"u8))
        {
            errmessage = "Wrong signature";
            return false;
        }
        return true;
    }
}   