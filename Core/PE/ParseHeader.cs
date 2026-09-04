namespace Core.PE;
using Core.Models;
public class HeaderParser
{
    private const int InitialBufferSize = 1024;
    public HPResult Parse(string filePath)
    {    
        if(!File.Exists(filePath)) return HPResult.Fail("The file is missing from this directory");
        using var file = new FileStream(filePath, FileMode.Open, FileAccess.Read);
        if(file.Length < 64) return HPResult.Fail("The file length is insufficient");
        int bytesToRead = (int)Math.Min(file.Length,InitialBufferSize);
        byte[] buffer = new byte[bytesToRead];
        file.ReadExactly(buffer,0,bytesToRead);
        ReadOnlySpan<byte> headerSpan = buffer;
        if(!TryGetPeOffset(headerSpan,out int peoffset,out string? errorMessage))
        {
            return HPResult.Fail(errorMessage!);
        }
        if (peoffset + 96 > file.Length)
        {
            return HPResult.Fail("File ends before PE headers complete");
        }
        if (peoffset + 96 > headerSpan.Length)
        {
            int requiredSize = (int)Math.Min(file.Length, peoffset + 512);
            buffer = new byte[requiredSize];
            file.Seek(0, SeekOrigin.Begin);
            file.ReadExactly(buffer, 0, requiredSize);
            headerSpan = buffer;
        }
        if(!ValidateSignature(headerSpan,peoffset,out string? errmessage))
        {
            return HPResult.Fail(errmessage!);
        }
        string architecture = GetArchitecture(headerSpan,peoffset);
        ushort dllcharacteristics = TryGetDLLCharacteristics(headerSpan,peoffset);
        bool hasAslr = (dllcharacteristics & 0x0040) != 0;
        bool hasDep = (dllcharacteristics & 0x0100) != 0;
        var info = new HPInfo{
          PeOffset = peoffset,
          Architecture = architecture,
          HasASLR = hasAslr,
          HasDEP = hasDep,
        };
        return HPResult.Success(info);
    }
    private bool TryGetPeOffset(ReadOnlySpan<byte> buffer,out int peoffset,out string? errorMessage )
    {
        peoffset = -1;
        errorMessage = null;
        if (buffer.Length < 64)
        {
        errorMessage = "The buffer is too small to contain a valid DOS header";
        return false;
        }
        if(buffer[0] != 0x4D || buffer[1] != 0x5A)
        {
            errorMessage = "This file does not match the executable file type";
            return false;
        }
        peoffset = BitConverter.ToInt32(buffer.Slice(0x3C, 4));
        if(peoffset < 64)
        {
            errorMessage = "Invalid PE header offset value";
            return false;
        }
        return true;
    }
    private bool ValidateSignature(ReadOnlySpan<byte> buffer,int peOffset,out string? errmessage)
    {
        errmessage = null;
        ReadOnlySpan<byte> signature = buffer.Slice(peOffset,4);
        if (!signature.SequenceEqual("PE\0\0"u8))
        {
            errmessage = "Wrong signature";
            return false;
        }
        return true;
    }
    private string GetArchitecture(ReadOnlySpan<byte> buffer,int peOffset)
    {
        ushort arch = BitConverter.ToUInt16(buffer.Slice(peOffset + 4,2));
        return arch switch
        {
            0x014C => "x86",
            0x8664 => "x64",
            0xAA64 => "ARM64",
            _ => "Unknown"
        };  
    }
    private ushort TryGetDLLCharacteristics(ReadOnlySpan<byte> buffer,int peOffset)
    {
        int dllOffset = peOffset + 24 + 70;
        return BitConverter.ToUInt16(buffer.Slice(dllOffset,2));
    }
}   