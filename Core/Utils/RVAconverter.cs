namespace Core.Models;

/// <summary>Maps an RVA to bytes that physically exist in a PE file.</summary>
public static class RVAConverter
{
    public static bool TryConvertRvaToFileOffset(
        uint rva,
        IReadOnlyList<SingleSectionInfo> sections,
        uint sizeOfHeaders,
        long fileLength,
        out long fileOffset,
        out long contiguousBytes,
        out string? error)
    {
        ArgumentNullException.ThrowIfNull(sections);
        fileOffset = 0;
        contiguousBytes = 0;
        error = null;

        if (fileLength < 0)
        {
            error = "The file length is invalid.";
            return false;
        }

        if (rva < sizeOfHeaders)
        {
            if (rva >= fileLength)
            {
                error = "The header RVA lies outside the file.";
                return false;
            }

            fileOffset = rva;
            contiguousBytes = Math.Min((long)sizeOfHeaders - rva, fileLength - fileOffset);
            return true;
        }

        foreach (SingleSectionInfo section in sections)
        {
            ulong start = section.VirtualAddress;
            ulong rawSize = section.SizeOfRawData;
            ulong virtualSize = section.VirtualSize == 0 ? rawSize : section.VirtualSize;
            ulong mappedSize = Math.Max(rawSize, virtualSize);
            ulong address = rva;
            if (address < start || address - start >= mappedSize)
                continue;

            ulong delta = address - start;
            if (delta >= rawSize)
            {
                error = "The RVA points to virtual section data that has no bytes in the file.";
                return false;
            }

            ulong rawOffset = (ulong)section.PointerToRawData + delta;
            if (rawOffset > long.MaxValue || rawOffset >= (ulong)fileLength)
            {
                error = "The RVA maps past the end of the file.";
                return false;
            }

            ulong remainingRaw = rawSize - delta;
            ulong remainingFile = (ulong)fileLength - rawOffset;
            fileOffset = (long)rawOffset;
            contiguousBytes = (long)Math.Min(remainingRaw, remainingFile);
            return true;
        }

        error = $"RVA 0x{rva:X8} does not belong to a file-backed PE header or section.";
        return false;
    }
}
