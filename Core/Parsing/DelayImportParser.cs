using Core.Models;
using Core.Models.ImportDLL;
using System.Buffers.Binary;
using System.Text;

namespace Core.Parsing;

/// <summary>
/// Parses PE Delay Import Directory (directory 13).
/// </summary>
public sealed class DelayImportParser
{
    /// <summary>Parse delay import directory.</summary>
    public IReadOnlyList<ImportedDLL> Parse(string filePath, HPInfo header, IReadOnlyList<SingleSectionInfo> sections)
    {
        if (header.DelayImportDirectoryRVA == 0 || header.DelayImportDirectorySize == 0)
            return Array.Empty<ImportedDLL>();

        try
        {
            using var file = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (!TryGetFileOffset(header.DelayImportDirectoryRVA, sections, file.Length, header.SizeOfHeaders, out uint fileOffset))
                return Array.Empty<ImportedDLL>();

            var imports = new List<ImportedDLL>();
            file.Position = fileOffset;

            // Each delay import descriptor is 32 bytes
            const int descriptorSize = 32;
            int maxDescriptors = 100; // Safety limit

            for (int i = 0; i < maxDescriptors; i++)
            {
                if (file.Position + descriptorSize > file.Length)
                    break;

                byte[] descriptor = new byte[descriptorSize];
                if (file.Read(descriptor) < descriptorSize)
                    break;

                uint attributes = BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(0));
                uint dllNameRva = BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(4));
                uint moduleHandle = BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(8));
                uint delayIAT = BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(12));
                uint delayINT = BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(16));

                // Null descriptor marks end
                if (dllNameRva == 0)
                    break;

                // Read DLL name
                if (!TryGetFileOffset(dllNameRva, sections, file.Length, header.SizeOfHeaders, out uint dllNameOffset))
                    continue;

                string? dllName = ReadNullTerminatedString(file, dllNameOffset);
                if (string.IsNullOrEmpty(dllName))
                    continue;

                // Parse import names (from INT or IAT)
                uint namesRva = delayINT != 0 ? delayINT : delayIAT;
                var functions = ParseImportNames(file, sections, header.SizeOfHeaders, namesRva, header.IsPE32Plus);

                var dll = new ImportedDLL(dllName, functions);
                imports.Add(dll);
            }

            return imports;
        }
        catch
        {
            return Array.Empty<ImportedDLL>();
        }
    }

    private List<string> ParseImportNames(FileStream file, IReadOnlyList<SingleSectionInfo> sections, uint sizeOfHeaders, uint namesRva, bool isPe64)
    {
        var functions = new List<string>();

        if (namesRva == 0 || !TryGetFileOffset(namesRva, sections, file.Length, sizeOfHeaders, out uint namesOffset))
            return functions;

        long savedPos = file.Position;
        file.Position = namesOffset;

        int entrySize = isPe64 ? 8 : 4;
        int maxEntries = 1000;

        for (int i = 0; i < maxEntries; i++)
        {
            if (file.Position + entrySize > file.Length)
                break;

            byte[] entryBytes = new byte[entrySize];
            if (file.Read(entryBytes) < entrySize)
                break;

            ulong entry = isPe64
                ? BinaryPrimitives.ReadUInt64LittleEndian(entryBytes)
                : BinaryPrimitives.ReadUInt32LittleEndian(entryBytes);

            if (entry == 0)
                break;

            // Check if import by ordinal
            ulong ordinalFlag = isPe64 ? 0x8000000000000000UL : 0x80000000UL;
            if ((entry & ordinalFlag) != 0)
            {
                ushort ordinal = (ushort)(entry & 0xFFFF);
                functions.Add($"#{ordinal}");
            }
            else
            {
                // Import by name
                uint nameRva = (uint)(entry & 0x7FFFFFFF);
                if (TryGetFileOffset(nameRva, sections, file.Length, sizeOfHeaders, out uint nameOffset))
                {
                    string? funcName = ReadImportName(file, nameOffset);
                    if (!string.IsNullOrEmpty(funcName))
                        functions.Add(funcName);
                }
            }
        }

        file.Position = savedPos;
        return functions;
    }

    private static bool TryGetFileOffset(uint rva, IReadOnlyList<SingleSectionInfo> sections, long fileLength, uint sizeOfHeaders, out uint fileOffset)
    {
        if (RVAConverter.TryConvertRvaToFileOffset(rva, sections, sizeOfHeaders, fileLength, out long offset, out _, out _) && offset <= uint.MaxValue)
        {
            fileOffset = (uint)offset;
            return true;
        }

        fileOffset = 0;
        return false;
    }

    private string? ReadNullTerminatedString(FileStream file, uint offset, int maxLength = 256)
    {
        long savedPos = file.Position;
        file.Position = offset;

        byte[] buffer = new byte[maxLength];
        int bytesRead = file.Read(buffer);

        int nullIndex = Array.IndexOf(buffer, (byte)0, 0, bytesRead);
        if (nullIndex < 0)
            nullIndex = bytesRead;

        file.Position = savedPos;

        if (nullIndex == 0)
            return null;

        return Encoding.UTF8.GetString(buffer, 0, nullIndex);
    }

    private string? ReadImportName(FileStream file, uint offset)
    {
        long savedPos = file.Position;
        file.Position = offset;

        // Skip hint (2 bytes)
        file.Position += 2;

        byte[] buffer = new byte[256];
        int bytesRead = file.Read(buffer);

        int nullIndex = Array.IndexOf(buffer, (byte)0, 0, bytesRead);
        if (nullIndex < 0)
            nullIndex = bytesRead;

        file.Position = savedPos;

        if (nullIndex == 0)
            return null;

        return Encoding.UTF8.GetString(buffer, 0, nullIndex);
    }
}
