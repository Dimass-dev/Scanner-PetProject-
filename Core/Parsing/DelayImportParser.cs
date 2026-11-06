using System.Buffers.Binary;
using System.Text;
using Core.Analysis;
using Core.Models;
using Core.Models.ImportDLL;

namespace Core.Parsing;

/// <summary>
/// Parses PE Delay Import Directory (directory 13).
/// </summary>
public sealed class DelayImportParser
{
    private const int DescriptorSize = 32;
    private const int MaximumDescriptors = 100;
    private const int MaximumThunksPerLibrary = 1000;
    private const int MaximumStringLength = 256;

    /// <summary>Parse delay import directory.</summary>
    public IReadOnlyList<ImportedDLL> Parse(
        string filePath,
        HPInfo header,
        IReadOnlyList<SingleSectionInfo> sections,
        CancellationToken cancellationToken = default)
    {
        if (header.DelayImportDirectoryRVA == 0 || header.DelayImportDirectorySize == 0)
        {
            return Array.Empty<ImportedDLL>();
        }

        try
        {
            using var reader = PeFileReader.Open(filePath);
            return Parse(reader, header, sections, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return Array.Empty<ImportedDLL>();
        }
    }

    public IReadOnlyList<ImportedDLL> Parse(
        PeFileReader reader,
        HPInfo header,
        IReadOnlyList<SingleSectionInfo> sections,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(header);
        ArgumentNullException.ThrowIfNull(sections);

        if (header.DelayImportDirectoryRVA == 0 || header.DelayImportDirectorySize == 0)
        {
            return Array.Empty<ImportedDLL>();
        }

        try
        {
            if (!TryGetFileOffset(
                header.DelayImportDirectoryRVA,
                sections,
                reader.Length,
                header.SizeOfHeaders,
                out long directoryOffset))
            {
                return Array.Empty<ImportedDLL>();
            }

            var imports = new List<ImportedDLL>();
            long descriptorLimit = Math.Min(
                header.DelayImportDirectorySize / DescriptorSize,
                MaximumDescriptors);

            for (int i = 0; i < descriptorLimit; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                long descriptorOffset = directoryOffset + i * DescriptorSize;
                if (!reader.IsRangeWithinFile(descriptorOffset, DescriptorSize))
                {
                    break;
                }

                byte[] descriptor = new byte[DescriptorSize];
                reader.ReadExactly(descriptorOffset, descriptor, cancellationToken);

                uint dllNameRva = BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(4));
                uint delayIAT = BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(12));
                uint delayINT = BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(16));

                // Null descriptor marks end
                if (dllNameRva == 0)
                {
                    break;
                }

                if (!TryGetFileOffset(dllNameRva, sections, reader.Length, header.SizeOfHeaders, out long dllNameOffset))
                {
                    continue;
                }

                string? dllName = ReadNullTerminatedString(reader, dllNameOffset, cancellationToken);
                if (string.IsNullOrEmpty(dllName))
                {
                    continue;
                }

                // Parse import names (from INT or IAT)
                uint namesRva = delayINT != 0 ? delayINT : delayIAT;
                var functions = ParseImportNames(
                    reader,
                    sections,
                    header.SizeOfHeaders,
                    namesRva,
                    header.IsPE32Plus,
                    cancellationToken);

                imports.Add(new ImportedDLL(dllName, functions));
            }

            return imports;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return Array.Empty<ImportedDLL>();
        }
    }

    private List<string> ParseImportNames(
        PeFileReader reader,
        IReadOnlyList<SingleSectionInfo> sections,
        uint sizeOfHeaders,
        uint namesRva,
        bool isPe64,
        CancellationToken cancellationToken)
    {
        var functions = new List<string>();

        if (namesRva == 0 ||
            !TryGetFileOffset(namesRva, sections, reader.Length, sizeOfHeaders, out long namesOffset))
        {
            return functions;
        }

        int entrySize = isPe64 ? 8 : 4;

        for (int i = 0; i < MaximumThunksPerLibrary; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            long entryOffset = namesOffset + (long)i * entrySize;
            if (!reader.IsRangeWithinFile(entryOffset, entrySize))
            {
                break;
            }

            byte[] entryBytes = new byte[entrySize];
            reader.ReadExactly(entryOffset, entryBytes, cancellationToken);

            ulong entry = isPe64
                ? BinaryPrimitives.ReadUInt64LittleEndian(entryBytes)
                : BinaryPrimitives.ReadUInt32LittleEndian(entryBytes);

            if (entry == 0)
            {
                break;
            }

            // Check if import by ordinal
            ulong ordinalFlag = isPe64 ? 0x8000000000000000UL : 0x80000000UL;
            if ((entry & ordinalFlag) != 0)
            {
                ushort ordinal = (ushort)(entry & 0xFFFF);
                functions.Add($"#{ordinal}");
                continue;
            }

            uint nameRva = (uint)(entry & 0x7FFFFFFF);
            if (TryGetFileOffset(nameRva, sections, reader.Length, sizeOfHeaders, out long nameOffset))
            {
                string? funcName = ReadImportName(reader, nameOffset, cancellationToken);
                if (!string.IsNullOrEmpty(funcName))
                {
                    functions.Add(funcName);
                }
            }
        }

        return functions;
    }

    private static bool TryGetFileOffset(
        uint rva,
        IReadOnlyList<SingleSectionInfo> sections,
        long fileLength,
        uint sizeOfHeaders,
        out long fileOffset)
    {
        if (RVAConverter.TryConvertRvaToFileOffset(
            rva,
            sections,
            sizeOfHeaders,
            fileLength,
            out fileOffset,
            out _,
            out _))
        {
            return true;
        }

        fileOffset = 0;
        return false;
    }

    private static string? ReadNullTerminatedString(
        PeFileReader reader,
        long offset,
        CancellationToken cancellationToken)
    {
        int available = (int)Math.Min(MaximumStringLength, reader.Length - offset);
        if (available <= 0)
        {
            return null;
        }

        byte[] buffer = new byte[available];
        int bytesRead = reader.Read(offset, buffer);
        if (bytesRead <= 0)
        {
            return null;
        }

        int nullIndex = Array.IndexOf(buffer, (byte)0, 0, bytesRead);
        if (nullIndex < 0)
        {
            nullIndex = bytesRead;
        }

        return nullIndex == 0
            ? null
            : Encoding.UTF8.GetString(buffer, 0, nullIndex);
    }

    private static string? ReadImportName(
        PeFileReader reader,
        long offset,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // Skip hint (2 bytes)
        long nameOffset = offset + 2;
        int available = (int)Math.Min(MaximumStringLength, reader.Length - nameOffset);
        if (available <= 0)
        {
            return null;
        }

        byte[] buffer = new byte[available];
        int bytesRead = reader.Read(nameOffset, buffer);
        if (bytesRead <= 0)
        {
            return null;
        }

        int nullIndex = Array.IndexOf(buffer, (byte)0, 0, bytesRead);
        if (nullIndex < 0)
        {
            nullIndex = bytesRead;
        }

        return nullIndex == 0
            ? null
            : Encoding.UTF8.GetString(buffer, 0, nullIndex);
    }
}
