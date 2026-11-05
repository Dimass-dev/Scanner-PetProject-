using Core.Analysis;
using Core.Models;
using System.Buffers.Binary;

namespace Core.Parsing;

/// <summary>
/// Parses PE Load Configuration Directory for SafeSEH and Control Flow Guard information.
/// </summary>
public sealed class LoadConfigParser
{
    private const uint GuardCfInstrumented = 0x00000100;
    private const uint GuardCfFunctionTablePresent = 0x00000400;

    /// <summary>Parse load config directory.</summary>
    public LoadConfigInfo? Parse(string filePath, HPInfo header, IReadOnlyList<SingleSectionInfo> sections)
    {
        if (header.LoadConfigDirectoryRVA == 0 || header.LoadConfigDirectorySize == 0)
            return null;

        try
        {
            using var file = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);

            if (!RVAConverter.TryConvertRvaToFileOffset(
                header.LoadConfigDirectoryRVA,
                sections,
                header.SizeOfHeaders,
                file.Length,
                out long fileOffset,
                out _,
                out _))
                return null;

            if (fileOffset + 4 > file.Length)
                return null;

            // Read size field (first DWORD)
            file.Position = fileOffset;
            Span<byte> sizeBytes = stackalloc byte[4];
            if (file.Read(sizeBytes) < 4)
                return null;

            uint size = BinaryPrimitives.ReadUInt32LittleEndian(sizeBytes);
            if (size < 64 || size > 65536) // Sanity check
                return null;

            // Read the structure (limit to reasonable size)
            int readSize = Math.Min((int)size, 256);
            byte[] data = new byte[readSize];
            file.Position = fileOffset;
            if (file.Read(data) < readSize)
                return null;

            // Parse based on architecture
            if (header.IsPE32Plus)
                return ParseLoadConfig64(data);
            else
                return ParseLoadConfig32(data);
        }
        catch
        {
            return null;
        }
    }

    private LoadConfigInfo ParseLoadConfig32(byte[] data)
    {
        uint size = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(0));

        // SafeSEH fields (x86 only)
        uint seHandlerTable = 0;
        uint seHandlerCount = 0;
        if (size >= 72 && data.Length >= 72)
        {
            seHandlerTable = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(64));
            seHandlerCount = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(68));
        }

        // CFG fields
        uint guardCFCheckFunction = 0;
        uint guardCFDispatchFunction = 0;
        uint guardCFFunctionTable = 0;
        uint guardCFFunctionCount = 0;
        uint guardFlags = 0;

        if (size >= 92 && data.Length >= 92)
        {
            guardCFCheckFunction = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(72));
            guardCFDispatchFunction = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(76));
            guardCFFunctionTable = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(80));
            guardCFFunctionCount = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(84));
            guardFlags = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(88));
        }

        return new LoadConfigInfo(
            Size: size,
            HasSEH: seHandlerTable != 0 && seHandlerCount > 0,
            SEHandlerTable: seHandlerTable,
            SEHandlerCount: seHandlerCount,
            GuardCFCheckFunctionPointer: guardCFCheckFunction,
            GuardCFDispatchFunctionPointer: guardCFDispatchFunction,
            GuardCFFunctionTable: guardCFFunctionTable,
            GuardCFFunctionCount: guardCFFunctionCount,
            GuardFlags: guardFlags,
            IsCFInstrumented: (guardFlags & GuardCfInstrumented) != 0,
            IsCFFunctionTablePresent: (guardFlags & GuardCfFunctionTablePresent) != 0);
    }

    private LoadConfigInfo ParseLoadConfig64(byte[] data)
    {
        uint size = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(0));

        // No SafeSEH on x64
        // CFG fields (ULONGLONG pointers in IMAGE_LOAD_CONFIG_DIRECTORY64)
        uint guardCFCheckFunction = 0;
        uint guardCFDispatchFunction = 0;
        uint guardCFFunctionTable = 0;
        uint guardCFFunctionCount = 0;
        uint guardFlags = 0;

        if (size >= 144 && data.Length >= 144)
        {
            guardCFCheckFunction = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(112));
            guardCFDispatchFunction = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(120));
            guardCFFunctionTable = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(128));
            guardCFFunctionCount = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(136));
        }

        if (size >= 148 && data.Length >= 148)
        {
            guardFlags = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(144));
        }

        return new LoadConfigInfo(
            Size: size,
            HasSEH: false, // x64 doesn't use SafeSEH
            SEHandlerTable: 0,
            SEHandlerCount: 0,
            GuardCFCheckFunctionPointer: guardCFCheckFunction,
            GuardCFDispatchFunctionPointer: guardCFDispatchFunction,
            GuardCFFunctionTable: guardCFFunctionTable,
            GuardCFFunctionCount: guardCFFunctionCount,
            GuardFlags: guardFlags,
            IsCFInstrumented: (guardFlags & GuardCfInstrumented) != 0,
            IsCFFunctionTablePresent: (guardFlags & GuardCfFunctionTablePresent) != 0);
    }
}
