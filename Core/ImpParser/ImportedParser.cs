using System.Buffers.Binary;
using System.Text;
using Core.Analysis;
using Core.Models;
using Core.Models.ImportDLL;
using Core.PE;

namespace Core.ImpParser;

/// <summary>Resolves imported DLL names and function names/ordinals from PE import tables.</summary>
public sealed class ImportedParser
{
    private const int ImportDescriptorSize = 20;
    private const int MaximumCStringLength = 4096;
    private const int MaximumThunksPerLibrary = 65536;
    private const int MaximumImportDescriptors = 65536;
    private const int MaximumLibraries = 4096;
    private const int MaximumTotalFunctions = 200_000;

    public ImportParseResult Parse(
        string filePath,
        HPInfo info,
        IReadOnlyList<SingleSectionInfo> sections,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(info);
        ArgumentNullException.ThrowIfNull(sections);
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            return ImportParseResult.Fail("File not found.");
        }

        if (info.ImportDirectoryRVA == 0 && info.ImportDirectorySize == 0)
        {
            return ImportParseResult.Success([]);
        }

        if (info.ImportDirectoryRVA == 0 || info.ImportDirectorySize == 0)
        {
            return ImportParseResult.Fail("The import directory has an RVA or size of zero, but not both.");
        }

        try
        {
            using var reader = PeFileReader.Open(filePath);
            return Parse(reader, info, sections, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (IOException exception)
        {
            return ImportParseResult.Fail($"Unable to read the import table: {exception.Message}");
        }
        catch (UnauthorizedAccessException exception)
        {
            return ImportParseResult.Fail($"Unable to access the PE file: {exception.Message}");
        }
    }

    public ImportParseResult Parse(
        PeFileReader reader,
        HPInfo info,
        IReadOnlyList<SingleSectionInfo> sections,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(info);
        ArgumentNullException.ThrowIfNull(sections);
        if (info.ImportDirectoryRVA == 0 && info.ImportDirectorySize == 0)
        {
            return ImportParseResult.Success([]);
        }

        if (info.ImportDirectoryRVA == 0 || info.ImportDirectorySize == 0)
        {
            return ImportParseResult.Fail("The import directory has an RVA or size of zero, but not both.");
        }

        try
        {
            var libraries = new List<ImportedDLL>();
            bool foundTerminator = false;
            int totalFunctions = 0;

            ulong descriptorLimit = Math.Min(
                (ulong)info.ImportDirectorySize / ImportDescriptorSize,
                MaximumImportDescriptors);
            for (ulong index = 0; index < descriptorLimit; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                ulong consumed = index * ImportDescriptorSize;
                ulong descriptorRvaValue = (ulong)info.ImportDirectoryRVA + consumed;
                if (descriptorRvaValue > uint.MaxValue)
                {
                    return ImportParseResult.Fail("The import descriptor RVA overflows the PE address space.");
                }

                if (!TryReadRva(reader, (uint)descriptorRvaValue, ImportDescriptorSize, info, sections,
                        out _, out byte[] descriptor, out string? mappingError, cancellationToken))
                {
                    return ImportParseResult.Fail(mappingError!);
                }

                if (descriptor.AsSpan().IndexOfAnyExcept((byte)0) < 0)
                {
                    foundTerminator = true;
                    break;
                }

                uint originalFirstThunk = BinaryPrimitives.ReadUInt32LittleEndian(descriptor);
                uint nameRva = BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(12));
                uint firstThunk = BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(16));
                if (nameRva == 0 || (originalFirstThunk == 0 && firstThunk == 0))
                {
                    return ImportParseResult.Fail("An import descriptor is incomplete.");
                }

                if (libraries.Count >= MaximumLibraries)
                {
                    return ImportParseResult.Fail($"The import table exceeds the supported limit of {MaximumLibraries} libraries.");
                }

                if (!TryMapRva(reader, nameRva, info, sections, out long nameOffset, out long nameBytes, out mappingError))
                {
                    return ImportParseResult.Fail(mappingError!);
                }

                if (!TryReadCString(reader, nameOffset, nameBytes, out string dllName, out string? stringError, cancellationToken))
                {
                    return ImportParseResult.Fail($"Invalid imported DLL name: {stringError}");
                }

                var library = new ImportedDLL
                {
                    DLLName = dllName,
                    NameRVA = nameRva,
                    OriginalFirstThunk = originalFirstThunk,
                    FirstThunk = firstThunk
                };
                uint lookupTableRva = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
                if (!TryReadThunks(
                    reader,
                    lookupTableRva,
                    info,
                    sections,
                    library,
                    ref totalFunctions,
                    out string? thunkError,
                    cancellationToken))
                {
                    return ImportParseResult.Fail($"Invalid import table for '{dllName}': {thunkError}");
                }

                libraries.Add(library);
            }

            if (!foundTerminator)
            {
                return ImportParseResult.Fail("The import descriptor table has no null terminator within its declared size or supported entry limit.");
            }

            return ImportParseResult.Success(libraries);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (IOException exception)
        {
            return ImportParseResult.Fail($"Unable to read the import table: {exception.Message}");
        }
        catch (UnauthorizedAccessException exception)
        {
            return ImportParseResult.Fail($"Unable to access the PE file: {exception.Message}");
        }
    }

    private static bool TryReadThunks(
        PeFileReader reader,
        uint tableRva,
        HPInfo info,
        IReadOnlyList<SingleSectionInfo> sections,
        ImportedDLL library,
        ref int totalFunctions,
        out string? error,
        CancellationToken cancellationToken)
    {
        error = null;
        if (!TryMapRva(reader, tableRva, info, sections, out long tableOffset, out long available, out error))
        {
            return false;
        }

        int width = info.IsPE32Plus ? 8 : 4;
        long entryCount = Math.Min(available / width, MaximumThunksPerLibrary);
        byte[] entryBuffer = new byte[width];
        Span<byte> hintBuffer = stackalloc byte[2];
        for (long index = 0; index < entryCount; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            long entryOffset = tableOffset + index * width;
            reader.ReadExactly(entryOffset, entryBuffer, cancellationToken);
            ulong thunk = width == 8
                ? BinaryPrimitives.ReadUInt64LittleEndian(entryBuffer)
                : BinaryPrimitives.ReadUInt32LittleEndian(entryBuffer);
            if (thunk == 0)
            {
                return true;
            }

            if (totalFunctions >= MaximumTotalFunctions)
            {
                error = $"The import table exceeds the supported limit of {MaximumTotalFunctions} functions.";
                return false;
            }

            ulong ordinalFlag = width == 8 ? 0x8000000000000000UL : 0x80000000UL;
            if ((thunk & ordinalFlag) != 0)
            {
                library.Functions.Add(new ImportedFunction(null, (ushort)(thunk & 0xFFFF), null));
                totalFunctions++;
                continue;
            }

            if (thunk > uint.MaxValue)
            {
                error = "A function-name RVA exceeds the PE address space.";
                return false;
            }

            uint functionNameRva = (uint)thunk;
            if (functionNameRva > uint.MaxValue - 2)
            {
                error = "A function-name entry RVA overflows the PE address space.";
                return false;
            }
            if (!TryMapRva(reader, functionNameRva, info, sections, out long hintOffset, out long hintBytes, out error))
            {
                return false;
            }

            if (hintBytes < 3)
            {
                error = "A Hint/Name entry is truncated.";
                return false;
            }

            reader.ReadExactly(hintOffset, hintBuffer, cancellationToken);
            ushort hint = BinaryPrimitives.ReadUInt16LittleEndian(hintBuffer);
            if (!TryReadCString(reader, hintOffset + 2, hintBytes - 2, out string functionName, out error, cancellationToken))
            {
                return false;
            }

            library.Functions.Add(new ImportedFunction(functionName, null, hint));
            totalFunctions++;
        }

        error = "The thunk table has no null terminator within the file-backed section or supported entry limit.";
        return false;
    }

    private static bool TryReadRva(
        PeFileReader reader,
        uint rva,
        int length,
        HPInfo info,
        IReadOnlyList<SingleSectionInfo> sections,
        out long fileOffset,
        out byte[] bytes,
        out string? error,
        CancellationToken cancellationToken)
    {
        bytes = [];
        if (!TryMapRva(reader, rva, info, sections, out fileOffset, out long available, out error))
        {
            return false;
        }

        if (available < length)
        {
            error = "An import descriptor crosses the end of its file-backed section.";
            return false;
        }

        bytes = new byte[length];
        reader.ReadExactly(fileOffset, bytes, cancellationToken);
        return true;
    }

    private static bool TryMapRva(
        PeFileReader reader,
        uint rva,
        HPInfo info,
        IReadOnlyList<SingleSectionInfo> sections,
        out long fileOffset,
        out long available,
        out string? error) => RVAConverter.TryConvertRvaToFileOffset(
            rva, sections, info.SizeOfHeaders, reader.Length, out fileOffset, out available, out error);

    private static bool TryReadCString(
        PeFileReader reader,
        long offset,
        long available,
        out string value,
        out string? error,
        CancellationToken cancellationToken)
    {
        value = string.Empty;
        error = null;
        if (available <= 0)
        {
            error = "the string has no file-backed bytes";
            return false;
        }

        int bytesToRead = (int)Math.Min(available, MaximumCStringLength + 1L);
        byte[] buffer = new byte[bytesToRead];
        reader.ReadExactly(offset, buffer, cancellationToken);
        int terminator = Array.IndexOf(buffer, (byte)0);
        if (terminator < 0)
        {
            error = bytesToRead > MaximumCStringLength ? "the string exceeds the supported length" : "the string is not null-terminated";
            return false;
        }

        value = Encoding.ASCII.GetString(buffer, 0, terminator);
        if (value.Length == 0)
        {
            error = "the string is empty";
            return false;
        }
        return true;
    }
}

public sealed class ImportParseResult
{
    public bool IsSuccess { get; private init; }
    public string? ErrorMessage { get; private init; }
    public IReadOnlyList<ImportedDLL> Libraries { get; private init; } = [];

    private ImportParseResult() { }

    public static ImportParseResult Success(IReadOnlyList<ImportedDLL> libraries) =>
        new() { IsSuccess = true, Libraries = libraries };

    public static ImportParseResult Fail(string error) =>
        new() { IsSuccess = false, ErrorMessage = error };
}
