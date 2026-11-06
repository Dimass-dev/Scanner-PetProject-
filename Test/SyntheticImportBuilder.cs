using System.Buffers.Binary;
using Core.Models;

namespace Scanner.Tests;

internal static class SyntheticImportBuilder
{
    private const int RawBase = 0x200;
    private const uint VirtualBase = 0x1000;
    private const int DescriptorSize = 20;
    private const int PageAlign = 0x200;

    public static string WriteFile(
        int libraryCount,
        int functionsPerLibrary,
        out HPInfo header,
        out IReadOnlyList<SingleSectionInfo> sections)
    {
        int descriptorTableSize = (libraryCount + 1) * DescriptorSize;
        const string dllName = "KERNEL32.dll";
        int nameBytes = dllName.Length + 1;
        int nameOffset = RawBase + descriptorTableSize;
        int thunkOffset = Align(nameOffset + nameBytes, 4);
        int tableEntryCount = functionsPerLibrary + 1;
        int thunkTableSize = tableEntryCount * 4;
        int rawSize = Align(thunkOffset - RawBase + thunkTableSize * Math.Max(libraryCount, 1), PageAlign);
        byte[] file = new byte[RawBase + rawSize];

        for (int index = 0; index < libraryCount; index++)
        {
            int descriptorOffset = RawBase + index * DescriptorSize;
            int tableOffset = thunkOffset + index * thunkTableSize;
            uint tableRva = VirtualBase + (uint)(tableOffset - RawBase);

            BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(descriptorOffset, 4), tableRva);
            BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(descriptorOffset + 12, 4), VirtualBase + (uint)(nameOffset - RawBase));
            BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(descriptorOffset + 16, 4), tableRva);

            for (int function = 0; function < functionsPerLibrary; function++)
            {
                int entryOffset = tableOffset + function * 4;
                BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(entryOffset, 4), 0x80000001);
            }
        }

        // Null descriptor terminator.
        int terminatorOffset = RawBase + libraryCount * DescriptorSize;
        Array.Clear(file, terminatorOffset, DescriptorSize);

        System.Text.Encoding.ASCII.GetBytes(dllName).CopyTo(file.AsSpan(nameOffset));
        file[nameOffset + dllName.Length] = 0;

        string path = Path.Combine(Path.GetTempPath(), $"scanner-imports-{Guid.NewGuid():N}.bin");
        File.WriteAllBytes(path, file);

        header = new HPInfo
        {
            IsPE32Plus = false,
            SizeOfHeaders = RawBase,
            ImportDirectoryRVA = VirtualBase,
            ImportDirectorySize = (uint)descriptorTableSize,
            NumberOfSections = 1
        };

        sections = new[]
        {
            new SingleSectionInfo
            {
                SectionName = ".text",
                VirtualAddress = VirtualBase,
                VirtualSize = (uint)rawSize,
                SizeOfRawData = (uint)rawSize,
                PointerToRawData = RawBase
            }
        };

        return path;
    }

    private static int Align(int value, int alignment) =>
        (value + alignment - 1) / alignment * alignment;
}
