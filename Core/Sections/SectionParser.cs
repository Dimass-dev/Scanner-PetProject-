using System.Buffers.Binary;
using System.Text;
using Core.Models;
using Core.PE;

namespace Core.Sections;

/// <summary>Reads the IMAGE_SECTION_HEADER table after validating its file bounds.</summary>
public sealed class SectionParser
{
    private const int SectionHeaderSize = 40;

    public SingleSectionResult Parse(string filePath, HPInfo info)
    {
        ArgumentNullException.ThrowIfNull(info);
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            return SingleSectionResult.Fail("File not found.");
        if (info.NumberOfSections < 0 || info.NumberOfSections > 96 || info.SectionOffset < 0)
            return SingleSectionResult.Fail("The section table metadata is invalid.");

        try
        {
            using var file = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            int tableSize = checked(info.NumberOfSections * SectionHeaderSize);
            if (!HeaderParser.IsRangeWithinFile(info.SectionOffset, tableSize, file.Length))
                return SingleSectionResult.Fail("The section table extends past the end of the file.");

            byte[] table = new byte[tableSize];
            HeaderParser.ReadExactlyAt(file, info.SectionOffset, table);
            var sections = new List<SingleSectionInfo>(info.NumberOfSections);
            ReadOnlySpan<byte> bytes = table;
            for (int index = 0; index < info.NumberOfSections; index++)
            {
                int start = index * SectionHeaderSize;
                string name = Encoding.ASCII.GetString(bytes.Slice(start, 8)).TrimEnd('\0');
                sections.Add(new SingleSectionInfo
                {
                    SectionName = name,
                    VirtualSize = BinaryPrimitives.ReadUInt32LittleEndian(bytes[(start + 8)..]),
                    VirtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(bytes[(start + 12)..]),
                    SizeOfRawData = BinaryPrimitives.ReadUInt32LittleEndian(bytes[(start + 16)..]),
                    PointerToRawData = BinaryPrimitives.ReadUInt32LittleEndian(bytes[(start + 20)..]),
                    Characteristics = (SectionFlag)BinaryPrimitives.ReadUInt32LittleEndian(bytes[(start + 36)..])
                });
            }

            return SingleSectionResult.Success(sections);
        }
        catch (IOException exception)
        {
            return SingleSectionResult.Fail($"Unable to read the section table: {exception.Message}");
        }
        catch (OverflowException)
        {
            return SingleSectionResult.Fail("The section table size exceeds the supported range.");
        }
        catch (UnauthorizedAccessException exception)
        {
            return SingleSectionResult.Fail($"Unable to access the PE file: {exception.Message}");
        }
    }
}
