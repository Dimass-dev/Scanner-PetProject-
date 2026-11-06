using System.Buffers.Binary;
using System.Text;
using Core.Analysis;
using Core.Models;
using Core.PE;

namespace Core.Sections;

/// <summary>Reads the IMAGE_SECTION_HEADER table after validating its file bounds.</summary>
public sealed class SectionParser
{
    private const int SectionHeaderSize = 40;

    public SingleSectionResult Parse(string filePath, HPInfo info, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(info);
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            return SingleSectionResult.Fail("File not found.");
        }

        try
        {
            using var reader = PeFileReader.Open(filePath);
            return Parse(reader, info, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (IOException exception)
        {
            return SingleSectionResult.Fail($"Unable to read the section table: {exception.Message}");
        }
        catch (UnauthorizedAccessException exception)
        {
            return SingleSectionResult.Fail($"Unable to access the PE file: {exception.Message}");
        }
    }

    public SingleSectionResult Parse(PeFileReader reader, HPInfo info, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(info);
        if (info.NumberOfSections < 0 || info.NumberOfSections > 96 || info.SectionOffset < 0)
        {
            return SingleSectionResult.Fail("The section table metadata is invalid.");
        }

        try
        {
            int tableSize = checked(info.NumberOfSections * SectionHeaderSize);
            if (!reader.IsRangeWithinFile(info.SectionOffset, tableSize))
            {
                return SingleSectionResult.Fail("The section table extends past the end of the file.");
            }

            byte[] table = new byte[tableSize];
            reader.ReadExactly(info.SectionOffset, table, cancellationToken);
            var sections = new List<SingleSectionInfo>(info.NumberOfSections);
            ReadOnlySpan<byte> bytes = table;
            for (int index = 0; index < info.NumberOfSections; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();
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
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (EndOfStreamException)
        {
            return SingleSectionResult.Fail("The section table extends past the end of the file.");
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
