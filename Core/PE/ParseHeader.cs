using System.Buffers.Binary;
using Core.Models;

namespace Core.PE;

/// <summary>Reads PE/COFF metadata without loading or executing the image.</summary>
public sealed class HeaderParser
{
    private const int DosHeaderSize = 64;
    private const int CoffHeaderSize = 20;
    private const int MaximumSectionCount = 96;
    private const ushort Pe32Magic = 0x10B;
    private const ushort Pe32PlusMagic = 0x20B;
    private const ushort DllDynamicBase = 0x0040;
    private const ushort DllHighEntropyVa = 0x0020;
    private const ushort DllNxCompat = 0x0100;
    private const ushort DllGuardCf = 0x4000;
    private const ushort ImageFileDll = 0x2000;

    public HPResult Parse(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            return HPResult.Fail("A file path is required.");
        if (!File.Exists(filePath))
            return HPResult.Fail("The file does not exist.");

        try
        {
            using var file = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (file.Length < DosHeaderSize)
                return HPResult.Fail("The file is too small to contain a DOS header.");

            Span<byte> dosHeader = stackalloc byte[DosHeaderSize];
            ReadExactlyAt(file, 0, dosHeader);
            if (!dosHeader[..2].SequenceEqual("MZ"u8))
                return HPResult.Fail("The DOS signature is missing.");

            uint peOffsetValue = BinaryPrimitives.ReadUInt32LittleEndian(dosHeader[0x3C..0x40]);
            if (peOffsetValue < DosHeaderSize || peOffsetValue > int.MaxValue)
                return HPResult.Fail("The PE header offset is invalid.");
            long peOffset = peOffsetValue;
            if (!IsRangeWithinFile(peOffset, 4 + CoffHeaderSize, file.Length))
                return HPResult.Fail("The file ends before the PE/COFF headers are complete.");

            Span<byte> signatureAndCoff = stackalloc byte[4 + CoffHeaderSize];
            ReadExactlyAt(file, peOffset, signatureAndCoff);
            if (!signatureAndCoff[..4].SequenceEqual("PE\0\0"u8))
                return HPResult.Fail("The PE signature is invalid.");

            ReadOnlySpan<byte> coff = signatureAndCoff[4..];
            ushort machine = BinaryPrimitives.ReadUInt16LittleEndian(coff);
            int sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(coff[2..]);
            uint timeDateStamp = BinaryPrimitives.ReadUInt32LittleEndian(coff[4..]);
            ushort optionalHeaderSize = BinaryPrimitives.ReadUInt16LittleEndian(coff[16..]);
            ushort fileCharacteristics = BinaryPrimitives.ReadUInt16LittleEndian(coff[18..]);
            if (sectionCount > MaximumSectionCount)
                return HPResult.Fail($"The section count exceeds the supported limit of {MaximumSectionCount}.");

            long optionalHeaderOffset = peOffset + 4 + CoffHeaderSize;
            if (optionalHeaderSize < 2 || !IsRangeWithinFile(optionalHeaderOffset, optionalHeaderSize, file.Length))
                return HPResult.Fail("The optional header is truncated or has an invalid size.");

            byte[] optionalHeader = new byte[optionalHeaderSize];
            ReadExactlyAt(file, optionalHeaderOffset, optionalHeader);
            ReadOnlySpan<byte> optional = optionalHeader;
            ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(optional);
            if (magic is not (Pe32Magic or Pe32PlusMagic))
                return HPResult.Fail($"Unsupported optional-header magic 0x{magic:X4}.");

            bool isPe32Plus = magic == Pe32PlusMagic;
            if (optional.Length < 72)
                return HPResult.Fail("The optional header is too short to contain DllCharacteristics.");

            // Read standard optional header fields
            uint addressOfEntryPoint = optional.Length >= 20
                ? BinaryPrimitives.ReadUInt32LittleEndian(optional[16..])
                : 0;

            uint sizeOfImage = optional.Length >= 60
                ? BinaryPrimitives.ReadUInt32LittleEndian(optional[56..])
                : 0;

            uint sizeOfHeaders = optional.Length >= 64
                ? BinaryPrimitives.ReadUInt32LittleEndian(optional[60..])
                : 0;

            uint checkSum = optional.Length >= 68
                ? BinaryPrimitives.ReadUInt32LittleEndian(optional[64..])
                : 0;

            ushort subsystem = optional.Length >= 70
                ? BinaryPrimitives.ReadUInt16LittleEndian(optional[68..])
                : (ushort)0;

            ushort dllCharacteristics = BinaryPrimitives.ReadUInt16LittleEndian(optional[70..]);

            // Parse data directories
            uint exportRva = 0, exportSize = 0;
            uint importRva = 0, importSize = 0;
            uint resourceRva = 0, resourceSize = 0;
            uint securityOffset = 0, securitySize = 0;
            uint loadConfigRva = 0, loadConfigSize = 0;
            uint delayImportRva = 0, delayImportSize = 0;
            uint debugRva = 0, debugSize = 0;

            int numberOfDirectoriesOffset = isPe32Plus ? 108 : 92;
            int dataDirectoriesOffset = isPe32Plus ? 112 : 96;

            if (optional.Length >= numberOfDirectoriesOffset + 4)
            {
                uint directoryCount = BinaryPrimitives.ReadUInt32LittleEndian(optional[numberOfDirectoriesOffset..]);
                int dirBase = dataDirectoriesOffset;

                // Export (0)
                if (directoryCount > 0 && optional.Length >= dirBase + 8)
                {
                    exportRva = BinaryPrimitives.ReadUInt32LittleEndian(optional[dirBase..]);
                    exportSize = BinaryPrimitives.ReadUInt32LittleEndian(optional[(dirBase + 4)..]);
                }

                // Import (1)
                if (directoryCount > 1 && optional.Length >= dirBase + 16)
                {
                    importRva = BinaryPrimitives.ReadUInt32LittleEndian(optional[(dirBase + 8)..]);
                    importSize = BinaryPrimitives.ReadUInt32LittleEndian(optional[(dirBase + 12)..]);
                }

                // Resource (2)
                if (directoryCount > 2 && optional.Length >= dirBase + 24)
                {
                    resourceRva = BinaryPrimitives.ReadUInt32LittleEndian(optional[(dirBase + 16)..]);
                    resourceSize = BinaryPrimitives.ReadUInt32LittleEndian(optional[(dirBase + 20)..]);
                }

                // Security (4) - note: this is a file offset, not RVA
                if (directoryCount > 4 && optional.Length >= dirBase + 40)
                {
                    securityOffset = BinaryPrimitives.ReadUInt32LittleEndian(optional[(dirBase + 32)..]);
                    securitySize = BinaryPrimitives.ReadUInt32LittleEndian(optional[(dirBase + 36)..]);
                }

                // Debug (6)
                if (directoryCount > 6 && optional.Length >= dirBase + 56)
                {
                    debugRva = BinaryPrimitives.ReadUInt32LittleEndian(optional[(dirBase + 48)..]);
                    debugSize = BinaryPrimitives.ReadUInt32LittleEndian(optional[(dirBase + 52)..]);
                }

                // LoadConfig (10)
                if (directoryCount > 10 && optional.Length >= dirBase + 88)
                {
                    loadConfigRva = BinaryPrimitives.ReadUInt32LittleEndian(optional[(dirBase + 80)..]);
                    loadConfigSize = BinaryPrimitives.ReadUInt32LittleEndian(optional[(dirBase + 84)..]);
                }

                // DelayImport (13)
                if (directoryCount > 13 && optional.Length >= dirBase + 112)
                {
                    delayImportRva = BinaryPrimitives.ReadUInt32LittleEndian(optional[(dirBase + 104)..]);
                    delayImportSize = BinaryPrimitives.ReadUInt32LittleEndian(optional[(dirBase + 108)..]);
                }
            }

            var info = new HPInfo
            {
                PeOffset = checked((int)peOffset),
                Architecture = GetArchitecture(machine),
                Machine = machine,
                OptionalHeaderMagic = magic,
                IsPE32Plus = isPe32Plus,
                FileCharacteristics = fileCharacteristics,
                DllCharacteristics = dllCharacteristics,
                HasASLR = (dllCharacteristics & DllDynamicBase) != 0,
                HasDEP = (dllCharacteristics & DllNxCompat) != 0,
                HasHighEntropyVA = (dllCharacteristics & DllHighEntropyVa) != 0,
                HasControlFlowGuard = (dllCharacteristics & DllGuardCf) != 0,
                SizeOfHeaders = sizeOfHeaders,
                NumberOfSections = sectionCount,
                SizeOfOptionalHeader = optionalHeaderSize,
                SectionOffset = checked((int)(optionalHeaderOffset + optionalHeaderSize)),

                // Extended fields
                Subsystem = subsystem,
                SubsystemName = GetSubsystemName(subsystem),
                AddressOfEntryPoint = addressOfEntryPoint,
                TimeDateStamp = timeDateStamp,
                CheckSum = checkSum,
                SizeOfImage = sizeOfImage,
                IsDll = (fileCharacteristics & ImageFileDll) != 0,

                // Data directories
                ExportDirectoryRVA = exportRva,
                ExportDirectorySize = exportSize,
                ImportDirectoryRVA = importRva,
                ImportDirectorySize = importSize,
                ResourceDirectoryRVA = resourceRva,
                ResourceDirectorySize = resourceSize,
                SecurityDirectoryFileOffset = securityOffset,
                SecurityDirectorySize = securitySize,
                LoadConfigDirectoryRVA = loadConfigRva,
                LoadConfigDirectorySize = loadConfigSize,
                DelayImportDirectoryRVA = delayImportRva,
                DelayImportDirectorySize = delayImportSize,
                DebugDirectoryRVA = debugRva,
                DebugDirectorySize = debugSize
            };
            return HPResult.Success(info);
        }
        catch (IOException exception)
        {
            return HPResult.Fail($"Unable to read the PE file: {exception.Message}");
        }
        catch (UnauthorizedAccessException exception)
        {
            return HPResult.Fail($"Unable to access the PE file: {exception.Message}");
        }
        catch (OverflowException)
        {
            return HPResult.Fail("A PE header offset exceeds the supported range.");
        }
    }

    private static string GetArchitecture(ushort machine) => machine switch
    {
        0x014C => "x86",
        0x8664 => "x64",
        0xAA64 => "ARM64",
        0x01C0 or 0x01C2 or 0x01C4 => "ARM",
        _ => $"Unknown (0x{machine:X4})"
    };

    private static string GetSubsystemName(ushort subsystem) => subsystem switch
    {
        0 => "Unknown",
        1 => "Native",
        2 => "GUI",
        3 => "Console",
        5 => "OS/2 Console",
        7 => "POSIX Console",
        9 => "Windows CE",
        10 => "EFI Application",
        11 => "EFI Boot Service Driver",
        12 => "EFI Runtime Driver",
        13 => "EFI ROM",
        14 => "XBOX",
        16 => "Windows Boot Application",
        _ => $"Unknown ({subsystem})"
    };

    internal static bool IsRangeWithinFile(long offset, long length, long fileLength) =>
        offset >= 0 && length >= 0 && offset <= fileLength && length <= fileLength - offset;

    internal static void ReadExactlyAt(FileStream file, long offset, Span<byte> destination)
    {
        if (!IsRangeWithinFile(offset, destination.Length, file.Length))
            throw new EndOfStreamException("A PE structure extends past the end of the file.");
        file.Position = offset;
        file.ReadExactly(destination);
    }
}
