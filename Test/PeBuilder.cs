using System.Buffers.Binary;
using System.Text;

namespace Scanner.Tests;

/// <summary>Builds small synthetic PE images so parser tests do not depend on the host OS.</summary>
internal static class PeBuilder
{
    public const int PeOffset = 0x40;
    public const int SectionOffset = 0x148;
    public const int RawSectionOffset = 0x200;
    public const int FileSize = 0x400;

    public static byte[] CreatePe64(
        ushort dllCharacteristics = 0x0160,
        uint sectionCharacteristics = 0x60000020,
        string sectionName = ".text")
    {
        byte[] file = new byte[FileSize];

        "MZ"u8.CopyTo(file);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(0x3C, 4), PeOffset);

        "PE\0\0"u8.CopyTo(file.AsSpan(PeOffset));

        int coffOffset = PeOffset + 4;
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(coffOffset, 2), 0x8664);
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(coffOffset + 2, 2), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(coffOffset + 4, 4), 0x60000000);
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(coffOffset + 16, 2), 240);
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(coffOffset + 18, 2), 0x0022);

        int optionalOffset = coffOffset + 20;
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(optionalOffset, 2), 0x20B);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(optionalOffset + 16, 4), 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(optionalOffset + 20, 4), 0x1000);
        BinaryPrimitives.WriteUInt64LittleEndian(file.AsSpan(optionalOffset + 24, 8), 0x140000000);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(optionalOffset + 32, 4), 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(optionalOffset + 36, 4), 0x200);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(optionalOffset + 56, 4), 0x2000);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(optionalOffset + 60, 4), 0x200);
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(optionalOffset + 68, 2), 3);
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(optionalOffset + 70, 2), dllCharacteristics);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(optionalOffset + 108, 4), 16);

        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(SectionOffset + 8, 4), 0x200);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(SectionOffset + 12, 4), 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(SectionOffset + 16, 4), 0x200);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(SectionOffset + 20, 4), RawSectionOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(SectionOffset + 36, 4), sectionCharacteristics);

        Encoding.ASCII.GetBytes(sectionName.PadRight(8, '\0')[..8]).CopyTo(file.AsSpan(SectionOffset));
        file.AsSpan(RawSectionOffset, 0x200).Fill(0x90);

        return file;
    }

    public static string WriteTemporaryPeFile(byte[]? content = null)
    {
        string path = Path.Combine(Path.GetTempPath(), $"scanner-test-{Guid.NewGuid():N}.exe");
        File.WriteAllBytes(path, content ?? CreatePe64());
        return path;
    }
}
