namespace Core.Models;

/// <summary>Validated PE/COFF header values needed by the analysis pipeline.</summary>
public sealed class HPInfo
{
    public string Architecture { get; init; } = "Unknown";
    public ushort Machine { get; init; }
    public ushort OptionalHeaderMagic { get; init; }
    public bool IsPE32Plus { get; init; }
    public ushort FileCharacteristics { get; init; }
    public ushort DllCharacteristics { get; init; }
    public bool HasASLR { get; init; }
    public bool HasDEP { get; init; }
    public bool HasHighEntropyVA { get; init; }
    public bool HasControlFlowGuard { get; init; }
    public uint SizeOfHeaders { get; init; }
    public int PeOffset { get; init; }
    public int NumberOfSections { get; init; }
    public int SizeOfOptionalHeader { get; init; }
    public int SectionOffset { get; init; }
    public uint ImportDirectoryRVA { get; init; }
    public uint ImportDirectorySize { get; init; }

    // Extended fields for Phase 1
    public ushort Subsystem { get; init; }
    public string SubsystemName { get; init; } = "Unknown";
    public uint AddressOfEntryPoint { get; init; }
    public uint TimeDateStamp { get; init; }
    public uint CheckSum { get; init; }
    public uint SizeOfImage { get; init; }
    public bool IsDll { get; init; }

    // Data directories
    public uint ExportDirectoryRVA { get; init; }
    public uint ExportDirectorySize { get; init; }
    public uint ResourceDirectoryRVA { get; init; }
    public uint ResourceDirectorySize { get; init; }
    public uint SecurityDirectoryFileOffset { get; init; }
    public uint SecurityDirectorySize { get; init; }
    public uint LoadConfigDirectoryRVA { get; init; }
    public uint LoadConfigDirectorySize { get; init; }
    public uint DelayImportDirectoryRVA { get; init; }
    public uint DelayImportDirectorySize { get; init; }
    public uint DebugDirectoryRVA { get; init; }
    public uint DebugDirectorySize { get; init; }
}
