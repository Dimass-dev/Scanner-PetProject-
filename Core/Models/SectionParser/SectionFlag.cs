namespace Core.Models;
[Flags]
public enum SectionFlag : uint
{
     ContentCode = 0x00000020,
     ContentInitializedData = 0x00000040,
     ContentUninitializedData = 0x00000080,
     MemDiscardable = 0x02000000,
     MemExecute = 0x20000000,
     MemRead = 0x40000000,
     MemWrite = 0x80000000
}
