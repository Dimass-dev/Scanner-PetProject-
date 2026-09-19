namespace Core.Models;
public class HPInfo
{
    public string Architecture {get; set;} = "Uknown";
    public int PeOffset {get; init;}
    public bool HasASLR {get; init;}
    public bool HasDEP {get; init;}
    public uint NumberOfSections{get;init;}
    public uint SizeOfOptionalHeader{get;init;}
    public int SectionOffset{get;init;}
    public uint ImportDirectoryRVA{get;init;}
    public uint ImportDirectorySize{get;init;}
}