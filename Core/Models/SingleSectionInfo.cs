namespace Core.Models;
public class SingleSectionInfo
{
    public string SectionName{get;init;} = "";
    public uint VirtualSize{get;init;}
    public uint VirtualAddress{get;init;}
    public uint SizeOfRawData{get;init;}
    public uint PointerToRawData{get;init;}
    public uint Characteristics{get;init;}
}