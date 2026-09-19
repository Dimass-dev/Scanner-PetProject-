namespace Core.Models;
public static class RVAConverter
{
    public static uint ConvertRVAtoRawOffset(uint rvaOffset,List<SingleSectionInfo> sections)
    {
        foreach(var section in sections)
        {
            if(rvaOffset >= section.VirtualAddress && rvaOffset < section.VirtualAddress + section.VirtualSize)
            {
                uint rawOffset = rvaOffset - section.VirtualAddress + section.PointerToRawData;
                return rawOffset;   
            }
        }
        return 0;
    }
}