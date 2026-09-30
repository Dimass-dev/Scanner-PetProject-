namespace Core.Models;
public class ImportedParser

{
    public List<ImportedDLL> ParserImportedDLL(string filePath,uint importedRVA,List<SingleSectionInfo> sections,string architecture)
    {
        uint rawOffset = RVAConverter.ConvertRVAtoRawOffset(importedRVA,sections);
        if(rawOffset == 0)
        {
            throw new Exception("RVA to Raw Offset conversion failed.");
        }
        using var file = new FileStream(filePath, FileMode.Open, FileAccess.Read);
        file.Seek(rawOffset, SeekOrigin.Begin);
        var importedDLLs = new List<ImportedDLL>();
        while (true)
        {
            byte[] buffer = new byte[20];
            int bytestoRead = file.Read(buffer,0,20);
            if(bytestoRead < 20)
            {
                break;
            }
            uint OriginalFirstThunk = BitConverter.ToUInt32(buffer, 0);
            uint nameRVA = BitConverter.ToUInt32(buffer, 12);
            uint firstThunk = BitConverter.ToUInt32(buffer, 16);
            if(nameRVA == 0 && firstThunk == 0)
            {
                break;
            }
            var importedDLL = new ImportedDLL
            {
                NameRVA = nameRVA,
                OriginalFirstThunk = OriginalFirstThunk,
                FirstThunk = firstThunk
            };
            importedDLLs.Add(importedDLL);
        }
        foreach (var dll in importedDLLs)
        {

            uint nameRawOffset = RVAConverter.ConvertRVAtoRawOffset(dll.NameRVA, sections);
            if(nameRawOffset == 0)
            {
                throw new Exception("RVA to Raw Offset conversion failed.");
            }
            file.Seek(nameRawOffset, SeekOrigin.Begin);
            var nameBytes = new List<byte>();
            while (true)
            {
                int b = file.ReadByte();
                if(b == -1 || b == 0)
                {
                    break;
                }
                nameBytes.Add((byte)b);
            }
            dll.DLLName = System.Text.Encoding.ASCII.GetString(nameBytes.ToArray());
        }
        return importedDLLs;
    }
}