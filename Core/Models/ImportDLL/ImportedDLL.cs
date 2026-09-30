namespace Core.Models;
public class ImportedDLL
{
    public string DLLName { get; set; } = string.Empty;
    public uint OriginalFirstThunk { get; set; }
    public uint FirstThunk { get; set; }
    public uint NameRVA { get; set; }
    public List<string> ImportedFunctions { get; set; } = new List<string>();

}