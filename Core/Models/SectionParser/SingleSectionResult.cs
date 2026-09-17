namespace Core.Models;
public class SingleSectionResult
{
    public string? ErrorMessage {get;init;}
    public bool IsSuccess {get;init;}
    public List<SingleSectionInfo>? SectionInfo {get;init;}
    private SingleSectionResult(){}
    public static SingleSectionResult Success (List<SingleSectionInfo> info) => new(){IsSuccess = true,SectionInfo = info};
    public static SingleSectionResult Fail(string error) => new(){IsSuccess = false,ErrorMessage = error};
}