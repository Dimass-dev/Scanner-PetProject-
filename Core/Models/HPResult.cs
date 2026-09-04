namespace Core.Models;
using Core.Models;
public class HPResult
{
    public bool IsSuccess {get; init; }
    public string? ErrorMessage{get; init; }
    public HPInfo? Info {get; init;}
    private HPResult(){}
    public static HPResult Success (HPInfo info) => new(){IsSuccess = true,Info = info};
    public static HPResult Fail(string error) => new(){IsSuccess = false,ErrorMessage = error};
}