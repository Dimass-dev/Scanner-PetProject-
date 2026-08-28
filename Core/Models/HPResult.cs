namespace Core.Models;
public class HPResult
{
    public bool IsSuccess {get; init; }
    public string? ErrorMessage{get; init; }
    public int PeOffset {get; init; }
    private HPResult(){}
    public static HPResult Success (int offset) => new() {IsSuccess = true,PeOffset = offset};
    public static HPResult Fail(string error) => new(){IsSuccess = false,ErrorMessage = error};
}