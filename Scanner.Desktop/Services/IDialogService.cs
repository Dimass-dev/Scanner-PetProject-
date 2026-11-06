namespace Scanner.Desktop.Services;

/// <summary>Dialogs shown by view models, abstracted for testability.</summary>
public interface IDialogService
{
    void ShowError(string message, string title = "Error");

    void ShowInformation(string message, string title = "Information");
}
