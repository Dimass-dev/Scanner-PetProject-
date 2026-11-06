using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Scanner.Desktop.ViewModels;

namespace Scanner.Desktop;

public partial class MainWindow : Window
{
    private static readonly HashSet<string> PeExtensions =
        new(StringComparer.OrdinalIgnoreCase) { ".exe", ".dll", ".sys" };

    private static readonly Brush DropZoneBorder = new SolidColorBrush(Color.FromRgb(0xBD, 0xBD, 0xBD));
    private static readonly Brush DropZoneBackground = new SolidColorBrush(Color.FromRgb(0xFA, 0xFA, 0xFA));
    private static readonly Brush ActiveDropZoneBorder = new SolidColorBrush(Color.FromRgb(0x21, 0x96, 0xF3));
    private static readonly Brush ActiveDropZoneBackground = new SolidColorBrush(Color.FromRgb(0xE3, 0xF2, 0xFD));

    private MainViewModel? ViewModel => DataContext as MainViewModel;

    public MainWindow()
    {
        InitializeComponent();
    }

    private async void Window_Drop(object sender, DragEventArgs e)
    {
        ResetDropZone(PeDropZone);
        ResetDropZone(ArchiveDropZone);
        await HandleDropAsync(e, DropTarget.Any);
    }

    private async void FileDropZone_Drop(object sender, DragEventArgs e)
    {
        ResetDropZone(PeDropZone);
        await HandleDropAsync(e, DropTarget.PeFile);
    }

    private async void ArchiveDropZone_Drop(object sender, DragEventArgs e)
    {
        ResetDropZone(ArchiveDropZone);
        await HandleDropAsync(e, DropTarget.Archive);
    }

    private void FileDropZone_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop)
            ? DragDropEffects.Copy
            : DragDropEffects.None;
        e.Handled = true;
    }

    private void DropZone_DragEnter(object sender, DragEventArgs e)
    {
        bool hasFiles = e.Data.GetDataPresent(DataFormats.FileDrop);
        e.Effects = hasFiles ? DragDropEffects.Copy : DragDropEffects.None;
        SetDropZoneState(sender as Border, hasFiles);
        e.Handled = true;
    }

    private void DropZone_DragLeave(object sender, DragEventArgs e)
    {
        SetDropZoneState(sender as Border, false);
        e.Handled = true;
    }

    private static void ResetDropZone(Border? zone) => SetDropZoneState(zone, false);

    private static void SetDropZoneState(Border? zone, bool isActive)
    {
        if (zone is null)
        {
            return;
        }

        zone.BorderBrush = isActive ? ActiveDropZoneBorder : DropZoneBorder;
        zone.Background = isActive ? ActiveDropZoneBackground : DropZoneBackground;
    }

    private async Task HandleDropAsync(DragEventArgs e, DropTarget target)
    {
        e.Handled = true;

        try
        {
            if (!e.Data.GetDataPresent(DataFormats.FileDrop) ||
                e.Data.GetData(DataFormats.FileDrop) is not string[] { Length: > 0 } files)
            {
                return;
            }

            string file = files[0];
            if (!File.Exists(file))
            {
                ShowMessage("The dropped file no longer exists.", "File not found", MessageBoxImage.Warning);
                return;
            }

            if (ViewModel is not MainViewModel viewModel)
            {
                ShowMessage(
                    "The application is still starting. Please try again.",
                    "Not ready",
                    MessageBoxImage.Warning);
                return;
            }

            string extension = Path.GetExtension(file);

            if (target == DropTarget.Archive)
            {
                if (!IsZip(extension))
                {
                    ShowMessage(
                        "This drop zone accepts only .zip archives.",
                        "Unsupported file type",
                        MessageBoxImage.Warning);
                    return;
                }

                await viewModel.ScanArchiveAsync(file);
                return;
            }

            if (IsZip(extension))
            {
                await viewModel.ScanArchiveAsync(file);
                return;
            }

            if (!PeExtensions.Contains(extension))
            {
                ShowMessage(
                    "Unsupported file type. Please drop .exe, .dll, .sys, or .zip files.",
                    "Unsupported file type",
                    MessageBoxImage.Warning);
                return;
            }

            await viewModel.ScanFileAsync(file);
        }
        catch (Exception ex)
        {
            ShowMessage($"Could not process the dropped file:\n{ex.Message}", "Drop failed", MessageBoxImage.Error);
        }
    }

    private static bool IsZip(string extension) =>
        extension.Equals(".zip", StringComparison.OrdinalIgnoreCase);

    private static void ShowMessage(string text, string caption, MessageBoxImage image)
    {
        MessageBox.Show(text, caption, MessageBoxButton.OK, image);
    }

    private enum DropTarget
    {
        Any,
        PeFile,
        Archive
    }
}
