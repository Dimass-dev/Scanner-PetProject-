using System.Windows;
using Scanner.Desktop.ViewModels;

namespace Scanner.Desktop;

public partial class MainWindow : Window
{
    private MainViewModel ViewModel => (MainViewModel)DataContext;

    public MainWindow()
    {
        InitializeComponent();
    }

    private async void Window_Drop(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(DataFormats.FileDrop))
        {
            string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
            if (files.Length > 0)
            {
                string file = files[0];
                string extension = System.IO.Path.GetExtension(file).ToLowerInvariant();

                if (extension == ".zip")
                {
                    await ViewModel.ScanArchiveAsync(file);
                }
                else if (extension == ".exe" || extension == ".dll" || extension == ".sys")
                {
                    await ViewModel.ScanFileAsync(file);
                }
                else
                {
                    MessageBox.Show("Unsupported file type. Please drop .exe, .dll, .sys, or .zip files.",
                        "Invalid File", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
        }
    }

    private async void FileDropZone_Drop(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(DataFormats.FileDrop))
        {
            string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
            if (files.Length > 0)
            {
                await ViewModel.ScanFileAsync(files[0]);
            }
        }
    }

    private async void ArchiveDropZone_Drop(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(DataFormats.FileDrop))
        {
            string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
            if (files.Length > 0)
            {
                await ViewModel.ScanArchiveAsync(files[0]);
            }
        }
    }

    private void FileDropZone_DragOver(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(DataFormats.FileDrop))
        {
            e.Effects = DragDropEffects.Copy;
        }
        else
        {
            e.Effects = DragDropEffects.None;
        }
        e.Handled = true;
    }
}
