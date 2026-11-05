using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using Scanner.Desktop.Models;
using Scanner.Desktop.Services;

namespace Scanner.Desktop.ViewModels;

public partial class MainViewModel : ObservableObject
{
    private readonly IScannerApiClient _apiClient;

    [ObservableProperty]
    private bool _isScanning;

    [ObservableProperty]
    private string _statusMessage = "Ready";

    [ObservableProperty]
    private bool _isServerConnected;

    [ObservableProperty]
    private ScanResult? _currentScanResult;

    [ObservableProperty]
    private ArchiveScanResult? _currentArchiveResult;

    [ObservableProperty]
    private int _selectedTabIndex;

    public ObservableCollection<ScanResult> ScanHistory { get; } = new();

    public MainViewModel(IScannerApiClient apiClient)
    {
        _apiClient = apiClient;
        _ = CheckServerConnectionAsync();
    }

    [RelayCommand]
    private async Task SelectAndScanFileAsync()
    {
        var dialog = new OpenFileDialog
        {
            Title = "Select file to scan",
            Filter = "Executable Files (*.exe;*.dll;*.sys)|*.exe;*.dll;*.sys|All Files (*.*)|*.*"
        };

        if (dialog.ShowDialog() == true)
        {
            await ScanFileAsync(dialog.FileName);
        }
    }

    [RelayCommand]
    private async Task SelectAndScanArchiveAsync()
    {
        var dialog = new OpenFileDialog
        {
            Title = "Select archive to scan",
            Filter = "ZIP Archives (*.zip)|*.zip|All Files (*.*)|*.*"
        };

        if (dialog.ShowDialog() == true)
        {
            await ScanArchiveAsync(dialog.FileName);
        }
    }

    public async Task ScanFileAsync(string filePath)
    {
        if (IsScanning) return;

        try
        {
            IsScanning = true;
            StatusMessage = $"Scanning {Path.GetFileName(filePath)}...";
            CurrentScanResult = null;

            var result = await _apiClient.ScanFileAsync(filePath);

            if (result != null)
            {
                CurrentScanResult = result;
                ScanHistory.Insert(0, result);
                StatusMessage = $"Scan completed: {result.RiskLevel} risk";
            }
            else
            {
                StatusMessage = "Scan failed: No result returned";
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
            MessageBox.Show($"Scan failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            IsScanning = false;
        }
    }

    public async Task ScanArchiveAsync(string archivePath)
    {
        if (IsScanning) return;

        try
        {
            IsScanning = true;
            StatusMessage = $"Scanning archive {Path.GetFileName(archivePath)}...";
            CurrentArchiveResult = null;

            var result = await _apiClient.ScanArchiveAsync(archivePath);

            if (result != null)
            {
                CurrentArchiveResult = result;
                StatusMessage = $"Archive scan completed: {result.ScannedFiles} files scanned";
            }
            else
            {
                StatusMessage = "Archive scan failed: No result returned";
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
            MessageBox.Show($"Archive scan failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            IsScanning = false;
        }
    }

    [RelayCommand]
    private async Task CheckServerConnectionAsync()
    {
        try
        {
            IsServerConnected = await _apiClient.CheckHealthAsync();
            StatusMessage = IsServerConnected
                ? "Connected to server"
                : "Server not responding. Please start the Server project.";
        }
        catch
        {
            IsServerConnected = false;
            StatusMessage = "Cannot connect to server";
        }
    }

    [RelayCommand]
    private void ClearHistory()
    {
        ScanHistory.Clear();
        CurrentScanResult = null;
        CurrentArchiveResult = null;
        StatusMessage = "History cleared";
    }
}
