using System.Collections.ObjectModel;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using Scanner.Desktop.Models;
using Scanner.Desktop.Services;

namespace Scanner.Desktop.ViewModels;

public partial class MainViewModel : ObservableObject
{
    private const int MaxHistoryEntries = 20;

    private readonly IScannerApiClient _apiClient;
    private readonly IDialogService _dialogService;
    private CancellationTokenSource? _scanCts;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CancelScanCommand))]
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

    public MainViewModel(IScannerApiClient apiClient, IDialogService dialogService)
    {
        _apiClient = apiClient;
        _dialogService = dialogService;
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

    [RelayCommand(CanExecute = nameof(IsScanning))]
    private void CancelScan()
    {
        _scanCts?.Cancel();
    }

    public async Task ScanFileAsync(string filePath)
    {
        if (IsScanning)
        {
            return;
        }

        using var cts = new CancellationTokenSource();
        _scanCts = cts;

        try
        {
            IsScanning = true;
            StatusMessage = $"Scanning {Path.GetFileName(filePath)}...";
            CurrentScanResult = null;

            var result = await _apiClient.ScanFileAsync(filePath, cts.Token);

            if (result != null)
            {
                CurrentScanResult = result;
                ScanHistory.Insert(0, result);
                TrimHistory();
                StatusMessage = $"Scan completed: {result.RiskLevel} risk";
            }
            else
            {
                StatusMessage = "Scan failed: No result returned";
            }
        }
        catch (OperationCanceledException) when (cts.IsCancellationRequested)
        {
            StatusMessage = "Scan cancelled";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
            _dialogService.ShowError($"Scan failed: {ex.Message}");
        }
        finally
        {
            IsScanning = false;
            _scanCts = null;
        }
    }

    public async Task ScanArchiveAsync(string archivePath)
    {
        if (IsScanning)
        {
            return;
        }

        using var cts = new CancellationTokenSource();
        _scanCts = cts;

        try
        {
            IsScanning = true;
            StatusMessage = $"Scanning archive {Path.GetFileName(archivePath)}...";
            CurrentArchiveResult = null;

            var result = await _apiClient.ScanArchiveAsync(archivePath, cts.Token);

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
        catch (OperationCanceledException) when (cts.IsCancellationRequested)
        {
            StatusMessage = "Archive scan cancelled";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
            _dialogService.ShowError($"Archive scan failed: {ex.Message}");
        }
        finally
        {
            IsScanning = false;
            _scanCts = null;
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

    private void TrimHistory()
    {
        while (ScanHistory.Count > MaxHistoryEntries)
        {
            ScanHistory.RemoveAt(ScanHistory.Count - 1);
        }
    }
}
