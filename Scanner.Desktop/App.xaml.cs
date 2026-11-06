using System.IO;
using System.Windows;
using System.Windows.Threading;
using Microsoft.Extensions.DependencyInjection;
using Scanner.Desktop.Services;
using Scanner.Desktop.ViewModels;

namespace Scanner.Desktop;

public partial class App : Application
{
    private ServiceProvider? _serviceProvider;

    public App()
    {
        DispatcherUnhandledException += OnDispatcherUnhandledException;
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var services = new ServiceCollection();
        ConfigureServices(services);
        _serviceProvider = services.BuildServiceProvider();

        var mainWindow = _serviceProvider.GetRequiredService<MainWindow>();
        mainWindow.DataContext = _serviceProvider.GetRequiredService<MainViewModel>();
        mainWindow.Show();
    }

    private void ConfigureServices(IServiceCollection services)
    {
        services.AddSingleton(DesktopSettings.Load());
        services.AddSingleton<IDialogService, DialogService>();
        services.AddHttpClient<IScannerApiClient, ScannerApiClient>();
        services.AddSingleton<MainViewModel>();
        services.AddTransient<MainWindow>();
    }

    private static void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        try
        {
            string logPath = Path.Combine(Path.GetTempPath(), "scanner-desktop-errors.log");
            File.AppendAllText(
                logPath,
                $"[{DateTime.Now:O}] {e.Exception}{Environment.NewLine}{Environment.NewLine}");
        }
        catch
        {
            // Logging must never take down the UI thread.
        }

        MessageBox.Show(
            $"Unexpected UI error:\n{e.Exception.Message}",
            "Security Scanner",
            MessageBoxButton.OK,
            MessageBoxImage.Error);
        e.Handled = true;
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _serviceProvider?.Dispose();
        base.OnExit(e);
    }
}
