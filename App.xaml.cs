using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace Inquisitron;

/// <summary>
/// Interaction logic for App.xaml.
///
/// Startup failures in a WPF app are otherwise silent — the process exits with
/// no window and no message. These handlers write the exception to
/// %TEMP%\Inquisitron-crash.log and show it, so a failure at a demo station is
/// diagnosable on the spot instead of a mystery.
/// </summary>
public partial class App : Application
{
    private static readonly string CrashLog =
        Path.Combine(Path.GetTempPath(), "Inquisitron-crash.log");

    public App()
    {
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            Report(e.ExceptionObject as Exception, "AppDomain", fatal: true);
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        // Registered before base.OnStartup so a MainWindow constructor failure
        // (StartupUri creates it inside that call) is still caught.
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        base.OnStartup(e);
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        Report(e.Exception, "Dispatcher", fatal: false);
        e.Handled = true; // keep the app alive if the UI thread can recover
    }

    private static void Report(Exception? ex, string source, bool fatal)
    {
        if (ex is null) return;

        var text = $"""
            === Inquisitron crash ===
            Time:   {DateTime.Now:yyyy-MM-dd HH:mm:ss}
            Source: {source}
            Type:   {ex.GetType().FullName}

            {ex}
            """;

        try
        {
            File.AppendAllText(CrashLog, text + Environment.NewLine + Environment.NewLine);
        }
        catch
        {
            // A logging failure must never mask the original exception.
        }

        try
        {
            MessageBox.Show(
                $"{ex.GetType().Name}: {ex.Message}\n\nFull details written to:\n{CrashLog}",
                fatal ? "Inquisitron — fatal error" : "Inquisitron — error",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        catch
        {
            // No UI available (very early startup) — the log file still has it.
        }
    }
}
