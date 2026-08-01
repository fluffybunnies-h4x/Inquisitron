using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace Inquisitron.Models;

/// <summary>A process in the live tree, keyed by Sysmon ProcessGuid.</summary>
public sealed class ProcessNode : INotifyPropertyChanged
{
    private string _image = "";
    private string _commandLine = "";
    private string _pid = "";
    private bool _exited;
    private bool _isPlaceholder;
    private string _suspicionReason = "";
    private string _severity = "";
    private bool _isExpanded = true;

    public string Guid { get; init; } = "";
    public string ParentGuid { get; set; } = "";
    public DateTime? StartTime { get; set; }
    public ObservableCollection<ProcessNode> Children { get; } = new();

    public string Image
    {
        get => _image;
        set { if (Set(ref _image, value)) OnPropertyChanged(nameof(Name)); }
    }

    public string CommandLine { get => _commandLine; set => Set(ref _commandLine, value); }
    public string Pid { get => _pid; set { if (Set(ref _pid, value)) OnPropertyChanged(nameof(PidText)); } }
    public bool Exited { get => _exited; set => Set(ref _exited, value); }

    /// <summary>True when we only know this process from a child's ParentImage field.</summary>
    public bool IsPlaceholder
    {
        get => _isPlaceholder;
        set { if (Set(ref _isPlaceholder, value)) OnPropertyChanged(nameof(Name)); }
    }

    public string SuspicionReason
    {
        get => _suspicionReason;
        set { if (Set(ref _suspicionReason, value)) { OnPropertyChanged(nameof(IsSuspicious)); OnPropertyChanged(nameof(Flag)); } }
    }

    /// <summary>Critical / High / Medium / Low, or "" if clean.</summary>
    public string Severity
    {
        get => _severity;
        set { if (Set(ref _severity, value)) OnPropertyChanged(nameof(Flag)); }
    }

    public bool IsSuspicious => _suspicionReason.Length > 0;

    public string Flag => _severity switch
    {
        "Critical" => "⛔ ",
        "High" => "⚠ ",
        "Medium" => "▲ ",
        "Low" => "• ",
        _ => IsSuspicious ? "⚠ " : "",
    };
    public bool IsExpanded { get => _isExpanded; set => Set(ref _isExpanded, value); }

    public string Name
    {
        get
        {
            var idx = _image.LastIndexOf('\\');
            var name = idx >= 0 ? _image[(idx + 1)..] : _image;
            if (name.Length == 0) name = "(unknown)";
            return IsPlaceholder ? $"{name} (not observed)" : name;
        }
    }

    public string PidText => _pid.Length > 0 ? $"PID {_pid}" : "";

    public event PropertyChangedEventHandler? PropertyChanged;

    private bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        OnPropertyChanged(name);
        return true;
    }

    private void OnPropertyChanged(string? name) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
