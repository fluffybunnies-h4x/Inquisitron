using System.Collections.Generic;
using System.ComponentModel;

namespace Inquisitron.Models;

/// <summary>
/// A parsed event from the Sysmon Operational channel (or any other event channel).
/// Immutable except for SuspicionReason, which can be rewritten when the
/// suspicion rules are reloaded and re-applied to already-captured events.
/// </summary>
public sealed class SysmonEvent : INotifyPropertyChanged
{
    public long RecordId { get; init; }
    public DateTime TimeCreated { get; init; }
    public int EventId { get; init; }
    public string TaskName { get; init; } = "";
    public string Summary { get; init; } = "";
    public string RawXml { get; init; } = "";

    /// <summary>ProcessId field, or "" when the event type doesn't carry one.</summary>
    public string Pid { get; init; } = "";

    /// <summary>ParentProcessId field (Event ID 1 only), or "".</summary>
    public string ParentPid { get; init; } = "";

    public string ProcessGuid { get; init; } = "";
    public string ParentProcessGuid { get; init; } = "";
    public string ParentImage { get; init; } = "";

    private Services.RuleHit? _hit;

    /// <summary>The rule that flagged this event, or null if clean.</summary>
    public Services.RuleHit? Hit
    {
        get => _hit;
        set
        {
            if (_hit == value) return;
            _hit = value;
            foreach (var name in new[]
                     {
                         nameof(Hit), nameof(SuspicionReason), nameof(SuspicionRuleName),
                         nameof(SuspicionSeverity), nameof(IsSuspicious), nameof(Flag),
                     })
            {
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
            }
        }
    }

    /// <summary>Why this event was flagged, or "" if clean.</summary>
    public string SuspicionReason => _hit?.ToString() ?? "";

    /// <summary>Short name of the rule that fired, or "" if clean.</summary>
    public string SuspicionRuleName => _hit?.Name ?? "";

    /// <summary>Critical / High / Medium / Low, or "" if clean.</summary>
    public string SuspicionSeverity => _hit is null ? "" : _hit.Severity.ToString();

    public bool IsSuspicious => _hit is not null;

    public string Flag => _hit?.Severity switch
    {
        Services.Severity.Critical => "⛔",
        Services.Severity.High => "⚠",
        Services.Severity.Medium => "▲",
        Services.Severity.Low => "•",
        _ => "",
    };

    public event PropertyChangedEventHandler? PropertyChanged;

    /// <summary>Value of the named EventData field, or "" if absent.</summary>
    public string GetData(string name)
    {
        foreach (var kv in Data)
        {
            if (kv.Key == name) return kv.Value;
        }
        return "";
    }

    /// <summary>Name/value pairs from the EventData section, in original order.</summary>
    public IReadOnlyList<KeyValuePair<string, string>> Data { get; init; } =
        Array.Empty<KeyValuePair<string, string>>();

    /// <summary>Friendly names for Sysmon event IDs.</summary>
    public static readonly IReadOnlyDictionary<int, string> SysmonEventNames = new Dictionary<int, string>
    {
        [1] = "Process Create",
        [2] = "File Creation Time Changed",
        [3] = "Network Connection",
        [4] = "Sysmon Service State Changed",
        [5] = "Process Terminated",
        [6] = "Driver Loaded",
        [7] = "Image Loaded",
        [8] = "CreateRemoteThread",
        [9] = "RawAccessRead",
        [10] = "Process Access",
        [11] = "File Create",
        [12] = "Registry Object Create/Delete",
        [13] = "Registry Value Set",
        [14] = "Registry Key/Value Rename",
        [15] = "File Create Stream Hash",
        [16] = "Sysmon Config Change",
        [17] = "Pipe Created",
        [18] = "Pipe Connected",
        [19] = "WMI Event Filter",
        [20] = "WMI Event Consumer",
        [21] = "WMI Consumer To Filter",
        [22] = "DNS Query",
        [23] = "File Delete (Archived)",
        [24] = "Clipboard Change",
        [25] = "Process Tampering",
        [26] = "File Delete Detected",
        [27] = "File Block Executable",
        [28] = "File Block Shredding",
        [29] = "File Executable Detected",
        [255] = "Sysmon Error",
    };

    /// <summary>Fields that make the most useful one-line summary, tried in order.</summary>
    private static readonly string[] SummaryFields =
    {
        "CommandLine", "Image", "QueryName", "TargetFilename", "TargetObject",
        "DestinationIp", "ImageLoaded", "PipeName", "Details", "State",
    };

    public static string NameForEventId(int id) =>
        SysmonEventNames.TryGetValue(id, out var name) ? name : $"Event {id}";

    public static string BuildSummary(IReadOnlyList<KeyValuePair<string, string>> data)
    {
        foreach (var field in SummaryFields)
        {
            foreach (var kv in data)
            {
                if (kv.Key == field && !string.IsNullOrWhiteSpace(kv.Value) && kv.Value != "-")
                    return kv.Value;
            }
        }
        return data.Count > 0 ? data[0].Value : "";
    }

    /// <summary>The process image, if this event type carries one (most do).</summary>
    public string ProcessImage
    {
        get
        {
            foreach (var kv in Data)
            {
                if (kv.Key is "Image" or "SourceImage" && !string.IsNullOrEmpty(kv.Value))
                    return kv.Value;
            }
            return "";
        }
    }

    /// <summary>Just the executable name portion of <see cref="ProcessImage"/>.</summary>
    public string ProcessName
    {
        get
        {
            var image = ProcessImage;
            if (image.Length == 0) return "";
            var idx = image.LastIndexOf('\\');
            return idx >= 0 ? image[(idx + 1)..] : image;
        }
    }

    /// <summary>True if any field, the task name, or the XML contains the given text.</summary>
    public bool Matches(string needle)
    {
        if (TaskName.Contains(needle, StringComparison.OrdinalIgnoreCase)) return true;
        if (ProcessImage.Contains(needle, StringComparison.OrdinalIgnoreCase)) return true;
        foreach (var kv in Data)
        {
            if (kv.Value.Contains(needle, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }
}
