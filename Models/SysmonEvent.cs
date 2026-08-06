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

    /// <summary>Channel this event came from, e.g. "Microsoft-Windows-Sysmon/Operational".</summary>
    public string Channel { get; init; } = "";

    /// <summary>Short channel label for the grid column ("Sysmon", "Security", …).</summary>
    public string ChannelName => ShortChannelName(Channel);

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

    /// <summary>Hunting-relevant Security channel events.</summary>
    private static readonly Dictionary<int, string> SecurityEventNames = new()
    {
        [1102] = "Audit Log Cleared",
        [4624] = "Logon",
        [4625] = "Logon Failed",
        [4634] = "Logoff",
        [4648] = "Logon With Explicit Credentials",
        [4672] = "Special Privileges Assigned",
        [4688] = "Process Create",
        [4689] = "Process Exit",
        [4697] = "Service Installed",
        [4698] = "Scheduled Task Created",
        [4699] = "Scheduled Task Deleted",
        [4702] = "Scheduled Task Updated",
        [4720] = "User Account Created",
        [4726] = "User Account Deleted",
        [4728] = "Member Added To Global Group",
        [4732] = "Member Added To Local Group",
        [4756] = "Member Added To Universal Group",
        [4768] = "Kerberos TGT Requested",
        [4769] = "Kerberos Service Ticket Requested",
        [4776] = "NTLM Authentication",
        [5140] = "Network Share Accessed",
        [5145] = "Network Share Access Checked",
    };

    /// <summary>Microsoft-Windows-PowerShell/Operational.</summary>
    private static readonly Dictionary<int, string> PowerShellOperationalNames = new()
    {
        [4100] = "Engine Error",
        [4103] = "Module Logging (Pipeline)",
        [4104] = "Script Block Logging",
        [4105] = "Script Start",
        [4106] = "Script Stop",
    };

    /// <summary>The classic "Windows PowerShell" log.</summary>
    private static readonly Dictionary<int, string> PowerShellClassicNames = new()
    {
        [400] = "Engine State Changed To Available",
        [403] = "Engine State Changed To Stopped",
        [500] = "Command Started",
        [501] = "Command Stopped",
        [600] = "Provider Lifecycle",
        [800] = "Pipeline Execution Details",
    };

    /// <summary>System channel — service control and event log lifecycle.</summary>
    private static readonly Dictionary<int, string> SystemEventNames = new()
    {
        [41] = "Kernel Power (Unexpected Restart)",
        [104] = "Event Log Cleared",
        [1074] = "Shutdown Initiated",
        [6005] = "Event Log Service Started",
        [6006] = "Event Log Service Stopped",
        [6008] = "Unexpected Shutdown",
        [7034] = "Service Terminated Unexpectedly",
        [7036] = "Service State Changed",
        [7040] = "Service Start Type Changed",
        [7045] = "Service Installed",
    };

    /// <summary>Microsoft-Windows-Windows Defender/Operational.</summary>
    private static readonly Dictionary<int, string> DefenderEventNames = new()
    {
        [1006] = "Malware Detected",
        [1007] = "Action Taken On Malware",
        [1008] = "Action On Malware Failed",
        [1015] = "Suspicious Behavior Detected",
        [1116] = "Malware Detected",
        [1117] = "Action Taken On Malware",
        [1118] = "Action On Malware Failed",
        [1119] = "Critical Action Failure",
        [5001] = "Realtime Protection Disabled",
        [5004] = "Realtime Protection Configuration Changed",
        [5007] = "Defender Configuration Changed",
        [5010] = "Malware Scanning Disabled",
        [5012] = "Virus Scanning Disabled",
    };

    /// <summary>Microsoft-Windows-TaskScheduler/Operational.</summary>
    private static readonly Dictionary<int, string> TaskSchedulerEventNames = new()
    {
        [100] = "Task Started",
        [102] = "Task Completed",
        [106] = "Task Registered",
        [129] = "Task Created Process",
        [140] = "Task Updated",
        [141] = "Task Deleted",
        [200] = "Action Started",
        [201] = "Action Completed",
    };

    /// <summary>Microsoft-Windows-WMI-Activity/Operational.</summary>
    private static readonly Dictionary<int, string> WmiActivityEventNames = new()
    {
        [5857] = "Provider Started",
        [5858] = "Query Error",
        [5859] = "ESS Operation",
        [5860] = "Temporary Event Subscription",
        [5861] = "Permanent Event Subscription",
    };

    /// <summary>
    /// Channel matchers, most specific first. Event IDs are only meaningful
    /// relative to their channel — Sysmon 7 is "Image Loaded" while System 7 is
    /// a disk driver event — so naming must never be done on the ID alone.
    /// </summary>
    private static readonly (string Match, string Short, Dictionary<int, string> Names)[] ChannelTables =
    {
        ("sysmon",                 "Sysmon",        (Dictionary<int, string>)SysmonEventNames),
        ("windows defender",       "Defender",      DefenderEventNames),
        ("powershell/operational", "PowerShell",    PowerShellOperationalNames),
        ("windows powershell",     "PowerShell",    PowerShellClassicNames),
        ("taskscheduler",          "TaskSched",     TaskSchedulerEventNames),
        ("wmi-activity",           "WMI",           WmiActivityEventNames),
        ("security",               "Security",      SecurityEventNames),
        ("system",                 "System",        SystemEventNames),
    };

    /// <summary>Short label for the Channel column; falls back to the leaf of the channel path.</summary>
    public static string ShortChannelName(string channel)
    {
        if (channel.Length == 0) return "";
        foreach (var (match, shortName, _) in ChannelTables)
        {
            if (channel.Contains(match, StringComparison.OrdinalIgnoreCase)) return shortName;
        }
        // "Microsoft-Windows-Foo/Operational" -> "Foo"
        var trimmed = channel;
        var slash = trimmed.IndexOf('/');
        if (slash > 0) trimmed = trimmed[..slash];
        const string prefix = "Microsoft-Windows-";
        if (trimmed.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) trimmed = trimmed[prefix.Length..];
        return trimmed;
    }

    /// <summary>Sysmon-relative name. Prefer the channel-aware overload.</summary>
    public static string NameForEventId(int id) =>
        SysmonEventNames.TryGetValue(id, out var name) ? name : $"Event {id}";

    /// <summary>
    /// Friendly name for an event ID *within its channel*. Unknown combinations
    /// return "Event {id}" rather than borrowing another channel's meaning —
    /// an honestly unnamed row beats a confidently mislabeled one.
    /// </summary>
    public static string NameForEventId(string channel, int id)
    {
        foreach (var (match, _, names) in ChannelTables)
        {
            if (!channel.Contains(match, StringComparison.OrdinalIgnoreCase)) continue;
            return names.TryGetValue(id, out var name) ? name : $"Event {id}";
        }
        return $"Event {id}";
    }

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
