using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Xml;
using Inquisitron.Models;

namespace Inquisitron.Services;

/// <summary>
/// Streams events from a Windows event channel: a one-time backfill of recent
/// history, then push-based real-time updates via <see cref="EventLogWatcher"/>.
/// Events are raised on threadpool threads — callers marshal to the UI thread.
/// </summary>
public sealed class EventLogService : IDisposable
{
    private readonly Dictionary<string, EventLogWatcher> _watchers =
        new(StringComparer.OrdinalIgnoreCase);

    public event Action<SysmonEvent>? EventArrived;
    public event Action<string>? Error;

    /// <summary>Channels currently subscribed, in the order they were started.</summary>
    public IReadOnlyCollection<string> Channels => _watchers.Keys.ToList();

    public bool IsRunning => _watchers.Count > 0;

    /// <summary>Returns true if the channel exists on this machine.</summary>
    public static bool ChannelExists(string channel)
    {
        try
        {
            using var session = new EventLogSession();
            var names = session.GetLogNames();
            foreach (var name in names)
            {
                if (string.Equals(name, channel, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Reads the most recent <paramref name="maxEvents"/> events from the channel.
    /// Throws UnauthorizedAccessException / EventLogException on access problems.
    /// </summary>
    public static List<SysmonEvent> ReadRecent(string channel, int maxEvents)
    {
        var query = new EventLogQuery(channel, PathType.LogName) { ReverseDirection = true };
        using var reader = new EventLogReader(query);

        var events = new List<SysmonEvent>(maxEvents);
        for (var i = 0; i < maxEvents; i++)
        {
            using var record = reader.ReadEvent();
            if (record is null) break;
            var parsed = Parse(record);
            if (parsed is not null) events.Add(parsed);
        }

        events.Reverse(); // back to chronological order
        return events;
    }

    /// <summary>
    /// Reads events from a saved .evtx file in chronological order, up to
    /// <paramref name="maxEvents"/>. Reports progress every 5,000 events.
    /// </summary>
    public static List<SysmonEvent> ReadFile(string filePath, int maxEvents, Action<int>? progress = null)
    {
        var query = new EventLogQuery(filePath, PathType.FilePath);
        using var reader = new EventLogReader(query);

        var events = new List<SysmonEvent>();
        while (events.Count < maxEvents)
        {
            using var record = reader.ReadEvent();
            if (record is null) break;
            var parsed = Parse(record);
            if (parsed is not null)
            {
                events.Add(parsed);
                if (progress is not null && events.Count % 5000 == 0)
                    progress(events.Count);
            }
        }
        return events;
    }

    /// <summary>
    /// Starts a real-time subscription for one channel. Safe to call for several
    /// channels; each keeps its own watcher so one failing channel doesn't take
    /// the others down. Throws if this channel is missing or unreadable.
    /// </summary>
    public void Start(string channel)
    {
        if (_watchers.ContainsKey(channel)) return;

        var query = new EventLogQuery(channel, PathType.LogName);
        var watcher = new EventLogWatcher(query);
        watcher.EventRecordWritten += OnEventRecordWritten;
        watcher.Enabled = true; // throws if channel missing or access denied
        _watchers[channel] = watcher;
    }

    /// <summary>Stops one channel's subscription, leaving any others running.</summary>
    public void StopChannel(string channel)
    {
        if (!_watchers.Remove(channel, out var watcher)) return;
        DisposeWatcher(watcher);
    }

    /// <summary>Stops every subscription.</summary>
    public void Stop()
    {
        foreach (var watcher in _watchers.Values) DisposeWatcher(watcher);
        _watchers.Clear();
    }

    private void DisposeWatcher(EventLogWatcher watcher)
    {
        try
        {
            watcher.Enabled = false;
            watcher.EventRecordWritten -= OnEventRecordWritten;
            watcher.Dispose();
        }
        catch
        {
            // A channel that vanished underneath us must not block shutdown.
        }
    }

    private void OnEventRecordWritten(object? sender, EventRecordWrittenEventArgs e)
    {
        if (e.EventException is not null)
        {
            Error?.Invoke(e.EventException.Message);
            return;
        }

        using var record = e.EventRecord;
        if (record is null) return;

        var parsed = Parse(record);
        if (parsed is not null) EventArrived?.Invoke(parsed);
    }

    /// <summary>Parses an EventRecord's XML into our model.</summary>
    public static SysmonEvent? Parse(EventRecord record)
    {
        try
        {
            var xml = record.ToXml();
            var data = ParseEventData(xml);
            var eventId = record.Id;
            // Event IDs only mean something relative to their channel, so the
            // channel rides along with every event and drives naming and rules.
            var channel = record.LogName ?? "";
            var image = GetField(data, "Image");
            var parentImage = GetField(data, "ParentImage");

            return new SysmonEvent
            {
                RecordId = record.RecordId ?? 0,
                TimeCreated = record.TimeCreated?.ToLocalTime() ?? DateTime.Now,
                EventId = eventId,
                Channel = channel,
                TaskName = SysmonEvent.NameForEventId(channel, eventId),
                Summary = SysmonEvent.BuildSummary(data),
                RawXml = xml,
                Data = data,
                Pid = GetField(data, "ProcessId"),
                ParentPid = GetField(data, "ParentProcessId"),
                ProcessGuid = GetField(data, "ProcessGuid"),
                ParentProcessGuid = GetField(data, "ParentProcessGuid"),
                ParentImage = parentImage,
                Hit = SuspicionRules.Evaluate(channel, eventId, image, parentImage, data),
            };
        }
        catch
        {
            return null; // skip records we cannot render rather than crashing the stream
        }
    }

    private static string GetField(List<KeyValuePair<string, string>> data, string name)
    {
        foreach (var kv in data)
        {
            if (kv.Key == name) return kv.Value;
        }
        return "";
    }

    private static List<KeyValuePair<string, string>> ParseEventData(string xml)
    {
        var result = new List<KeyValuePair<string, string>>();
        using var reader = XmlReader.Create(new StringReader(xml));
        while (reader.Read())
        {
            if (reader.NodeType == XmlNodeType.Element && reader.Name == "Data")
            {
                var name = reader.GetAttribute("Name") ?? "";
                var value = reader.Read() && reader.NodeType == XmlNodeType.Text
                    ? reader.Value
                    : "";
                result.Add(new KeyValuePair<string, string>(name, value));
            }
        }
        return result;
    }

    public void Dispose() => Stop();
}
