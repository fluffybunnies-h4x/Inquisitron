using System.IO;
using System.Text;
using System.Text.Json;
using Inquisitron.Models;

namespace Inquisitron.Services;

/// <summary>Writes event sets to CSV (grid columns) or JSON (full field data).</summary>
public static class Exporter
{
    public static void ToCsv(string path, IReadOnlyList<SysmonEvent> events)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Time,RecordId,EventId,EventType,PID,PPID,Image,ParentImage,Summary,Severity,Detection,SuspicionReason");
        foreach (var e in events)
        {
            sb.Append(Csv(e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss.fff"))).Append(',');
            sb.Append(e.RecordId).Append(',');
            sb.Append(e.EventId).Append(',');
            sb.Append(Csv(e.TaskName)).Append(',');
            sb.Append(Csv(e.Pid)).Append(',');
            sb.Append(Csv(e.ParentPid)).Append(',');
            sb.Append(Csv(e.ProcessImage)).Append(',');
            sb.Append(Csv(e.ParentImage)).Append(',');
            sb.Append(Csv(e.Summary)).Append(',');
            sb.Append(Csv(e.SuspicionSeverity)).Append(',');
            sb.Append(Csv(e.SuspicionRuleName)).Append(',');
            sb.Append(Csv(e.SuspicionReason)).AppendLine();
        }
        // UTF-8 BOM so Excel opens non-ASCII paths/command lines correctly.
        File.WriteAllText(path, sb.ToString(), new UTF8Encoding(true));
    }

    private static string Csv(string s)
    {
        if (s.IndexOfAny(new[] { ',', '"', '\n', '\r' }) < 0) return s;
        return $"\"{s.Replace("\"", "\"\"")}\"";
    }

    public static void ToJson(string path, IReadOnlyList<SysmonEvent> events)
    {
        using var stream = File.Create(path);
        using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true });

        writer.WriteStartArray();
        foreach (var e in events)
        {
            writer.WriteStartObject();
            writer.WriteString("time", e.TimeCreated.ToString("o"));
            writer.WriteNumber("recordId", e.RecordId);
            writer.WriteNumber("eventId", e.EventId);
            writer.WriteString("eventType", e.TaskName);
            if (e.IsSuspicious)
            {
                writer.WriteString("detection", e.SuspicionRuleName);
                writer.WriteString("severity", e.SuspicionSeverity);
                writer.WriteString("suspicionReason", e.SuspicionReason);
            }
            writer.WriteStartObject("data");
            foreach (var kv in e.Data)
                writer.WriteString(kv.Key.Length == 0 ? "_" : kv.Key, kv.Value);
            writer.WriteEndObject();
            writer.WriteEndObject();
        }
        writer.WriteEndArray();
    }
}
