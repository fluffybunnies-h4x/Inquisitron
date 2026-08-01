using System.Collections.ObjectModel;
using Inquisitron.Models;

namespace Inquisitron.Services;

/// <summary>
/// Builds a live parent→child process tree from Sysmon events, keyed by
/// ProcessGuid (stable across PID reuse). Event ID 1 adds nodes, Event ID 5
/// marks them exited. All methods must be called on the UI thread.
/// </summary>
public sealed class ProcessTree
{
    public ObservableCollection<ProcessNode> Roots { get; } = new();

    private readonly Dictionary<string, ProcessNode> _byGuid = new(StringComparer.OrdinalIgnoreCase);

    public void Apply(SysmonEvent evt)
    {
        switch (evt.EventId)
        {
            case 1: AddProcess(evt); break;
            case 5: MarkExited(evt); break;
        }
    }

    private void AddProcess(SysmonEvent evt)
    {
        if (evt.ProcessGuid.Length == 0) return;

        var commandLine = FieldOf(evt, "CommandLine");
        if (_byGuid.TryGetValue(evt.ProcessGuid, out var existing))
        {
            // We knew this process only as someone's parent — fill in the real data.
            existing.Image = FieldOf(evt, "Image");
            existing.CommandLine = commandLine;
            existing.Pid = evt.Pid;
            existing.StartTime = evt.TimeCreated;
            existing.IsPlaceholder = false;
            existing.SuspicionReason = evt.SuspicionReason;
            existing.Severity = evt.SuspicionSeverity;
            Reparent(existing, evt.ParentProcessGuid, evt);
            return;
        }

        var node = new ProcessNode
        {
            Guid = evt.ProcessGuid,
            Image = FieldOf(evt, "Image"),
            CommandLine = commandLine,
            Pid = evt.Pid,
            StartTime = evt.TimeCreated,
            SuspicionReason = evt.SuspicionReason,
            Severity = evt.SuspicionSeverity,
        };
        _byGuid[evt.ProcessGuid] = node;
        AttachToParent(node, evt.ParentProcessGuid, evt);
    }

    private void AttachToParent(ProcessNode node, string parentGuid, SysmonEvent evt)
    {
        node.ParentGuid = parentGuid;
        if (parentGuid.Length == 0)
        {
            Roots.Add(node);
            return;
        }

        if (!_byGuid.TryGetValue(parentGuid, out var parent))
        {
            // Parent started before our capture window — synthesize it from
            // what the child's event tells us about it.
            parent = new ProcessNode
            {
                Guid = parentGuid,
                Image = evt.ParentImage,
                Pid = evt.ParentPid,
                IsPlaceholder = true,
            };
            _byGuid[parentGuid] = parent;
            Roots.Add(parent);
        }
        parent.Children.Add(node);
    }

    private void Reparent(ProcessNode node, string parentGuid, SysmonEvent evt)
    {
        if (node.ParentGuid.Equals(parentGuid, StringComparison.OrdinalIgnoreCase)) return;
        if (node.ParentGuid.Length == 0) Roots.Remove(node);
        AttachToParent(node, parentGuid, evt);
    }

    private void MarkExited(SysmonEvent evt)
    {
        if (evt.ProcessGuid.Length > 0 && _byGuid.TryGetValue(evt.ProcessGuid, out var node))
            node.Exited = true;
    }

    public ProcessNode? Find(string guid) =>
        guid.Length > 0 && _byGuid.TryGetValue(guid, out var node) ? node : null;

    /// <summary>Ancestry chain, oldest ancestor first, ending at the given process.</summary>
    public List<ProcessNode> Lineage(string guid)
    {
        var chain = new List<ProcessNode>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var current = Find(guid);
        while (current is not null && seen.Add(current.Guid))
        {
            chain.Add(current);
            current = Find(current.ParentGuid);
        }
        chain.Reverse();
        return chain;
    }

    public void Clear()
    {
        Roots.Clear();
        _byGuid.Clear();
    }

    public void SetExpandedAll(bool expanded)
    {
        foreach (var node in _byGuid.Values)
            node.IsExpanded = expanded;
    }

    private static string FieldOf(SysmonEvent evt, string name) => evt.GetData(name);
}
