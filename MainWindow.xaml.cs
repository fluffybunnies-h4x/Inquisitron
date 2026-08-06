using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Interop;
using System.Windows.Threading;
using System.Xml.Linq;
using Inquisitron.Models;
using Inquisitron.Services;

namespace Inquisitron;

public partial class MainWindow : Window
{
    private const int MaxEventsKept = 50_000;
    private const int BackfillCount = 2_000;
    private const int MaxFileEvents = 500_000;

    private readonly EventLogService _service = new();
    private readonly ProcessTree _tree = new();
    private readonly ObservableCollection<SysmonEvent> _events = new();
    private readonly ConcurrentQueue<SysmonEvent> _incoming = new();
    private readonly DispatcherTimer _flushTimer;
    private readonly DispatcherTimer _filterDebounce;
    private readonly Dictionary<string, TextBox> _filterBoxes = new();
    private readonly Dictionary<string, string> _columnFilters = new();
    private ICollectionView? _view;
    private long _totalSeen;
    private bool _fileMode;

    public MainWindow()
    {
        InitializeComponent();

        _view = CollectionViewSource.GetDefaultView(_events);
        _view.Filter = FilterEvent;
        EventGrid.ItemsSource = _view;
        ProcessTreeView.ItemsSource = _tree.Roots;

        PopulateEventIdFilter();

        _service.EventArrived += e => _incoming.Enqueue(e);
        _service.Error += msg => Dispatcher.BeginInvoke(() => StatusText.Text = $"Watcher error: {msg}");

        // Batch UI updates: draining a queue 4x/second keeps the grid smooth
        // even when Sysmon is writing hundreds of events per second.
        _flushTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(250) };
        _flushTimer.Tick += (_, _) => FlushIncoming();

        // Debounce column-filter typing so we don't refilter 50k rows per keystroke.
        _filterDebounce = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(300) };
        _filterDebounce.Tick += (_, _) =>
        {
            _filterDebounce.Stop();
            RefreshFilter();
        };

        Closed += (_, _) => _service.Dispose();
    }

    // ---- Dark title bar ----

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        try
        {
            var hwnd = new WindowInteropHelper(this).Handle;
            var on = 1;
            // DWMWA_USE_IMMERSIVE_DARK_MODE is 20 on Windows 10 20H1+/11 and was
            // 19 on 1809-1909; try the current value, fall back to the old one.
            if (DwmSetWindowAttribute(hwnd, 20, ref on, sizeof(int)) != 0)
                DwmSetWindowAttribute(hwnd, 19, ref on, sizeof(int));
        }
        catch
        {
            // dwmapi missing or pre-1809 — keep the default light title bar.
        }
    }

    private void PopulateEventIdFilter()
    {
        EventIdFilterBox.Items.Add("All events");
        foreach (var (id, name) in SysmonEvent.SysmonEventNames.OrderBy(kv => kv.Key))
            EventIdFilterBox.Items.Add($"{id} — {name}");
        EventIdFilterBox.SelectedIndex = 0;
    }

    // ---- Start / stop ----

    private void StartStopButton_Click(object sender, RoutedEventArgs e)
    {
        if (_service.IsRunning)
        {
            StopWatching();
            return;
        }

        var requested = ParseChannelList(ChannelBox.Text);
        if (requested.Count == 0) return;

        var missing = requested.Where(c => !EventLogService.ChannelExists(c)).ToList();
        var available = requested.Except(missing, StringComparer.OrdinalIgnoreCase).ToList();

        if (available.Count == 0)
        {
            StatusText.Text = $"Channel not found: {string.Join(", ", missing)}";
            MessageBox.Show(
                $"None of the requested channels exist on this machine:\n\n  {string.Join("\n  ", missing)}\n\n" +
                "If you expected Sysmon logs, Sysmon is probably not installed. Install it from " +
                "an elevated prompt:  sysmon.exe -accepteula -i sysmonconfig.xml",
                "Channel not found", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        // Leaving offline file mode: the file's events don't belong in a live view.
        if (_fileMode)
        {
            _events.Clear();
            _tree.Clear();
            _totalSeen = 0;
            _fileMode = false;
        }

        // Backfill every channel first, then subscribe. Failures are collected
        // per channel so one unreadable log doesn't abandon the others.
        var backfill = new List<SysmonEvent>();
        var started = new List<string>();
        var failed = new List<string>(missing.Select(c => $"{c} (not found)"));

        foreach (var channel in available)
        {
            try
            {
                backfill.AddRange(EventLogService.ReadRecent(channel, BackfillCount));
                _service.Start(channel);
                started.Add(channel);
            }
            catch (UnauthorizedAccessException)
            {
                failed.Add($"{channel} (access denied)");
            }
            catch (Exception ex)
            {
                failed.Add($"{channel} ({ex.Message})");
            }
        }

        if (started.Count == 0)
        {
            _service.Stop();
            StatusText.Text = $"Failed to start: {string.Join("; ", failed)}";
            MessageBox.Show(
                $"Could not subscribe to any channel:\n\n  {string.Join("\n  ", failed)}\n\n" +
                "Sysmon and Security are readable by Administrators only. Right-click " +
                "Inquisitron.exe and choose \"Run as administrator\", or add your account to " +
                "the \"Event Log Readers\" group and grant the channel ACL.",
                "Cannot start", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        // The whole point of multi-channel is a single timeline, so the merged
        // backfill has to be ordered by time rather than by channel.
        backfill.Sort((a, b) => a.TimeCreated.CompareTo(b.TimeCreated));
        BulkAdd(backfill);
        _totalSeen += backfill.Count;

        _flushTimer.Start();
        ChannelBox.IsEnabled = false;
        StartStopButton.Content = "⏸ Stop";
        StatusText.Text = failed.Count == 0
            ? $"Watching {started.Count} channel{(started.Count == 1 ? "" : "s")}: {string.Join(", ", started.Select(SysmonEvent.ShortChannelName))}"
            : $"Watching {string.Join(", ", started.Select(SysmonEvent.ShortChannelName))} — skipped {string.Join("; ", failed)}";
        UpdateCounts();
        ScrollToEnd();
    }

    /// <summary>Channel box accepts several channels separated by commas or semicolons.</summary>
    private static List<string> ParseChannelList(string text) =>
        text.Split(new[] { ',', ';' },
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

    private void StopWatching()
    {
        _service.Stop();
        _flushTimer.Stop();
        FlushIncoming(); // drain anything still queued
        ChannelBox.IsEnabled = true;
        StartStopButton.Content = "▶ Start";
        StatusText.Text = "Stopped";
    }

    private void ClearButton_Click(object sender, RoutedEventArgs e)
    {
        _events.Clear();
        _tree.Clear();
        _totalSeen = 0;
        while (_incoming.TryDequeue(out _)) { }
        DetailGrid.ItemsSource = null;
        XmlBox.Clear();
        UpdateCounts();
    }

    // ---- Incoming event pump ----

    private void FlushIncoming()
    {
        if (_incoming.IsEmpty) return;

        // Drain first, then order by timestamp: each channel has its own watcher
        // firing independently, so arrival order is not chronological order.
        var batch = new List<SysmonEvent>();
        while (_incoming.TryDequeue(out var queued)) batch.Add(queued);
        if (batch.Count > 1) batch.Sort((a, b) => a.TimeCreated.CompareTo(b.TimeCreated));

        foreach (var evt in batch)
        {
            _events.Add(evt);
            _tree.Apply(evt);
            _totalSeen++;
        }

        // Cap memory: drop oldest rows once past the limit.
        while (_events.Count > MaxEventsKept)
            _events.RemoveAt(0);

        UpdateCounts();
        ScrollToEnd();
    }

    /// <summary>
    /// Appends many events at once, detaching the grid so it doesn't re-render
    /// per row.
    ///
    /// Deliberately does NOT use ICollectionView.DeferRefresh(): adding to the
    /// source collection while a refresh is deferred makes ListCollectionView
    /// adjust currency, which reads CurrentPosition and throws
    /// "Cannot change or check the contents or Current position of
    /// CollectionView while Refresh is being deferred". Detaching the grid gets
    /// the same rendering win without touching currency.
    /// </summary>
    private void BulkAdd(IReadOnlyList<SysmonEvent> events)
    {
        EventGrid.ItemsSource = null;
        try
        {
            foreach (var evt in events)
            {
                _events.Add(evt);
                _tree.Apply(evt);
            }
        }
        finally
        {
            EventGrid.ItemsSource = _view;
        }
    }

    private void ScrollToEnd()
    {
        if (AutoScrollCheck.IsChecked != true || _view is null) return;
        var last = _view.Cast<object>().LastOrDefault();
        if (last is not null) EventGrid.ScrollIntoView(last);
    }

    private void UpdateCounts()
    {
        var shown = _view?.Cast<object>().Count() ?? 0;
        CountText.Text = $"{shown:N0} shown / {_events.Count:N0} kept / {_totalSeen:N0} seen";
    }

    // ---- Filtering ----

    private bool FilterEvent(object item)
    {
        if (item is not SysmonEvent evt) return false;

        if (EventIdFilterBox.SelectedIndex > 0 &&
            EventIdFilterBox.SelectedItem is string sel)
        {
            var idText = sel.Split('—')[0].Trim();
            if (int.TryParse(idText, out var id) && evt.EventId != id) return false;
        }

        if (FlaggedOnlyCheck.IsChecked == true && !evt.IsSuspicious) return false;

        var needle = SearchBox.Text.Trim();
        if (needle.Length > 0 && !evt.Matches(needle)) return false;

        foreach (var (column, spec) in _columnFilters)
        {
            if (spec.Length == 0) continue;
            var value = column switch
            {
                "Time" => evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss.fff"),
                "Channel" => evt.ChannelName,
                "ID" => evt.EventId.ToString(),
                "PID" => evt.Pid,
                "PPID" => evt.ParentPid,
                "Type" => evt.TaskName,
                "Rule" => evt.SuspicionRuleName,
                "Process" => evt.ProcessImage,
                "Summary" => evt.Summary,
                _ => "",
            };
            // IDs and PIDs match exactly so "1" doesn't also match 10, 11, 12...
            if (!MatchesSpec(value, spec, exact: column is "ID" or "PID" or "PPID")) return false;
        }

        return true;
    }

    /// <summary>
    /// Filter spec: comma-separated terms; a term starting with '!' excludes.
    /// Any exclusion match rejects; if inclusion terms exist, one must match.
    /// </summary>
    private static bool MatchesSpec(string value, string spec, bool exact)
    {
        var hasIncludes = false;
        var includeHit = false;

        foreach (var raw in spec.Split(','))
        {
            var term = raw.Trim();
            if (term.Length == 0) continue;

            var negate = term.StartsWith('!');
            if (negate) term = term[1..].Trim();
            if (term.Length == 0) continue;

            var hit = exact
                ? string.Equals(value, term, StringComparison.OrdinalIgnoreCase)
                : value.Contains(term, StringComparison.OrdinalIgnoreCase);

            if (negate)
            {
                if (hit) return false;
            }
            else
            {
                hasIncludes = true;
                if (hit) includeHit = true;
            }
        }

        return !hasIncludes || includeHit;
    }

    private void RefreshFilter()
    {
        if (_view is null) return;
        _view.Refresh();
        UpdateCounts();
        ScrollToEnd();
    }

    private void Filter_Changed(object sender, RoutedEventArgs e)
    {
        if (_view is null) return; // fires during InitializeComponent
        RefreshFilter();
    }

    // ---- Column filter boxes (live inside the DataGrid column headers) ----

    private void HeaderFilter_Loaded(object sender, RoutedEventArgs e)
    {
        if (sender is not TextBox box || box.Tag is not string key) return;
        _filterBoxes[key] = box;
        // Restore state if the header got re-templated.
        if (_columnFilters.TryGetValue(key, out var spec) && box.Text != spec)
            box.Text = spec;
    }

    private void HeaderFilter_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (sender is not TextBox box || box.Tag is not string key) return;
        _columnFilters[key] = box.Text.Trim();
        _filterDebounce.Stop();
        _filterDebounce.Start();
    }

    private void SetColumnFilter(string column, string spec)
    {
        _columnFilters[column] = spec;
        if (_filterBoxes.TryGetValue(column, out var box))
            box.Text = spec; // TextChanged will debounce-refresh
        else
            RefreshFilter();
    }

    private void AppendFilterTerm(string column, string term)
    {
        _columnFilters.TryGetValue(column, out var current);
        current ??= "";
        // Don't stack duplicates of the same term.
        var exists = current.Split(',').Any(t =>
            string.Equals(t.Trim(), term, StringComparison.OrdinalIgnoreCase));
        if (exists) return;
        SetColumnFilter(column, current.Length == 0 ? term : $"{current},{term}");
    }

    // ---- Row context menu ----

    /// <summary>Text of the cell under the cursor when the context menu opened.</summary>
    private string _contextCellText = "";

    private static T? FindAncestor<T>(object? source) where T : DependencyObject
    {
        var d = source as DependencyObject;
        while (d is not null && d is not T)
        {
            d = d is System.Windows.Media.Visual or System.Windows.Media.Media3D.Visual3D
                ? System.Windows.Media.VisualTreeHelper.GetParent(d)
                : LogicalTreeHelper.GetParent(d);
        }
        return d as T;
    }

    private void EventGrid_ContextMenuOpening(object sender, ContextMenuEventArgs e)
    {
        // Right-click doesn't move selection on its own, so without this every
        // context action would target the previously-selected row instead of the
        // one under the cursor.
        var row = FindAncestor<DataGridRow>(e.OriginalSource);
        if (row?.Item is SysmonEvent evt && !ReferenceEquals(EventGrid.SelectedItem, evt))
            EventGrid.SelectedItem = evt;

        var cell = FindAncestor<DataGridCell>(e.OriginalSource);
        _contextCellText = (cell?.Content as TextBlock)?.Text ?? "";
        if (_contextCellText.Length > 0)
        {
            var label = _contextCellText.Length > 60 ? _contextCellText[..60] + "…" : _contextCellText;
            // "_" is the MenuItem access-key marker; double it to display literally.
            CopyCellItem.Header = $"Copy “{label.Replace("_", "__")}”";
            CopyCellItem.IsEnabled = true;
        }
        else
        {
            CopyCellItem.Header = "Copy cell";
            CopyCellItem.IsEnabled = false;
        }

        FilterPpidItem.IsEnabled =
            EventGrid.SelectedItem is SysmonEvent { ParentPid.Length: > 0 };
    }

    private void CopyCell_Click(object sender, RoutedEventArgs e)
    {
        if (_contextCellText.Length == 0) return;
        try
        {
            Clipboard.SetText(_contextCellText);
            StatusText.Text = $"Copied: {(_contextCellText.Length > 100 ? _contextCellText[..100] + "…" : _contextCellText)}";
        }
        catch (Exception ex)
        {
            // Another process can hold the clipboard open; don't crash over a copy.
            StatusText.Text = $"Copy failed (clipboard in use?): {ex.Message}";
        }
    }

    private void FilterToProcess_Click(object sender, RoutedEventArgs e)
    {
        if (EventGrid.SelectedItem is SysmonEvent evt && evt.ProcessName.Length > 0)
            SetColumnFilter("Process", evt.ProcessName);
    }

    private void ExcludeProcess_Click(object sender, RoutedEventArgs e)
    {
        if (EventGrid.SelectedItem is SysmonEvent evt && evt.ProcessName.Length > 0)
            AppendFilterTerm("Process", $"!{evt.ProcessName}");
    }

    private void FilterToEventId_Click(object sender, RoutedEventArgs e)
    {
        if (EventGrid.SelectedItem is SysmonEvent evt)
            SetColumnFilter("ID", evt.EventId.ToString());
    }

    private void ExcludeEventId_Click(object sender, RoutedEventArgs e)
    {
        if (EventGrid.SelectedItem is SysmonEvent evt)
            AppendFilterTerm("ID", $"!{evt.EventId}");
    }

    private void ClearFilters_Click(object sender, RoutedEventArgs e)
    {
        foreach (var key in _columnFilters.Keys.ToList())
            _columnFilters[key] = "";
        foreach (var box in _filterBoxes.Values)
            box.Text = "";
        SearchBox.Text = "";
        EventIdFilterBox.SelectedIndex = 0;
        FlaggedOnlyCheck.IsChecked = false;
        RefreshFilter();
    }

    private void FilterToPid_Click(object sender, RoutedEventArgs e)
    {
        if (EventGrid.SelectedItem is SysmonEvent evt && evt.Pid.Length > 0)
            SetColumnFilter("PID", evt.Pid);
    }

    private void FilterToPpid_Click(object sender, RoutedEventArgs e)
    {
        if (EventGrid.SelectedItem is SysmonEvent evt && evt.ParentPid.Length > 0)
            SetColumnFilter("PPID", evt.ParentPid);
    }

    // ---- Offline .evtx / export ----

    private async void OpenEvtx_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Filter = "Windows event log (*.evtx)|*.evtx|All files (*.*)|*.*",
            Title = "Open saved event log",
        };
        if (dlg.ShowDialog(this) != true) return;

        if (_service.IsRunning) StopWatching();
        _events.Clear();
        _tree.Clear();
        while (_incoming.TryDequeue(out _)) { }
        _totalSeen = 0;
        _fileMode = true;

        var path = dlg.FileName;
        var name = Path.GetFileName(path);
        StartStopButton.IsEnabled = false;
        StatusText.Text = $"Loading {name}…";

        try
        {
            var loaded = await Task.Run(() => EventLogService.ReadFile(path, MaxFileEvents,
                n => Dispatcher.BeginInvoke(() => StatusText.Text = $"Loading {name}… {n:N0} events")));

            BulkAdd(loaded);
            _totalSeen = loaded.Count;

            StatusText.Text = loaded.Count >= MaxFileEvents
                ? $"Loaded first {loaded.Count:N0} events of {name} (cap reached)"
                : $"Loaded {loaded.Count:N0} events from {name}";
        }
        catch (Exception ex)
        {
            _fileMode = false;
            StatusText.Text = $"Failed to load {name}: {ex.Message}";
        }
        finally
        {
            StartStopButton.IsEnabled = true;
        }
        UpdateCounts();
    }

    private void Export_Click(object sender, RoutedEventArgs e)
    {
        if (_view is null) return;
        var visible = _view.Cast<SysmonEvent>().ToList();
        if (visible.Count == 0)
        {
            StatusText.Text = "Nothing to export — no events match the current filters";
            return;
        }

        var dlg = new SaveFileDialog
        {
            Filter = "CSV file (*.csv)|*.csv|JSON file (*.json)|*.json",
            FileName = $"inquisitron-{DateTime.Now:yyyyMMdd-HHmmss}",
            Title = $"Export {visible.Count:N0} events",
        };
        if (dlg.ShowDialog(this) != true) return;

        try
        {
            var asJson = dlg.FilterIndex == 2 ||
                         dlg.FileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase);
            if (asJson) Exporter.ToJson(dlg.FileName, visible);
            else Exporter.ToCsv(dlg.FileName, visible);
            StatusText.Text = $"Exported {visible.Count:N0} events → {dlg.FileName}";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Export failed: {ex.Message}";
        }
    }

    // ---- Suspicion rules ----

    private void ReloadRules_Click(object sender, RoutedEventArgs e)
    {
        FlushIncoming(); // score everything that's arrived, not just what's rendered
        SuspicionRules.Reload();

        var flagged = 0;
        foreach (var evt in _events)
        {
            var hit = SuspicionRules.Evaluate(evt.Channel, evt.EventId, evt.GetData("Image"), evt.ParentImage, evt.Data);
            evt.Hit = hit;
            if (hit is not null) flagged++;

            var node = _tree.Find(evt.ProcessGuid);
            if (node is not null && !node.IsPlaceholder)
            {
                node.SuspicionReason = evt.SuspicionReason;
                node.Severity = evt.SuspicionSeverity;
            }
        }

        RefreshFilter();
        StatusText.Text =
            $"Rules reloaded ({SuspicionRules.Source}) — re-evaluated {_events.Count:N0} events, {flagged:N0} flagged";
    }

    // ---- Process tree ----

    private void ExpandTree_Click(object sender, RoutedEventArgs e) => _tree.SetExpandedAll(true);
    private void CollapseTree_Click(object sender, RoutedEventArgs e) => _tree.SetExpandedAll(false);

    private void ShowLineage_Click(object sender, RoutedEventArgs e)
    {
        if (EventGrid.SelectedItem is not SysmonEvent evt) return;

        var chain = _tree.Lineage(evt.ProcessGuid);
        if (chain.Count == 0)
        {
            MessageBox.Show(
                "No lineage available for this event. Lineage is built from Process Create " +
                "(Event ID 1) records, so the process must have started inside the capture window.",
                "Process lineage", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var sb = new StringBuilder();
        for (var i = 0; i < chain.Count; i++)
        {
            var node = chain[i];
            var indent = new string(' ', i * 4);
            var arrow = i == 0 ? "" : "└─ ";
            var exited = node.Exited ? "  [exited]" : "";
            var flag = node.IsSuspicious ? "  ⚠ " + node.SuspicionReason : "";
            sb.AppendLine($"{indent}{arrow}{node.Name}  ({node.PidText}){exited}{flag}");
            if (node.CommandLine.Length > 0)
                sb.AppendLine($"{indent}   {node.CommandLine}");
            sb.AppendLine();
        }

        var viewer = new Window
        {
            Title = $"Process lineage — {evt.ProcessName}",
            Owner = this,
            Width = 900,
            Height = 400,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Background = System.Windows.Media.Brushes.Black,
            Content = new TextBox
            {
                Text = sb.ToString(),
                IsReadOnly = true,
                FontFamily = new System.Windows.Media.FontFamily("Consolas"),
                FontSize = 13,
                Background = System.Windows.Media.Brushes.Black,
                Foreground = System.Windows.Media.Brushes.Gainsboro,
                BorderThickness = new Thickness(0),
                Padding = new Thickness(10),
                TextWrapping = TextWrapping.NoWrap,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
            },
        };
        viewer.Show();
    }

    // ---- Detail pane ----

    private void EventGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (EventGrid.SelectedItem is not SysmonEvent evt)
        {
            DetailGrid.ItemsSource = null;
            XmlBox.Clear();
            return;
        }

        DetailGrid.ItemsSource = evt.Data;
        XmlBox.Text = PrettyPrintXml(evt.RawXml);
    }

    private static string PrettyPrintXml(string xml)
    {
        try
        {
            return XDocument.Parse(xml).ToString();
        }
        catch
        {
            return xml;
        }
    }
}
