using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Inquisitron.Services;

public enum Severity { Low, Medium, High, Critical }

/// <summary>A rule that matched an event.</summary>
public sealed record RuleHit(string Name, string Description, Severity Severity)
{
    /// <summary>Single-line form stored on the event, shown in tooltips and exports.</summary>
    public override string ToString() => $"[{Severity.ToString().ToUpperInvariant()}] {Name} — {Description}";
}

/// <summary>
/// Behavioral detection rules evaluated against every parsed Sysmon event.
///
/// A rule can gate on event ID, parent/child image name, and any number of
/// EventData field matches — so rules can cover process creation (1), network
/// connections (3), file creation (11), registry writes (12/13), and DNS (22)
/// rather than parent/child lineage alone.
///
/// Rules load from "suspicion-rules.json" beside the exe when present, else
/// from the built-in defaults. The most severe matching rule wins.
/// </summary>
public static class SuspicionRules
{
    private sealed record FieldMatch(string Field, Regex Pattern, bool Negate);

    private sealed record Rule(
        string Name,
        string Description,
        Severity Severity,
        int[]? EventIds,
        Regex? Parent,
        Regex? Child,
        FieldMatch[] All,
        FieldMatch[] Any);

    private static volatile Dictionary<int, Rule[]> _byEventId = new();
    private static volatile Rule[] _anyEvent = Array.Empty<Rule>();

    /// <summary>Where the active rules came from, for status display.</summary>
    public static string Source { get; private set; } = "";

    /// <summary>Number of active rules.</summary>
    public static int Count { get; private set; }

    static SuspicionRules() => Reload();

    /// <summary>
    /// Re-reads suspicion-rules.json (or falls back to defaults) and swaps the
    /// active rule set. Safe to call while watcher threads are evaluating.
    /// </summary>
    public static void Reload()
    {
        try
        {
            ReloadCore();
        }
        catch (Exception ex)
        {
            // A malformed built-in rule must not take the whole app down via
            // TypeInitializationException — run with no rules and say so.
            _anyEvent = Array.Empty<Rule>();
            _byEventId = new Dictionary<int, Rule[]>();
            Count = 0;
            Source = $"NO RULES ACTIVE — rule engine failed to load: {ex.Message}";
        }
    }

    private static void ReloadCore()
    {
        var rules = LoadRules(out var source);

        // Most severe first, so the highest-severity matching rule is reported.
        // Stable sort: among equal severities, rule-file order is the tiebreaker,
        // so putting a specific rule above a generic one in the JSON is meaningful.
        rules = rules.OrderByDescending(r => r.Severity).ToList();

        // Index by event ID so a 500k-event .evtx load doesn't run every regex
        // against every event.
        var byId = new Dictionary<int, List<Rule>>();
        var anyEvent = new List<Rule>();
        foreach (var rule in rules)
        {
            if (rule.EventIds is null || rule.EventIds.Length == 0)
            {
                anyEvent.Add(rule);
                continue;
            }
            foreach (var id in rule.EventIds)
            {
                if (!byId.TryGetValue(id, out var list))
                    byId[id] = list = new List<Rule>();
                list.Add(rule);
            }
        }

        _anyEvent = anyEvent.ToArray();
        _byEventId = byId.ToDictionary(kv => kv.Key, kv => kv.Value.ToArray());
        Count = rules.Count;
        Source = source;
    }

    // ---- Loading ----

    private static List<Rule> LoadRules(out string source)
    {
        var custom = Path.Combine(AppContext.BaseDirectory, "suspicion-rules.json");
        if (File.Exists(custom))
        {
            try
            {
                var rules = ParseJson(File.ReadAllText(custom));
                source = $"{rules.Count} rules from suspicion-rules.json";
                return rules;
            }
            catch (Exception ex)
            {
                var fallback = Defaults();
                source = $"{fallback.Count} built-in rules (suspicion-rules.json invalid: {ex.Message})";
                return fallback;
            }
        }

        var defaults = Defaults();
        source = $"{defaults.Count} built-in rules";
        return defaults;
    }

    private static List<Rule> ParseJson(string json)
    {
        using var doc = JsonDocument.Parse(json,
            new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });

        var rules = new List<Rule>();
        foreach (var item in doc.RootElement.EnumerateArray())
        {
            var description = GetString(item, "description") ?? "Custom rule";
            var name = GetString(item, "name") ?? description;

            var severity = Severity.High;
            var severityText = GetString(item, "severity");
            if (severityText is not null && Enum.TryParse<Severity>(severityText, true, out var parsed))
                severity = parsed;

            int[]? eventIds = null;
            if (item.TryGetProperty("eventIds", out var idsEl) && idsEl.ValueKind == JsonValueKind.Array)
                eventIds = idsEl.EnumerateArray().Select(e => e.GetInt32()).ToArray();

            var parentPattern = GetString(item, "parent");
            var childPattern = GetString(item, "child");

            // Legacy rule files had no eventIds and were process-create only.
            if (eventIds is null && (parentPattern is not null || childPattern is not null))
                eventIds = new[] { 1 };

            rules.Add(new Rule(
                name,
                description,
                severity,
                eventIds,
                parentPattern is null ? null : NameRegex(parentPattern),
                childPattern is null ? null : NameRegex(childPattern),
                ParseMatches(item, "all"),
                ParseMatches(item, "any")));
        }
        return rules;
    }

    private static FieldMatch[] ParseMatches(JsonElement item, string property)
    {
        if (!item.TryGetProperty(property, out var arr) || arr.ValueKind != JsonValueKind.Array)
            return Array.Empty<FieldMatch>();

        var matches = new List<FieldMatch>();
        foreach (var m in arr.EnumerateArray())
        {
            var field = GetString(m, "field") ?? "Any";
            var pattern = GetString(m, "regex")
                ?? throw new FormatException($"a match in \"{property}\" is missing its \"regex\"");
            var negate = m.TryGetProperty("not", out var n) && n.ValueKind == JsonValueKind.True;
            matches.Add(new FieldMatch(field, FieldRegex(pattern), negate));
        }
        return matches.ToArray();
    }

    private static string? GetString(JsonElement el, string name) =>
        el.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    /// <summary>Executable-name patterns are anchored: "cmd\.exe" must match the whole name.</summary>
    private static Regex NameRegex(string pattern) =>
        new($"^{pattern}$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>Field patterns are substring matches: "Add-MpPreference" matches anywhere.</summary>
    private static Regex FieldRegex(string pattern) =>
        new(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // ---- Evaluation ----

    /// <summary>Returns the highest-severity rule matching this event, or null if clean.</summary>
    public static RuleHit? Evaluate(
        int eventId,
        string image,
        string parentImage,
        IReadOnlyList<KeyValuePair<string, string>> data)
    {
        // svchost.exe must be born from services.exe. Hardwired so it survives
        // any custom rule file — it is never a false positive worth losing.
        // "-" is Sysmon's placeholder for an unresolvable parent (zeroed
        // ParentProcessGuid, common for per-user services around logon); unknown
        // is not evidence of masquerade, and an attacker gains nothing by
        // forcing it that PPID-spoofing services.exe wouldn't already gain.
        if (eventId == 1 && image.Length > 0 && parentImage.Length > 0 && parentImage != "-")
        {
            var childName = FileName(image);
            var parentName = FileName(parentImage);
            if (childName.Equals("svchost.exe", StringComparison.OrdinalIgnoreCase) &&
                !parentName.Equals("services.exe", StringComparison.OrdinalIgnoreCase))
            {
                return new RuleHit(
                    "Masqueraded svchost",
                    $"svchost.exe launched by {parentName} instead of services.exe",
                    Severity.Critical);
            }
        }

        // Both buckets must be consulted: a Medium rule scoped to this event ID
        // must not mask a Critical rule that applies to all events. On a severity
        // tie the scoped rule wins — it is the more specific detection.
        var scopedHit = _byEventId.TryGetValue(eventId, out var scoped)
            ? FirstMatch(scoped, image, parentImage, data)
            : null;
        var anyHit = FirstMatch(_anyEvent, image, parentImage, data);
        if (scopedHit is null) return anyHit;
        if (anyHit is null) return scopedHit;
        return anyHit.Severity > scopedHit.Severity ? anyHit : scopedHit;
    }

    private static RuleHit? FirstMatch(
        Rule[] rules,
        string image,
        string parentImage,
        IReadOnlyList<KeyValuePair<string, string>> data)
    {
        foreach (var rule in rules)
        {
            if (rule.Parent is not null &&
                (parentImage.Length == 0 || !rule.Parent.IsMatch(FileName(parentImage)))) continue;
            if (rule.Child is not null &&
                (image.Length == 0 || !rule.Child.IsMatch(FileName(image)))) continue;

            var ok = true;
            foreach (var m in rule.All)
            {
                if (!MatchField(m, image, parentImage, data)) { ok = false; break; }
            }
            if (!ok) continue;

            if (rule.Any.Length > 0)
            {
                var anyHit = false;
                foreach (var m in rule.Any)
                {
                    if (MatchField(m, image, parentImage, data)) { anyHit = true; break; }
                }
                if (!anyHit) continue;
            }

            return new RuleHit(rule.Name, rule.Description, rule.Severity);
        }
        return null;
    }

    private static bool MatchField(
        FieldMatch m,
        string image,
        string parentImage,
        IReadOnlyList<KeyValuePair<string, string>> data)
    {
        bool hit;
        if (m.Field.Equals("Any", StringComparison.OrdinalIgnoreCase))
        {
            hit = false;
            foreach (var kv in data)
            {
                if (m.Pattern.IsMatch(kv.Value)) { hit = true; break; }
            }
        }
        else
        {
            hit = m.Pattern.IsMatch(ResolveField(m.Field, image, parentImage, data));
        }
        return m.Negate ? !hit : hit;
    }

    private static string ResolveField(
        string field,
        string image,
        string parentImage,
        IReadOnlyList<KeyValuePair<string, string>> data)
    {
        switch (field)
        {
            case "Image": return image;
            case "ImageName": return FileName(image);
            case "ParentImage": return parentImage;
            case "ParentImageName": return FileName(parentImage);
        }
        foreach (var kv in data)
        {
            if (string.Equals(kv.Key, field, StringComparison.OrdinalIgnoreCase)) return kv.Value;
        }
        return "";
    }

    private static string FileName(string path)
    {
        var idx = path.LastIndexOf('\\');
        return idx >= 0 ? path[(idx + 1)..] : path;
    }

    // ---- Built-in defaults ----

    private const string Shells = @"(cmd|powershell|pwsh|wscript|cscript|mshta)\.exe";
    private const string LolBins = @"(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|bitsadmin|certutil|msbuild|installutil|msiexec)\.exe";

    /// <summary>Parent→child spawn rule on Event ID 1.</summary>
    private static Rule Spawn(string name, string parent, string child, string description, Severity severity) =>
        new(name, description, severity, new[] { 1 }, NameRegex(parent), NameRegex(child),
            Array.Empty<FieldMatch>(), Array.Empty<FieldMatch>());

    /// <summary>Command-line rule on Event ID 1: any one of the patterns fires it.</summary>
    private static Rule Cmd(string name, string description, Severity severity, string childPattern, params string[] anyPatterns) =>
        new(name, description, severity, new[] { 1 }, null,
            childPattern.Length == 0 ? null : NameRegex(childPattern),
            Array.Empty<FieldMatch>(),
            anyPatterns.Select(p => new FieldMatch("CommandLine", FieldRegex(p), false)).ToArray());

    private static List<Rule> Defaults() => new()
    {
        // ---- Generic abnormal parentage ----
        Spawn("Office spawned LOLBin",
            @"(winword|excel|powerpnt|outlook|msaccess|mspub|visio|onenote)\.exe", LolBins,
            "Office application spawned a shell/LOLBin (common macro/phishing execution)", Severity.Critical),
        Spawn("Browser spawned shell",
            @"(chrome|msedge|firefox|iexplore|brave|opera)\.exe", Shells,
            "Browser spawned a shell/script host (possible drive-by or fake-update lure)", Severity.High),
        Spawn("WMI provider spawned LOLBin",
            @"wmiprvse\.exe", LolBins,
            "WMI provider host spawned a shell/LOLBin (common lateral-movement execution)", Severity.High),
        Spawn("Script host spawned LOLBin",
            @"(mshta|wscript|cscript)\.exe", LolBins,
            "Script host spawned a shell/LOLBin (script-based dropper chain)", Severity.High),
        Spawn("Server spawned shell",
            @"(sqlservr|w3wp|httpd|nginx|tomcat\w*|php-cgi)\.exe", @"(cmd|powershell|pwsh|wscript|cscript|sh|bash)\.exe",
            "Server process spawned a shell (possible webshell)", Severity.Critical),
        Spawn("LSASS spawned child",
            @"lsass\.exe", @".*",
            "LSASS spawned a child process (LSASS should not create children)", Severity.Critical),
        Spawn("Scheduled task spawned shell",
            @"(schtasks|taskeng)\.exe", Shells,
            "Scheduled task spawned a shell (persistence execution)", Severity.Medium),

        // ---- Defender / AMSI tampering ----
        Cmd("Defender exclusion: entire drive",
            "Add-MpPreference added a drive-root exclusion, blinding Defender to the whole filesystem",
            Severity.Critical, "", @"-ExclusionPath\s+['""]?[A-Za-z]:\\?['""]?(?![\\\w])"),
        Cmd("Defender exclusion added",
            "Add-MpPreference / Set-MpPreference added a Defender exclusion",
            Severity.High, "", @"(Add|Set)-MpPreference[^\n]*-Exclusion(Path|Extension|Process)"),
        Cmd("Defender disabled",
            "WinDefend service stopped/disabled or realtime monitoring turned off",
            Severity.Critical, "",
            @"(Stop|Set)-Service[^\n]*WinDefend",
            @"sc(\.exe)?\s+(stop|config)\s+windefend",
            @"Set-MpPreference[^\n]*-DisableRealtimeMonitoring\s+\$?true"),
        Cmd("AMSI bypass",
            "In-memory AMSI patching (amsiInitFailed / AmsiUtils reflection)",
            Severity.Critical, "", @"amsiInitFailed", @"AmsiUtils", @"AmsiScanBuffer"),
        Cmd("Defender definitions removed",
            "MpCmdRun used to remove Defender signature definitions",
            Severity.Critical, "", @"MpCmdRun[^\n]*-RemoveDefinitions"),

        // ---- Execution / download ----
        Cmd("In-memory C# compilation",
            "PowerShell compiled and executed C# in memory via Add-Type",
            Severity.High, @"(powershell|pwsh)\.exe", @"Add-Type[^\n]*-(Language|TypeDefinition)"),
        Cmd("Download from raw IP address",
            "Script downloaded content from a bare IP address rather than a hostname",
            Severity.High, "",
            @"(DownloadString|DownloadFile|DownloadData|Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\bcurl\b|\bwget\b|BitsTransfer)[^\n]*https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
        Cmd("Encoded PowerShell command",
            "PowerShell executed a base64-encoded command block",
            Severity.High, @"(powershell|pwsh)\.exe", @"\s-[eE][ncodemas]*\s+[A-Za-z0-9+/=]{40,}"),
        Cmd("Hidden-window PowerShell",
            "PowerShell launched with a hidden window and/or execution-policy bypass",
            Severity.Medium, @"(powershell|pwsh)\.exe",
            @"-(w|windowstyle)\s+hidden", @"-(ep|exec|executionpolicy)\s+bypass"),
        Cmd("Silent MSI install from user-writable path",
            "msiexec installed a package silently from TEMP/AppData/Public/Downloads",
            Severity.High, @"msiexec\.exe",
            @"/(qn|quiet|qb)[^\n]*(\\Temp\\|\\AppData\\|\\Users\\Public\\|\\Downloads\\)",
            @"(\\Temp\\|\\AppData\\|\\Users\\Public\\|\\Downloads\\)[^\n]*/(qn|quiet|qb)"),
        Cmd("Mark-of-the-Web removal",
            "Zone.Identifier alternate data stream stripped to bypass SmartScreen/MotW",
            Severity.High, "", @"Unlock-File", @"Zone\.Identifier"),
        Cmd("UAC self-elevation",
            "Process re-launched itself elevated via Start-Process -Verb RunAs",
            Severity.Medium, "", @"-Verb\s+['""]?RunAs"),

        // ---- SmartScreen / Explorer tampering ----
        new("SmartScreen disabled",
            "Registry write disabling SmartScreen reputation checks or Defender policy",
            Severity.Critical, new[] { 12, 13 }, null, null,
            Array.Empty<FieldMatch>(),
            new[]
            {
                new FieldMatch("TargetObject", FieldRegex(@"SmartScreenEnabled"), false),
                new FieldMatch("TargetObject", FieldRegex(@"\\Explorer\\ShellSmartScreenLevel"), false),
                new FieldMatch("TargetObject", FieldRegex(@"\\System\\EnableSmartScreen"), false),
                new FieldMatch("TargetObject", FieldRegex(@"Policies\\Microsoft\\Windows Defender"), false),
            }),
        Cmd("Explorer killed",
            "Explorer forcibly terminated (often to apply shell/SmartScreen policy changes immediately)",
            Severity.Medium, @"taskkill\.exe", @"explorer\.exe"),

        // ---- Suspicious drops ----
        new("Executable dropped in user-writable path",
            "Executable or installer written to TEMP, Public, or Downloads",
            Severity.Medium, new[] { 11 }, null, null,
            new[] { new FieldMatch("TargetFilename", FieldRegex(@"\.(exe|msi|dll|scr|ps1|vbs|bat|cmd)$"), false) },
            new[]
            {
                new FieldMatch("TargetFilename", FieldRegex(@"\\AppData\\Local\\Temp\\"), false),
                new FieldMatch("TargetFilename", FieldRegex(@"\\Users\\Public\\"), false),
                new FieldMatch("TargetFilename", FieldRegex(@"\\Downloads\\"), false),
            }),
    };
}
