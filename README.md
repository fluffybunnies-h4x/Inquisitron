# Inquisitron

A real-time Sysmon log viewer and behavioral detection engine for Windows threat hunting.

## Why "Inquisitron"

Good threat hunting is fundamentally *inquisitive*. A hunter doesn't wait for an
alert to tell them what happened — they interrogate the telemetry, ask why a
process has the parent it does, and follow the answer to the next question. The
name is that habit, wearing a retro-futuristic `-tron` suffix: part Transformer,
part machine-that-inquires.

That's also the design brief. Event Viewer *displays* Sysmon logs. Inquisitron is
built to ask questions of them.

## What it does

Sysmon produces excellent telemetry and Event Viewer is a poor place to read it:
no live streaming, no process lineage, no way to pivot from an event to the rest
of its story, and no notion of which events deserve attention. Inquisitron
replaces it for the `Microsoft-Windows-Sysmon/Operational` channel with:

- **Push-based streaming.** An `EventLogWatcher` subscription, not polling —
  events appear the instant Sysmon writes them, batched into the UI 4×/second so
  a noisy config doesn't stutter the grid.
- **A behavioral detection engine.** Every event is scored against a rule set as
  it arrives. Matches are colored by severity and explained in plain language.
- **Process-tree reconstruction.** Parent→child lineage keyed by `ProcessGuid`,
  so PID reuse can't corrupt the tree.
- **Fast pivoting.** Per-column filters, right-click pivots on PID / PPID /
  process / event ID, and single-cell copy for moving an IOC into your notes.
- **Offline triage.** Load a saved `.evtx` and get the same parsing, scoring, and
  tree reconstruction as a live capture.

It runs as a single self-contained executable with no .NET install required.

## No network egress, by design

Inquisitron reads local event logs and writes local files. It makes **no
outbound network connections** — no telemetry, no cloud, no update checks. This
is deliberate and non-negotiable: the tool is pointed at endpoint telemetry from
potentially compromised hosts, and that data never leaves the analyst's machine.

A cloud AI chat feature was prototyped and deliberately removed for this reason.
If it ever returns, it will be a local open-weight model with no egress.

## Features

**Live capture**
- Push subscription with a 2,000-event history backfill on Start
- Keeps the most recent 50,000 events in memory, dropping the oldest
- Any event channel — the channel box is editable and pre-populated with Sysmon,
  PowerShell Operational, Defender, Task Scheduler, WMI-Activity, Security, System

**Reading events**
- Sysmon event IDs mapped to friendly names, with a one-line summary column that
  picks the most useful field per event type (command line, target file, DNS
  query name, destination IP, …)
- Detail pane: parsed field/value table plus pretty-printed raw XML
- Live process tree: terminated processes gray out; parents that started before
  the capture window appear as reconstructed `(not observed)` placeholders

**Pivoting and filtering**
- A filter box in every column header. Comma-separated terms, `!` prefix
  excludes — `chrome,!msedge` in Process, `!22` in ID to hide DNS queries. ID,
  PID and PPID match exactly; other columns are case-insensitive substring.
- Right-click any row: copy that cell, show process lineage, filter to this PID
  or PPID, filter/exclude this process or event ID
- Free-text search across all fields, event-type dropdown, and a
  **⚠ Flagged only** toggle
- **Show process lineage** walks the full ancestry chain with PIDs, command
  lines, exit status, and detection hits at each hop

**Detection**
- Every event scored on arrival; the most severe matching rule wins
- Four severities with row coloring — Critical ⛔, High ⚠, Medium ▲, Low •
- **⟳ Rules** reloads `suspicion-rules.json` and re-scores every loaded event in
  place, no restart. Edit → save → ⟳ is the rule-tuning loop.
- A regression test suite that replays synthesized kill chains against the real
  engine and the real rule file

**Output**
- Export the currently *visible* (filtered) events to CSV (grid columns + parent
  image + detection reason, Excel-friendly) or JSON (full EventData per event,
  ready for jq / pandas / SIEM ingestion)

## Detection rules

Rules live in `suspicion-rules.json` beside the executable (JSON with `//`
comments allowed). If the file is missing or malformed, the engine falls back to
built-in defaults and the status bar says which set loaded.

```jsonc
{
  "name": "Short label shown in the Detection column",
  "description": "Why it fired — tooltip, export, and analyst-facing text",
  "severity": "critical | high | medium | low",
  "eventIds": [1],                              // omit = all event IDs
  "parent": "regex on PARENT exe filename",     // anchored to the whole name
  "child":  "regex on CHILD/Image exe filename",
  "all": [ { "field": "CommandLine", "regex": "…", "not": false } ],  // all must match
  "any": [ { "field": "TargetObject", "regex": "…" } ]                // one must match
}
```

`field` is any Sysmon EventData field (`CommandLine`, `ParentCommandLine`,
`TargetFilename`, `TargetObject`, `DestinationIp`, `QueryName`,
`OriginalFileName`, `ImageLoaded`, …) plus the pseudo-fields `Image`,
`ImageName`, `ParentImage`, `ParentImageName`, and `"Any"` (searches every field
value — convenient for IOC sweeps, slower). Field regexes are substring matches;
`parent`/`child` regexes are anchored to the whole filename.

Rules are indexed by event ID at load, so scoping with `eventIds` keeps
500,000-event `.evtx` loads fast.

### Writing good rules

Lessons that cost real false positives:

- **Require a verb, not just a noun.** Matching the bare string `SmartScreen`
  flagged `smartscreen.exe -Embedding` — Windows starting its own SmartScreen
  host — on every boot. Require an actual registry-write verb alongside it.
- **Prefer `OriginalFileName` for LOLBin detection.** Comparing the PE's embedded
  `OriginalFileName` against the on-disk filename catches renamed `powershell`,
  `certutil`, `rundll32`. It's the highest-value generic rule in the set.
- **Don't flag what inventory scripts do.** A bare `Win32_ComputerSystem`
  Manufacturer/Model query looks like VM detection but is also what every asset
  inventory script runs. Match the comparison against a vendor string instead.
- **Watch the noise floor.** Run an idle box with **⚠ Flagged only** ticked.
  Anything that lights up with no sample running is a false positive.

### Campaign rule packs

The shipped rule set includes behavioral packs derived from published Securonix
Threat Research advisories:

- **[FAUX#ELEVATE](https://www.securonix.com/blog/faux-elevate-threat-actors-crypto-miners-and-infostealers/)**
  — French CV-lure VBS dropper with a WMI `PartOfDomain` gate that delivers its
  payload only to domain-joined enterprise hosts, then ChromElevator credential
  theft, SMTP exfiltration, and an XMRig miner that pauses on user activity.
- **[DEAD#VAX](https://www.securonix.com/blog/deadvax-threat-research-security-advisory/)**
  — IPFS-delivered VHD (a Mark-of-the-Web bypass by construction) → `.pdf.wsf`
  double-extension → obfuscated batch → a renamed copy of `powershell.exe`
  reading its payload back out of its own script file.

Campaign packs are a convenience, not the point. The generic behavioral rules —
abnormal parentage, LOLBin renaming, defense-evasion sequences, credential-store
access, container delivery, persistence — are what survive an actor rotating
infrastructure.

## Build

```
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -o publish
```

Produces a ~62 MB single-file executable that needs no .NET install. WPF's native
libraries are bundled into the exe (`IncludeNativeLibrariesForSelfExtract`) and
extracted to `%TEMP%\.net\Inquisitron\` on first launch — redirect that with
`DOTNET_BUNDLE_EXTRACT_BASE_DIR` if your environment blocks execution from TEMP.

Ship `suspicion-rules.json` alongside the exe. Without it the app runs, but only
on the built-in default rules.

Every build stamps a UTC timestamp into its product version, so a deployed copy
can always identify itself:

```powershell
(Get-Item Inquisitron.exe).VersionInfo.ProductVersion   # e.g. 1.1.1+build.20260801-2123
```

## Tests

```
dotnet run --project Tests/DetectionTests -c Release
```

Replays synthesized kill-chain events for each campaign against the real engine
source and the real rule file, probes every rule in isolation so an
overshadowed rule can't quietly die, and asserts a set of benign events stays
clean. Exit code 0 means all green. Run it after every rule or engine change.

## Requirements

- Windows 10/11
- .NET 10 SDK to build
- **Administrator rights** to read the Sysmon channel — its ACL grants read to
  Administrators only. The app manifest requests elevation automatically.
- Sysmon installed and configured (see below)

## Sysmon configuration

**Inquisitron is only as good as the telemetry underneath it.** Its rules span
event IDs 1 (process create), 3 (network), 6 (driver load), 7 (image load),
11 (file create), 12/13 (registry), 22 (DNS), and 23/26 (file delete) — a
config that only logs process creation leaves most of the rule set dormant and
the process tree half-built.

The recommended config is
**[FT-Sysmon-Config](https://github.com/fluffybunnies-h4x/FT-Sysmon-Config)**:

```
sysmon.exe -accepteula -i ft-sysmonconfig-export.xml
```

It's a [SwiftOnSecurity sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
fork maintained against live malware TTPs in a threat-research range, and it
turns on several things Inquisitron's rules specifically need:

| FT-Sysmon-Config change | Rules that depend on it |
| --- | --- |
| **Event ID 26 enabled** (file delete detected) | Installer and script self-deletion — the post-exploitation cleanup step in several campaigns. Not enabled in the stock upstream config. |
| **Image loads from AppData / Downloads / non-`C:` drives** | Kernel-driver and sideloaded-DLL rules, including the WinRing0 MSR driver cryptominers bundle |
| **Registry coverage for `reg.exe`, PowerShell, `C:\Users\Public`, AppData** | SmartScreen teardown, `EnableLUA=0`, Run-key persistence |
| **File creates in `ProgramData`, `Windows\Temp`, `.lnk` and `.url`** | Staging-directory drops, random-named script drops, shortcut delivery |
| **Named-pipe coverage, conhost exclusion removed** | Reduces blind spots around injected and hollowed processes |

Stock SwiftOnSecurity works fine as a baseline — rules keyed on
`OriginalFileName` need the `ProcessCreate` fields it already provides — but
expect the delete- and image-load-based rules to stay quiet until you enable
those events.

Whatever config you run, verify it against the noise floor: start a capture on
an idle machine with **⚠ Flagged only** ticked and confirm nothing lights up.

## Project layout

| File | Purpose |
| --- | --- |
| `Models/SysmonEvent.cs` | Parsed event model + Sysmon event ID catalog |
| `Models/ProcessNode.cs` | A process in the live tree |
| `Services/EventLogService.cs` | Backfill reader, `EventLogWatcher` subscription, `.evtx` file reader |
| `Services/SuspicionRules.cs` | Detection rule engine |
| `Services/ProcessTree.cs` | Parent→child tree keyed by `ProcessGuid` |
| `Services/Exporter.cs` | CSV / JSON export of the filtered view |
| `MainWindow.xaml(.cs)` | Dark-themed UI: virtualized grid, filters, tree tab, detail pane |
| `Tests/DetectionTests/` | Detection regression suite |
| `app.manifest` | Requests elevation |
| `suspicion-rules.json` | The live rule set |

## License

MIT — see [LICENSE](LICENSE).
