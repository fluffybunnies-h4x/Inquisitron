# SMOKE#SCREEN demo station — Inquisitron setup

Detection rules built from the Securonix Threat Research advisory
*"Analyzing SMOKE#SCREEN: Threat Actors Abuse Trusted Software Lures and Cloudflare
Tunnels to Deploy ScreenConnect RMM Agents Across Windows and macOS"* (July 28, 2026),
scoped to the two samples being detonated at the demo station: **zoom-update.vbs**
and **SystemCheck**.

## ⚠️ Before the conference — verify the build

The rule engine was rewritten and these rules written in a session that lost the
ability to run commands partway through, so **the build and the detection tests
have not been run since the final edits**. Do this first:

```bash
dotnet publish "C:\Users\user\Documents\Null-Sec\Inquisitron\Inquisitron.csproj" -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -o "C:\Users\user\Documents\Null-Sec\Inquisitron\publish"
```

Then launch Inquisitron and confirm the status bar after clicking **⟳ Rules** reads
`36 rules from suspicion-rules.json`. Two failure messages to watch for:

- *"built-in rules (suspicion-rules.json invalid: …)"* — JSON syntax error; the
  message names the parse problem.
- *"NO RULES ACTIVE — rule engine failed to load: …"* — a built-in rule has a bad
  regex. Report the message; the app still runs, just without detections.

If the app fails to start at all, it now writes the exception to
`%TEMP%\Inquisitron-crash.log` and shows it in a dialog rather than exiting
silently.

## What fires, stage by stage

### zoom-update.vbs (XOR-encrypted VBScript dropper)

| Stage | Observable | Rule | Severity |
|---|---|---|---|
| Initial access | `wscript.exe` runs a `.vbs` from Downloads | SMOKE#SCREEN: VBScript launched from user-writable path | High |
| Decrypted payload exec | `wscript.exe` → hidden `powershell.exe` | SMOKE#SCREEN: VBScript dropper spawned PowerShell | Critical |
| In-memory compile | `Add-Type -Language CSharp`, `[HelloWorld.Program]::SayHello()` | SMOKE#SCREEN: in-memory C# compile | Critical |
| Staging path | URL containing `/Bin/` | SMOKE#SCREEN: /Bin/ staging path | Critical |
| C# source fetch | connect to `207.189.11.170` | SMOKE#SCREEN: C2 network connection | Critical |
| Payload install | `msiexec … /qn` from TEMP | SMOKE#SCREEN: silent MSI install | Critical |
| RMM beacon | connect to `207.174.0.143:8041` | SMOKE#SCREEN: C2 network connection | Critical |
| RMM config | `e=Access&y=Guest` | SMOKE#SCREEN: ScreenConnect guest-access install | Critical |

The script's WMI anti-analysis checks (`Win32_ComputerSystem` memory test,
`Win32_Process` blacklist of wireshark/procmon/vboxservice/vmtoolsd/xenservice/fiddler)
happen **inside** the script and create no child process, so Sysmon does not see them.
Worth calling out at the demo as a visibility gap — the evasion is invisible to
process telemetry, which is exactly why the actor put it there.

### SystemCheck (security-killing batch file)

| Stage | Observable | Rule | Severity |
|---|---|---|---|
| 1 — AMSI bypass | `amsiInitFailed` / `AmsiUtils` reflection | SMOKE#SCREEN: AMSI bypass | Critical |
| 2 — UAC elevation | `-Verb RunAs` | SMOKE#SCREEN: UAC self-elevation | High |
| 3 — SmartScreen | registry write to `EnableSmartScreen` / `ShellSmartScreenLevel` (Event 13) | SMOKE#SCREEN: SmartScreen disabled | Critical |
| 3 — Explorer restart | `taskkill /f /im explorer.exe` | SMOKE#SCREEN: Explorer restarted to apply policy | High |
| 4 — Defender | `Add-MpPreference -ExclusionPath` | SMOKE#SCREEN: Defender exclusion added | Critical |
| 4 — Masquerade | `WindowsExplorerSupport.msi` written to TEMP | SMOKE#SCREEN: SystemCheck masquerade filename | Critical |
| 5 — MotW strip | `Unlock-File` / `Zone.Identifier` | SMOKE#SCREEN: Mark-of-the-Web stripped | Critical |
| 5 — Install | `msiexec … /qn` | SMOKE#SCREEN: silent MSI install | Critical |
| 5 — Cleanup | MSI deleted from TEMP (Event 23/26) | SMOKE#SCREEN: installer self-delete | High |

The `MemoryLoader.cs`-derived EXEs (`AdobeReader_Update.exe`, `lirMkvpf.exe`,
`NYbiLtvO.exe`) are covered too — the drive-root exclusion and WinDefend-kill rules
catch the nine-step Defender destruction sequence that the advisory clocks at
under 15 seconds.

## Driving the demo

**Filter to the story.** Type `SMOKE` into the **Detection** column filter and the
grid collapses to just campaign hits. Or tick **⚠ Flagged only** for everything the
rule set caught, campaign or not.

**Severity reads at a glance** from across the booth:

| | |
|---|---|
| ⛔ Critical | deep red row |
| ⚠ High | orange row |
| ▲ Medium | amber row |
| • Low | slate row |

**Show lineage.** Right-click any flagged event → **Show process lineage** to walk
`explorer.exe → wscript.exe → powershell.exe → msiexec.exe` with command lines at
each hop. The **Process Tree** tab shows the same thing live as the sample runs.

**Live rule editing is the best moment.** Delete a rule from
`publish\suspicion-rules.json`, click **⟳ Rules**, and watch detections disappear
from already-captured events; paste it back, click again, and they light up. No
restart, no re-running the sample. That makes the point about behavioral vs
signature detection better than any slide.

**Export** hands an attendee the evidence: filter to flagged, **Export…** → CSV now
carries Severity and Detection columns.

## Tuning notes

### Fixed after first live run

- **`SmartScreen disabled via reg.exe`** matched the bare string "SmartScreen" on any
  process create, which flagged `C:\Windows\System32\smartscreen.exe -Embedding` —
  Windows starting its own SmartScreen host via COM, on every boot. Now requires the
  child to be `reg`/`powershell`/`cmd` **and** the command line to contain an actual
  registry-write verb (`reg add`, `Set-ItemProperty`, …). Renamed to
  *SmartScreen disabled via command line*.
- **`Installer dropped in user-writable path`** no longer matches `.dll` — legitimate
  software writes DLLs to TEMP constantly. Now covers exe/msi/scr/ps1/vbs/bat/cmd/gzip
  plus vhd/vhdx/iso/lnk (container-file delivery).

### Still expect noise from these

| Rule | Why it fires legitimately |
|---|---|
| `Hidden-window PowerShell` (Medium) | Installers, Chocolatey, and management agents routinely use `-nop -w hidden` |
| `Shell spawned msiexec silently` (High) | SCCM / Intune / Chocolatey software deployment looks identical |
| `UAC self-elevation` (High) | Any well-behaved installer asking for admin |
| `Unauthorized RMM agent` (High) | Fires if your org legitimately runs AnyDesk/TeamViewer/Atera |
| `Defender exclusion added` (Critical) | Admins add exclusions for real reasons — but you *want* to see this in a hunt |

### The tuning loop

This is worth doing on the demo box before the conference, and it doubles as a
demo in itself: run the machine idle for a few minutes, tick **⚠ Flagged only**,
and anything that lights up with no sample running is a false positive. Edit
`publish\suspicion-rules.json` — delete the rule, tighten its regex, or drop its
severity — then click **⟳ Rules** and the already-captured events re-score in place.
No restart, no re-run.
- **Rules are evaluated most-severe-first**, so a campaign rule at Critical wins over
  a generic rule at High on the same event. That is why the Detection column shows the
  SMOKE#SCREEN name rather than a generic one on the shared steps.
- **`Any` as a field name** searches every EventData value — useful for IOC sweeps,
  slower than naming a specific field. The campaign filename rule uses it deliberately.

## Sysmon config

The rules need Sysmon logging these event IDs: **1** (process create), **3** (network),
**11** (file create), **12/13** (registry), **22** (DNS), **23/26** (file delete).
SwiftOnSecurity's `sysmon-config` covers 1/3/11/12/13/22 but **filters DNS and network
heavily** — for the demo, loosen the network and DNS sections or the C2 rules will stay
quiet. Event 23/26 (file delete) is off by default in most configs; enable it or the
installer self-delete rule never fires.
