# DEAD#VAX demo station — Inquisitron setup

Detection rules built from the Securonix Threat Research DEAD#VAX advisory,
scoped to what is actually reproducible at the booth: the **VHD sample** and
**manual execution of the batch stage**.

Reload with **⟳ Rules** after copying the updated `suspicion-rules.json` — no
rebuild needed. Confirm the status bar reports rules loaded from
`suspicion-rules.json` rather than "built-in rules".

## ⚠️ Two things that will stop the chain on a demo VM

Read this before the booth opens — both are by design in the malware, and both
are recoverable.

**1. The batch detects VMware and exits.** Stage 3 runs
`Get-CimInstance Win32_ComputerSystem` and `Get-CimInstance Win32_BIOS` and
terminates if either matches `VMware`. If your demo VM is VMware, the chain dies
right there.

This is a feature, not a problem — *the detection still fires*. `DEAD#VAX: VM
detection via WMI` lights up Critical at the moment the malware checks, so the
demo beat becomes **"watch it look for the sandbox, find one, and quit"**, which
is a more interesting story than watching it succeed. If you want the chain to
continue past that point, run the later stages on bare metal or Hyper-V, or edit
the deobfuscated batch to skip the check.

**2. The memory floor is 3 GB.** The script exits with code 123 if
`TotalPhysicalMemory` is under `3221225472` bytes. Give the demo VM **at least
4 GB** or it terminates before anything interesting happens. (SMOKE#SCREEN's
`zoom-update.vbs` used a 2 GB floor for the same purpose — worth mentioning as
convergent tradecraft.)

## What fires, stage by stage

| Stage | Observable | Rule | Severity |
|---|---|---|---|
| Delivery | link to `*.ipfs.w3s.link`, CID starting `bafybei…` | DEAD#VAX: IPFS gateway delivery | Critical |
| Delivery | `PurchaseOrder_…_Docx.vhd` written to Downloads | Container image written to disk | Medium |
| Mount | Windows mounts the VHD as a new volume | Disk image mounted | High |
| Mount | `purchaseorder…pdf.wsf` — document extension followed by an executable one | DEAD#VAX: double-extension masquerade | Critical |
| Stage 2 | `.wsf` executed from the mounted volume | DEAD#VAX: WSF script execution | Critical |
| Stage 2 | anything running from `E:\` or another non-system letter | Script executed from mounted volume | Critical |
| Stage 2 | `Msxml2.DOMDocument.3.0` used to base64-decode | DEAD#VAX: MSXML base64 decoding | High |
| Stage 2 | hidden `%TEMP%\temp` created | DEAD#VAX: nested temp staging directory | High |
| Stage 2 | `MXVT60Xx6um7nRNl.bat` (random 16-char name) dropped | DEAD#VAX: random-named script dropped | High |
| Stage 3 | `net session` elevation probe; `%TEMP%\VBE` / `mapping.csv` checks | DEAD#VAX: analyst-environment check | High |
| Stage 3 | WMI query matching `VMware` | DEAD#VAX: VM detection via WMI | High |
| Stage 3 | `TotalPhysicalMemory` / `3221225472` | DEAD#VAX: sandbox memory check | High |
| Stage 3 | `rEgX.cmd` self-copy | DEAD#VAX: campaign artifact filename | Critical |
| Stage 3 | **`mbs.exe` — renamed `powershell.exe`** | DEAD#VAX: renamed LOLBin | Critical |
| Stage 3 | `Get-Content` pulling `@ ` lines out of the self-copy | DEAD#VAX: script self-read payload extraction | Critical |
| Stage 3 | `windows.dll` written (base64 text, not a library) | DEAD#VAX: campaign artifact filename | Critical |

Everything past this point depends on the dead C2, so it will not fire at the
booth — which is fine, because the loader mechanics above are the interesting
half anyway.

## The three moments worth narrating

**Mark-of-the-Web evaporating.** Download the VHD and show its `Zone.Identifier`
stream exists. Mount it, and show the `.wsf` inside has none. Same bytes, same
machine, no prompt. This is the whole reason the campaign uses a container, and
it lands better demonstrated than described.

**The renamed LOLBin.** `mbs.exe` is a byte-identical copy of `powershell.exe`
with a different name. Any detection keyed on the string "powershell" misses it
completely. Inquisitron catches it by comparing the PE's embedded
`OriginalFileName` (still `PowerShell.EXE`) against the filename on disk — they
disagree, so it fires. **This rule is campaign-independent** and one of the
highest-value detections in the whole set; it catches renamed `certutil`,
`rundll32`, `mshta`, `regsvr32`, and the rest for free.

> Requires Sysmon to log `OriginalFileName`, which is included in ProcessCreate
> by default on Sysmon 10 and later. If this rule never fires when you know
> `mbs.exe` ran, check that field is present in your event XML — the Fields tab
> on any Event ID 1 row will tell you immediately.

**Steganography in plain sight.** The batch copies itself to `rEgX.cmd`, then
uses PowerShell to read *itself* line by line, pull out the lines beginning with
`@ `, and write them to `windows.dll`. The payload was never a separate file — it
was sitting in the comment lines of the script the whole time. Show the tail of
`rEgX.cmd` next to the flagged `Get-Content` event.

## Cross-campaign comparison

If both demos run at the same station, the shared tradecraft is worth drawing out
— it makes the case for behavioral detection better than either campaign alone:

| Technique | SMOKE#SCREEN | DEAD#VAX |
|---|---|---|
| Sandbox memory floor | 2 GB (`zoom-update.vbs`) | 3 GB (batch stage) |
| Analyst-tool evasion | process blacklist: wireshark, procmon, vmtoolsd… | username `admin`, `VBE`, `mapping.csv` |
| MotW bypass | `Unlock-File` strips `Zone.Identifier` | container mount — never acquires one |
| Trusted-host delivery | Dropbox, Cloudflare Quick Tunnel | IPFS via w3s.link |
| Payload masquerade | `WindowsExplorerSupport.msi` | `windows.dll` (text), `.pdf.wsf` |
| LOLBin abuse | `Add-Type` in-memory C# compile | `mbs.exe` renamed PowerShell |
| Obfuscation | XOR + hex, VBScript state machine | rolling XOR + MSXML base64, thousands of batch SET vars |

Two unrelated actors, same playbook: get a container or a signed binary past the
gateway, check for analysts, strip or avoid MotW, then execute through a trusted
Windows binary. None of it is caught by hashes — every rule here is behavioral.

## Sysmon config

These rules need event IDs **1** (process create, with `OriginalFileName`), **3**
(network), **11** (file create), **12/13** (registry), **22** (DNS), **23/26**
(file delete). SwiftOnSecurity's `sysmon-config` filters DNS and network heavily
and excludes many file-create paths — loosen those sections or the IPFS, mount,
and drop rules will stay quiet. File-delete events are off in most configs.
