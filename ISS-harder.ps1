#requires -version 5.1
<#
IIS-Hardener-GUI.ps1
- GUI to assess + harden IIS, check patch status, and enable safe monitoring.
- Makes an IIS config backup before applying changes.
- Adds a Backups tab for restore workflow.

Notes:
- Some headers (especially CSP / HSTS / X-Frame-Options) can break apps. Keep them optional.
- Removing the "Server:" header is best done at the reverse proxy/WAF edge.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ----------------------------
# Globals / Logging
# ----------------------------
$AppName   = "IIS Hardener (GUI)"
$BaseDir   = Join-Path $env:ProgramData "IISHardener"
$LogDir    = Join-Path $BaseDir "Logs"
$ReportDir = Join-Path $BaseDir "Reports"
New-Item -ItemType Directory -Force -Path $LogDir, $ReportDir | Out-Null

function New-RunStamp { Get-Date -Format "yyyyMMdd_HHmmss_fff" }

$RunStamp  = New-RunStamp
$LogFile   = Join-Path $LogDir "IISHardener_$RunStamp.log"

try {
    Start-Transcript -Path $LogFile -Append | Out-Null
} catch {
    # Transcript can fail in constrained hosts. Keep app usable anyway.
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-AdminOrContinue {
    if (Test-IsAdmin) { return $true }

    $msg = "Not running as Administrator. Assessment may work, but hardening actions usually fail.`r`n`r`nDo you want to relaunch as Administrator?"
    $res = [System.Windows.Forms.MessageBox]::Show($msg, $AppName, [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)

    if ($res -eq [System.Windows.Forms.DialogResult]::Yes) {
        if ([string]::IsNullOrWhiteSpace($PSCommandPath) -or -not (Test-Path $PSCommandPath)) {
            [System.Windows.Forms.MessageBox]::Show("Cannot relaunch because PSCommandPath is not available. Save the script to a file and run it.", $AppName,
                [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
            return $false
        }

        $args = @(
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", "`"$PSCommandPath`""
        )
        Start-Process -FilePath "powershell.exe" -ArgumentList $args -Verb RunAs | Out-Null
        return $false
    }

    return $true
}

function Write-Ui {
    param(
        [Parameter(Mandatory)] [string] $Message,
        [ValidateSet("INFO","OK","WARN","ERR")] [string] $Level = "INFO"
    )

    $prefix = switch ($Level) {
        "OK"   { "[OK ]" }
        "WARN" { "[WARN]" }
        "ERR"  { "[ERR]" }
        default{ "[INFO]" }
    }

    $line = "{0} {1}" -f $prefix, $Message

    if (-not $script:OutputBox -or $script:OutputBox.IsDisposed) { return }

    if ($script:OutputBox.InvokeRequired) {
        $del = [Action[string]]{
            param($t)
            $script:OutputBox.AppendText($t + [Environment]::NewLine)
            $script:OutputBox.ScrollToCaret()
        }
        $null = $script:OutputBox.BeginInvoke($del, $line)
        return
    }

    $script:OutputBox.AppendText($line + [Environment]::NewLine)
    $script:OutputBox.ScrollToCaret()
}

function Set-UiBusy {
    param([bool]$Busy)

    if (-not $script:Form -or $script:Form.IsDisposed) { return }

    $script:Form.UseWaitCursor = $Busy
    foreach ($c in @($script:BtnAssess,$script:BtnExport,$script:BtnInetMgr,$script:BtnApply,$script:BtnClear,$script:BtnBkRefresh,$script:BtnBkRestore)) {
        if ($c) { $c.Enabled = -not $Busy }
    }
}

function Invoke-Safe {
    param(
        [Parameter(Mandatory)] [scriptblock] $ScriptBlock,
        [string] $Description = "Action"
    )
    try {
        Write-Ui "$Description..." "INFO"
        & $ScriptBlock
        Write-Ui "$Description: done." "OK"
        return $true
    } catch {
        Write-Ui "$Description: $($_.Exception.Message)" "ERR"
        return $false
    }
}

function Get-AppCmdPath {
    $p = Join-Path $env:windir "System32\inetsrv\appcmd.exe"
    if (Test-Path $p) { return $p }
    return $null
}

function Test-IISInstalled {
    $appcmdOk = Test-Path (Join-Path $env:windir "System32\inetsrv\appcmd.exe")
    if (-not $appcmdOk) { return $false }
    $w3 = Get-Service -Name W3SVC -ErrorAction SilentlyContinue
    return ($null -ne $w3)
}

function Import-IISModule {
    if (Get-Module -ListAvailable -Name WebAdministration) {
        Import-Module WebAdministration -ErrorAction Stop
        return $true
    }
    return $false
}

function Normalize-Url {
    param([string]$Url)
    $u = ($Url ?? "").Trim()
    if ([string]::IsNullOrWhiteSpace($u)) { return $null }

    if ($u -notmatch '^\w+://') {
        # default to https
        $u = "https://$u"
    }

    try {
        $uri = [Uri]$u
        if ($uri.Scheme -notin @("http","https")) { throw "Only http/https supported." }
        return $uri.AbsoluteUri
    } catch {
        throw "Invalid URL: $u"
    }
}

# ----------------------------
# Assessment
# ----------------------------
function Get-PatchStatus {
    $ci = Get-ComputerInfo

    $hotfix = @()
    try {
        $hotfix = @(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 12)
    } catch {
        # Some systems restrict Get-HotFix. Keep report usable.
        $hotfix = @()
    }

    $pendingReboot = $false
    $rebootKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    )
    foreach ($k in $rebootKeys) {
        if (Test-Path $k) {
            if ($k -like "*Session Manager") {
                $v = (Get-ItemProperty -Path $k -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
                if ($null -ne $v) { $pendingReboot = $true }
            } else {
                $pendingReboot = $true
            }
        }
    }

    $wua = Get-Service -Name wuauserv -ErrorAction SilentlyContinue

    [pscustomobject]@{
        ComputerName     = $env:COMPUTERNAME
        OSName           = $ci.WindowsProductName
        OSVersion        = $ci.WindowsVersion
        OSBuild          = $ci.OsBuildNumber
        UBR             = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue).UBR
        PendingReboot    = $pendingReboot
        WindowsUpdateSvc = if ($wua) { "$($wua.Status) (StartType: $($wua.StartType))" } else { "Not found" }
        RecentHotfixes   = $hotfix
    }
}

function Get-IISInventory {
    $appcmd = Get-AppCmdPath
    if (-not $appcmd) { throw "IIS appcmd.exe not found. IIS may not be installed." }

    $iisInfo = [ordered]@{}
    $iisInfo.AppCmd = $appcmd

    $isModOk = Import-IISModule
    $iisInfo.WebAdminModule = $isModOk

    if ($isModOk) {
        $iisInfo.Sites = Get-Website | Select-Object Name, State, PhysicalPath, @{
            n="Bindings";e={(Get-WebBinding -Name $_.Name | ForEach-Object { "$($_.protocol)://$($_.bindingInformation)" }) -join "; "}
        }
        $iisInfo.AppPools = Get-WebAppPoolState -Name * | Select-Object Name, Value
        $iisInfo.Modules  = Get-WebGlobalModule | Select-Object Name, Image
        $iisInfo.FeaturesHint = "Use Server Manager / Windows Features to confirm role services."
    } else {
        $iisInfo.Sites = @()
        $iisInfo.AppPools = @()
        $iisInfo.Modules = @()
        $iisInfo.FeaturesHint = "WebAdministration module not available. Install IIS Management Scripts and Tools."
    }

    $risky = New-Object System.Collections.Generic.List[string]
    $modNames = @($iisInfo.Modules | ForEach-Object { $_.Name })
    if ($modNames -contains "WebDavModule") { $risky.Add("WebDAV module detected (disable if not needed).") }
    if ($modNames -contains "CgiModule")   { $risky.Add("CGI module detected (ensure locked down).") }
    if ($modNames -contains "IsapiModule") { $risky.Add("ISAPI module detected (ensure only required extensions enabled).") }

    $iisInfo.RiskFlags = $risky.ToArray()
    return [pscustomobject]$iisInfo
}

function Test-SecurityHeaders {
    param([string]$Url)

    $u = Normalize-Url -Url $Url
    if (-not $u) { throw "URL is empty." }

    # Allow redirects so we can see headers on the final target in common cases.
    $resp = Invoke-WebRequest -Uri $u -Method Head -UseBasicParsing -MaximumRedirection 5 -ErrorAction SilentlyContinue
    if (-not $resp) {
        $resp = Invoke-WebRequest -Uri $u -Method Get -UseBasicParsing -MaximumRedirection 5
    }

    $h = $resp.Headers
    $interesting = @(
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Content-Security-Policy",
        "Permissions-Policy",
        "Server",
        "X-Powered-By"
    )

    $out = [ordered]@{}
    foreach ($k in $interesting) {
        $out[$k] = if ($h[$k]) { $h[$k] } else { "(missing)" }
    }
    return [pscustomobject]$out
}

# ----------------------------
# Hardening helpers
# ----------------------------
function Backup-IISConfig {
    $appcmd = Get-AppCmdPath
    if (-not $appcmd) { throw "appcmd.exe not found." }

    $name = "IISHardener_$(New-RunStamp)"
    & $appcmd add backup $name | Out-Null
    return $name
}

function Get-IISBackups {
    $appcmd = Get-AppCmdPath
    if (-not $appcmd) { throw "appcmd.exe not found." }

    # appcmd supports: list backup / restore backup "Name" :contentReference[oaicite:1]{index=1}
    $out = & $appcmd list backup 2>$null
    if (-not $out) { return @() }

    $names = foreach ($line in $out) {
        if ($line -match 'BACKUP\s+"(?<name>[^"]+)"') {
            $Matches["name"]
        }
    }

    return @($names | Sort-Object -Unique)
}

function Restore-IISBackup {
    param([Parameter(Mandatory)][string]$Name)

    $appcmd = Get-AppCmdPath
    if (-not $appcmd) { throw "appcmd.exe not found." }

    & $appcmd restore backup "$Name" | Out-Null
}

function Remove-CustomHeaderGlobal {
    param([Parameter(Mandatory)][string]$Name)
    if (-not (Import-IISModule)) { throw "WebAdministration module not available." }
    try {
        Remove-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" `
          -Filter "system.webServer/httpProtocol/customHeaders" `
          -Name "." -AtElement @{ name = $Name } -ErrorAction Stop
    } catch {
        # ignore if not present
    }
}

function Ensure-CustomHeaderGlobal {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value
    )
    if (-not (Import-IISModule)) { throw "WebAdministration module not available." }

    try {
        Remove-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" `
          -Filter "system.webServer/httpProtocol/customHeaders" `
          -Name "." -AtElement @{ name = $Name } -ErrorAction SilentlyContinue
    } catch {}

    Add-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" `
      -Filter "system.webServer/httpProtocol/customHeaders" `
      -Name "." -Value @{ name = $Name; value = $Value } | Out-Null
}

function Set-DirectoryBrowsingOffGlobal {
    if (-not (Import-IISModule)) { throw "WebAdministration module not available." }
    Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" `
      -Filter "system.webServer/directoryBrowse" -Name enabled -Value $false
}

function Deny-VerbGlobal {
    param([Parameter(Mandatory)][string]$Verb)
    if (-not (Import-IISModule)) { throw "WebAdministration module not available." }
    $filter = "system.webServer/security/requestFiltering/verbs"
    $existing = Get-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter $filter -Name "." |
        Where-Object { $_.verb -eq $Verb }
    if (-not $existing) {
        Add-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter $filter -Name "." `
          -Value @{ verb = $Verb; allowed = $false } | Out-Null
    }
}

function Set-RequestLimitsGlobal {
    param(
        [int]$MaxAllowedContentLengthBytes = 30000000,
        [int]$MaxUrl = 4096,
        [int]$MaxQueryString = 2048
    )
    if (-not (Import-IISModule)) { throw "WebAdministration module not available." }

    Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" `
      -Filter "system.webServer/security/requestFiltering/requestLimits" `
      -Name maxAllowedContentLength -Value $MaxAllowedContentLengthBytes

    Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" `
      -Filter "system.webServer/security/requestFiltering/requestLimits" `
      -Name maxUrl -Value $MaxUrl

    Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" `
      -Filter "system.webServer/security/requestFiltering/requestLimits" `
      -Name maxQueryString -Value $MaxQueryString
}

function Add-HiddenSegmentsGlobal {
    param([string[]]$Segments = @("bin","App_Data","App_Code",".git",".svn"))
    if (-not (Import-IISModule)) { throw "WebAdministration module not available." }
    $filter = "system.webServer/security/requestFiltering/hiddenSegments"
    $existing = Get-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter $filter -Name "." | ForEach-Object { $_.segment }

    foreach ($s in $Segments) {
        if ($existing -notcontains $s) {
            Add-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter $filter -Name "." `
              -Value @{ segment = $s } | Out-Null
        }
    }
}

function Ensure-IISW3CLoggingBasics {
    if (-not (Import-IISModule)) { throw "WebAdministration module not available." }

    Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" `
      -Filter "system.applicationHost/sites/siteDefaults/logFile" `
      -Name logFormat -Value "W3C"

    $appcmd = Get-AppCmdPath
    if ($appcmd) {
        & $appcmd set config -section:system.applicationHost/sites `
          "/siteDefaults.logFile.directory:`"%SystemDrive%\inetpub\logs\LogFiles`"" `
          "/commit:apphost" | Out-Null
    }
}

function Enable-IISRelatedEventLogs {
    $channels = @(
        "Microsoft-Windows-IIS-Configuration/Operational",
        "Microsoft-Windows-IIS-Logging/Logs",
        "Microsoft-Windows-HttpEvent/Operational",
        "Microsoft-Windows-HttpService/Trace"
    )
    foreach ($c in $channels) {
        try { & wevtutil sl $c /e:true 2>$null } catch {}
    }
}

# ----------------------------
# Report generation
# ----------------------------
function New-AssessmentReport {
    param(
        [pscustomobject]$Patch,
        [pscustomobject]$IIS,
        [pscustomobject]$HeaderCheck
    )

    $html = @()
    $html += "<html><head><meta charset='utf-8'><title>$AppName Report</title>"
    $html += "<style>body{font-family:Segoe UI,Arial;margin:20px} h2{margin-top:28px} code,pre{background:#f5f5f5;padding:8px;display:block}</style>"
    $html += "</head><body>"
    $html += "<h1>$AppName Report</h1>"
    $html += "<p><b>Generated:</b> $(Get-Date)</p>"

    $html += "<h2>Patch status</h2>"
    $html += "<ul>"
    $html += "<li><b>OS:</b> $($Patch.OSName) (Version $($Patch.OSVersion), Build $($Patch.OSBuild), UBR $($Patch.UBR))</li>"
    $html += "<li><b>Pending reboot:</b> $($Patch.PendingReboot)</li>"
    $html += "<li><b>Windows Update service:</b> $($Patch.WindowsUpdateSvc)</li>"
    $html += "</ul>"

    $html += "<h3>Recent hotfixes</h3><pre>"
    foreach ($hf in ($Patch.RecentHotfixes ?? @())) {
        $dt = if ($hf.InstalledOn) { $hf.InstalledOn.ToString("yyyy-MM-dd") } else { "unknown" }
        $html += ("{0,-12} {1,-12} {2}" -f $hf.HotFixID, $dt, $hf.Description)
    }
    $html += "</pre>"

    $html += "<h2>IIS inventory</h2>"
    $html += "<p><b>WebAdministration module:</b> $($IIS.WebAdminModule)</p>"

    if (($IIS.Sites ?? @()).Count -gt 0) {
        $html += "<h3>Sites</h3><pre>"
        foreach ($s in $IIS.Sites) {
            $html += "$($s.Name) | $($s.State) | $($s.PhysicalPath)"
            $html += "  Bindings: $($s.Bindings)"
        }
        $html += "</pre>"
    }

    if (($IIS.RiskFlags ?? @()).Count -gt 0) {
        $html += "<h3>Risk flags</h3><ul>"
        foreach ($r in $IIS.RiskFlags) { $html += "<li>$r</li>" }
        $html += "</ul>"
    } else {
        $html += "<h3>Risk flags</h3><p>(none detected from global modules)</p>"
    }

    if ($HeaderCheck) {
        $html += "<h2>HTTP security header check</h2><pre>"
        $HeaderCheck.PSObject.Properties | ForEach-Object {
            $html += ("{0}: {1}" -f $_.Name, $_.Value)
        }
        $html += "</pre>"
    }

    $html += "<h2>Reverse proxy / WAF guidance</h2>"
    $html += "<ul>"
    $html += "<li>Strip/overwrite inbound <b>X-Forwarded-For</b>, <b>X-Forwarded-Proto</b>, <b>X-Real-IP</b> at the edge proxy so clients cannot spoof them.</li>"
    $html += "<li>Prefer removing the <b>Server</b> header at the edge (WAF/CDN/proxy). IIS itself is limited here.</li>"
    $html += "<li>Enable rate limiting, bot protection, and managed OWASP rule sets on your WAF when possible.</li>"
    $html += "</ul>"

    $html += "</body></html>"
    return ($html -join "`r`n")
}

# ----------------------------
# GUI
# ----------------------------
[System.Windows.Forms.Application]::EnableVisualStyles()

$script:Form = New-Object System.Windows.Forms.Form
$script:Form.Text = $AppName
$script:Form.Size = New-Object System.Drawing.Size(980, 720)
$script:Form.StartPosition = "CenterScreen"

$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Dock = "Fill"

# --- Tab: Run
$tabMain = New-Object System.Windows.Forms.TabPage
$tabMain.Text = "Run"

$panelTop = New-Object System.Windows.Forms.Panel
$panelTop.Dock = "Top"
$panelTop.Height = 170

$lblTarget = New-Object System.Windows.Forms.Label
$lblTarget.Text = "Optional URL to check headers (example: https://your-site/):"
$lblTarget.AutoSize = $true
$lblTarget.Location = New-Object System.Drawing.Point(12, 14)

$txtUrl = New-Object System.Windows.Forms.TextBox
$txtUrl.Width = 640
$txtUrl.Location = New-Object System.Drawing.Point(12, 38)

$script:BtnAssess = New-Object System.Windows.Forms.Button
$script:BtnAssess.Text = "Run Assessment"
$script:BtnAssess.Width = 160
$script:BtnAssess.Location = New-Object System.Drawing.Point(12, 78)

$script:BtnExport = New-Object System.Windows.Forms.Button
$script:BtnExport.Text = "Export HTML Report"
$script:BtnExport.Width = 160
$script:BtnExport.Location = New-Object System.Drawing.Point(184, 78)

$script:BtnInetMgr = New-Object System.Windows.Forms.Button
$script:BtnInetMgr.Text = "Open IIS Manager"
$script:BtnInetMgr.Width = 160
$script:BtnInetMgr.Location = New-Object System.Drawing.Point(356, 78)

$chkBackup = New-Object System.Windows.Forms.CheckBox
$chkBackup.Text = "Backup IIS config before changes (recommended)"
$chkBackup.Checked = $true
$chkBackup.AutoSize = $true
$chkBackup.Location = New-Object System.Drawing.Point(12, 122)

$panelTop.Controls.AddRange(@($lblTarget,$txtUrl,$script:BtnAssess,$script:BtnExport,$script:BtnInetMgr,$chkBackup))

$script:OutputBox = New-Object System.Windows.Forms.RichTextBox
$script:OutputBox.Dock = "Fill"
$script:OutputBox.Font = New-Object System.Drawing.Font("Consolas", 10)
$script:OutputBox.ReadOnly = $true

$tabMain.Controls.Add($script:OutputBox)
$tabMain.Controls.Add($panelTop)

# --- Tab: Hardening
$tabHard = New-Object System.Windows.Forms.TabPage
$tabHard.Text = "Hardening"

$hardList = New-Object System.Windows.Forms.CheckedListBox
$hardList.Dock = "Fill"
$hardList.CheckOnClick = $true

$hardActions = [ordered]@{
    "Disable directory browsing (global)" = { Set-DirectoryBrowsingOffGlobal }
    "Remove 'X-Powered-By' header (global)" = { Remove-CustomHeaderGlobal -Name "X-Powered-By" }
    "Add basic security headers (global)" = {
        Ensure-CustomHeaderGlobal -Name "X-Content-Type-Options" -Value "nosniff"
        Ensure-CustomHeaderGlobal -Name "X-Frame-Options" -Value "DENY"
        Ensure-CustomHeaderGlobal -Name "Referrer-Policy" -Value "no-referrer"
        Ensure-CustomHeaderGlobal -Name "Permissions-Policy" -Value "geolocation=(), microphone=(), camera=()"
    }
    "Deny HTTP TRACE/TRACK (global)" = {
        Deny-VerbGlobal -Verb "TRACE"
        Deny-VerbGlobal -Verb "TRACK"
    }
    "Set sane request limits (global)" = { Set-RequestLimitsGlobal -MaxAllowedContentLengthBytes 30000000 -MaxUrl 4096 -MaxQueryString 2048 }
    "Hide common sensitive segments (global)" = { Add-HiddenSegmentsGlobal }
    "Ensure IIS W3C logging basics (global)" = { Ensure-IISW3CLoggingBasics }
    "Enable IIS-related Windows Event Logs" = { Enable-IISRelatedEventLogs }
}

# Safer defaults: pre-check low break-risk items, leave headers unchecked.
$recommendedChecked = @(
    "Disable directory browsing (global)",
    "Remove 'X-Powered-By' header (global)",
    "Deny HTTP TRACE/TRACK (global)",
    "Set sane request limits (global)",
    "Hide common sensitive segments (global)",
    "Ensure IIS W3C logging basics (global)",
    "Enable IIS-related Windows Event Logs"
)

foreach ($k in $hardActions.Keys) {
    $isChecked = $recommendedChecked -contains $k
    [void]$hardList.Items.Add($k, $isChecked)
}

$panelHardBottom = New-Object System.Windows.Forms.Panel
$panelHardBottom.Dock = "Bottom"
$panelHardBottom.Height = 70

$script:BtnApply = New-Object System.Windows.Forms.Button
$script:BtnApply.Text = "Apply Selected"
$script:BtnApply.Width = 160
$script:BtnApply.Location = New-Object System.Drawing.Point(12, 18)

$script:BtnClear = New-Object System.Windows.Forms.Button
$script:BtnClear.Text = "Clear Output"
$script:BtnClear.Width = 160
$script:BtnClear.Location = New-Object System.Drawing.Point(184, 18)

$panelHardBottom.Controls.AddRange(@($script:BtnApply,$script:BtnClear))
$tabHard.Controls.Add($hardList)
$tabHard.Controls.Add($panelHardBottom)

# --- Tab: Backups
$tabBk = New-Object System.Windows.Forms.TabPage
$tabBk.Text = "Backups"

$bkPanelTop = New-Object System.Windows.Forms.Panel
$bkPanelTop.Dock = "Top"
$bkPanelTop.Height = 60

$script:BtnBkRefresh = New-Object System.Windows.Forms.Button
$script:BtnBkRefresh.Text = "Refresh"
$script:BtnBkRefresh.Width = 160
$script:BtnBkRefresh.Location = New-Object System.Drawing.Point(12, 14)

$script:BtnBkRestore = New-Object System.Windows.Forms.Button
$script:BtnBkRestore.Text = "Restore Selected"
$script:BtnBkRestore.Width = 160
$script:BtnBkRestore.Location = New-Object System.Drawing.Point(184, 14)

$bkPanelTop.Controls.AddRange(@($script:BtnBkRefresh,$script:BtnBkRestore))

$bkList = New-Object System.Windows.Forms.ListBox
$bkList.Dock = "Fill"

$bkHint = New-Object System.Windows.Forms.Label
$bkHint.Dock = "Bottom"
$bkHint.Height = 52
$bkHint.Text = "Restore uses appcmd restore backup ""Name"". Test in staging if possible. Restoring rewinds IIS config."
$bkHint.Padding = New-Object System.Windows.Forms.Padding(12,8,12,8)

$tabBk.Controls.Add($bkList)
$tabBk.Controls.Add($bkPanelTop)
$tabBk.Controls.Add($bkHint)

# Add tabs
$tabs.TabPages.AddRange(@($tabMain,$tabHard,$tabBk))
$script:Form.Controls.Add($tabs)

# ----------------------------
# Button wiring
# ----------------------------
$script:LastPatch = $null
$script:LastIIS   = $null
$script:LastHdr   = $null

$script:BtnInetMgr.Add_Click({
    try {
        if (Get-Command inetmgr.exe -ErrorAction SilentlyContinue) {
            Start-Process inetmgr.exe | Out-Null
        } else {
            Write-Ui "inetmgr.exe not found. Install IIS Manager / management tools." "WARN"
        }
    } catch {
        Write-Ui "Could not open IIS Manager: $($_.Exception.Message)" "ERR"
    }
})

$script:BtnClear.Add_Click({ $script:OutputBox.Clear() })

$script:BtnAssess.Add_Click({
    Set-UiBusy -Busy $true
    try {
        $script:OutputBox.Clear()

        if (-not (Test-IISInstalled)) {
            Write-Ui "IIS does not appear installed or W3SVC not present." "ERR"
            return
        }

        Invoke-Safe -Description "Collect patch status" -ScriptBlock {
            $script:LastPatch = Get-PatchStatus
            Write-Ui "OS: $($script:LastPatch.OSName) | Version $($script:LastPatch.OSVersion) | Build $($script:LastPatch.OSBuild) | UBR $($script:LastPatch.UBR)" "OK"
            Write-Ui "Pending reboot: $($script:LastPatch.PendingReboot)" ($script:LastPatch.PendingReboot ? "WARN" : "OK")
            Write-Ui "Windows Update service: $($script:LastPatch.WindowsUpdateSvc)" "INFO"
            if (($script:LastPatch.RecentHotfixes ?? @()).Count -gt 0) {
                Write-Ui "Recent hotfixes:" "INFO"
                foreach ($hf in $script:LastPatch.RecentHotfixes) {
                    $dt = if ($hf.InstalledOn) { $hf.InstalledOn } else { [datetime]::MinValue }
                    Write-Ui ("  {0}  {1:yyyy-MM-dd}  {2}" -f $hf.HotFixID, $dt, $hf.Description) "INFO"
                }
            } else {
                Write-Ui "Recent hotfixes: unavailable on this system." "WARN"
            }
        } | Out-Null

        Invoke-Safe -Description "Collect IIS inventory" -ScriptBlock {
            $script:LastIIS = Get-IISInventory
            Write-Ui "IIS appcmd: $($script:LastIIS.AppCmd)" "OK"
            Write-Ui "WebAdministration module: $($script:LastIIS.WebAdminModule)" ($script:LastIIS.WebAdminModule ? "OK" : "WARN")

            if (($script:LastIIS.Sites ?? @()).Count -gt 0) {
                Write-Ui "Sites:" "INFO"
                foreach ($s in $script:LastIIS.Sites) {
                    Write-Ui "  $($s.Name) | $($s.State) | $($s.PhysicalPath)" "INFO"
                    Write-Ui "    Bindings: $($s.Bindings)" "INFO"
                }
            }

            if (($script:LastIIS.RiskFlags ?? @()).Count -gt 0) {
                Write-Ui "Risk flags:" "WARN"
                foreach ($r in $script:LastIIS.RiskFlags) { Write-Ui "  - $r" "WARN" }
            } else {
                Write-Ui "Risk flags: none detected from global modules." "OK"
            }
        } | Out-Null

        $u = $txtUrl.Text
        if (-not [string]::IsNullOrWhiteSpace($u)) {
            Invoke-Safe -Description "Check security headers for $u" -ScriptBlock {
                $script:LastHdr = Test-SecurityHeaders -Url $u
                $script:LastHdr.PSObject.Properties | ForEach-Object {
                    $lvl = if ($_.Value -eq "(missing)" -and $_.Name -notin @("Server","X-Powered-By")) { "WARN" } else { "INFO" }
                    Write-Ui ("  {0}: {1}" -f $_.Name, $_.Value) $lvl
                }
            } | Out-Null
        } else {
            Write-Ui "Header check skipped (no URL provided)." "INFO"
        }
    } finally {
        Set-UiBusy -Busy $false
    }
})

$script:BtnApply.Add_Click({
    if (-not (Test-IsAdmin)) {
        Write-Ui "Please run PowerShell as Administrator for hardening actions." "ERR"
        return
    }
    if (-not (Test-IISInstalled)) {
        Write-Ui "IIS not detected. Aborting." "ERR"
        return
    }

    Set-UiBusy -Busy $true
    try {
        if ($chkBackup.Checked) {
            Invoke-Safe -Description "Backup IIS configuration" -ScriptBlock {
                $b = Backup-IISConfig
                Write-Ui "IIS backup created: $b" "OK"
            } | Out-Null
        } else {
            Write-Ui "Backup skipped (you unchecked it)." "WARN"
        }

        for ($i=0; $i -lt $hardList.Items.Count; $i++) {
            if ($hardList.GetItemChecked($i)) {
                $name = [string]$hardList.Items[$i]
                $sb = $hardActions[$name]
                Invoke-Safe -Description $name -ScriptBlock $sb | Out-Null
            }
        }

        Write-Ui "Apply complete. Review output and test your apps." "OK"
    } finally {
        Set-UiBusy -Busy $false
    }
})

$script:BtnExport.Add_Click({
    if (-not $script:LastPatch -or -not $script:LastIIS) {
        Write-Ui "Run Assessment first so the report has content." "WARN"
        return
    }

    Set-UiBusy -Busy $true
    try {
        Invoke-Safe -Description "Export HTML report" -ScriptBlock {
            $stamp = New-RunStamp
            $html = New-AssessmentReport -Patch $script:LastPatch -IIS $script:LastIIS -HeaderCheck $script:LastHdr
            $path = Join-Path $ReportDir "IISHardener_Report_$stamp.html"
            $html | Out-File -Encoding UTF8 -FilePath $path
            Write-Ui "Report saved: $path" "OK"
            Start-Process $path | Out-Null
        } | Out-Null
    } finally {
        Set-UiBusy -Busy $false
    }
})

$script:BtnBkRefresh.Add_Click({
    if (-not (Test-IISInstalled)) { Write-Ui "IIS not detected." "ERR"; return }
    Invoke-Safe -Description "Refresh IIS backups" -ScriptBlock {
        $bkList.Items.Clear()
        foreach ($b in (Get-IISBackups)) { [void]$bkList.Items.Add($b) }
        Write-Ui "Backups listed: $($bkList.Items.Count)" "OK"
    } | Out-Null
})

$script:BtnBkRestore.Add_Click({
    if (-not (Test-IsAdmin)) { Write-Ui "Run as Administrator to restore backups." "ERR"; return }
    if ($bkList.SelectedItem -eq $null) { Write-Ui "Select a backup first." "WARN"; return }

    $name = [string]$bkList.SelectedItem
    $msg = "Restore IIS configuration from backup:`r`n`r`n$name`r`n`r`nThis rewinds IIS config on this machine. Continue?"
    $res = [System.Windows.Forms.MessageBox]::Show($msg, $AppName, [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($res -ne [System.Windows.Forms.DialogResult]::Yes) { return }

    Set-UiBusy -Busy $true
    try {
        Invoke-Safe -Description "Restore IIS backup $name" -ScriptBlock {
            Restore-IISBackup -Name $name
            Write-Ui "Restore complete. Open IIS Manager and verify sites/app pools." "OK"
        } | Out-Null
    } finally {
        Set-UiBusy -Busy $false
    }
})

# ----------------------------
# Start
# ----------------------------
Write-Ui "Log: $LogFile" "INFO"
Write-Ui "Ready." "OK"

# Offer elevation before showing UI
if (-not (Ensure-AdminOrContinue)) {
    try { Stop-Transcript | Out-Null } catch {}
    return
}

try {
    [void]$script:Form.ShowDialog()
} finally {
    try { Stop-Transcript | Out-Null } catch {}
}
