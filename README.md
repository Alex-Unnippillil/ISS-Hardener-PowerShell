# IIS Hardener GUI (PowerShell)

A lightweight Windows GUI tool (PowerShell 5.1 + WinForms) that assesses IIS security posture and applies a curated set of **safe, reversible** hardening changes. It also generates an HTML report and supports **IIS configuration backup + restore** using `appcmd`.

---

## What this does

### Assessment

* Collects Windows patch status (OS version/build, recent hotfixes, pending reboot)
* Inventories IIS (sites, app pools, global modules)
* Flags common risky IIS modules (WebDAV, CGI, ISAPI)
* Optional: checks a target URL for common HTTP security headers

### Hardening

Applies selected hardening actions **globally** (server-wide), including:

* Disable directory browsing
* Remove `X-Powered-By` custom header (if present)
* Deny HTTP `TRACE` and `TRACK`
* Apply request filtering limits (max body, URL, query string)
* Hide sensitive segments (e.g., `App_Data`, `.git`)
* Ensure IIS W3C log basics
* Enable IIS-related Windows Event Log channels

### Safety features

* **Optional IIS config backup before changes** (recommended)
* **Restore workflow** through a dedicated **Backups** tab
* Output logging + transcript logging to disk
* “Safer defaults” (break-prone header changes are not pre-selected)

---

## Screenshot / UI overview

Tabs:

* **Run**: Assessment, header check, report export, open IIS Manager
* **Hardening**: Choose actions and apply them
* **Backups**: List IIS backups and restore a selected one

---

## Requirements

* Windows with **IIS installed**
* PowerShell **5.1** (default on many Windows versions)
* Administrative privileges for hardening + restore operations
* IIS management tooling:

  * `appcmd.exe` present at `C:\Windows\System32\inetsrv\appcmd.exe`
  * `WebAdministration` module available for most config edits
    (If missing, install “IIS Management Scripts and Tools” via Windows Features)

---

## Installation

### Option A: Run locally

1. Clone this repository:

   ```powershell
   git clone https://github.com/<your-org-or-user>/iis-hardener-gui.git
   cd iis-hardener-gui
   ```
2. Run PowerShell as Administrator.
3. Launch:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\src\IIS-Hardener-GUI.ps1
   ```

### Option B: Download release (recommended for users)

* Download the latest release `.zip`
* Extract
* Run `src\IIS-Hardener-GUI.ps1` as Administrator

---

## How to use

### 1) Run Assessment

1. Open the **Run** tab
2. (Optional) enter a URL like:

   * `https://your-site/`
   * `your-site.com` (the tool will assume HTTPS)
3. Click **Run Assessment**
4. Review:

   * Patch status and pending reboot
   * IIS sites and module risk flags
   * Header check results (if provided)

### 2) Apply hardening

1. Open **Hardening** tab
2. Review selections
3. Keep **Backup IIS config before changes** checked (recommended)
4. Click **Apply Selected**
5. Test your applications

### 3) Restore an IIS backup (rollback)

1. Open **Backups**
2. Click **Refresh**
3. Select a backup
4. Click **Restore Selected**
5. Verify sites/app pools and test your apps

---

## Important warnings

### Security headers can break apps

Some headers can block embedding, scripts, or third-party integrations. For example:

* `X-Frame-Options: DENY` can break apps that legitimately use iframes.
* `Content-Security-Policy` requires app-specific tuning.

This project intentionally keeps “basic security headers” **not pre-selected** and conservative. You should validate header behavior in staging before production rollout.

### “Server” header removal

IIS is limited in safely removing the `Server` header everywhere. The best place is at the **edge**:

* reverse proxy
* load balancer
* WAF/CDN

---

## What changes are made exactly?

All hardening changes are applied at the IIS machine scope:

* `MACHINE/WEBROOT/APPHOST`
* IIS `requestFiltering`
* IIS `httpProtocol/customHeaders`
* IIS site defaults for logging

Backups and restores use:

* `appcmd add backup <Name>`
* `appcmd list backup`
* `appcmd restore backup "<Name>"`

---

## Logs and reports

### Logs

* Stored under:

  * `C:\ProgramData\IISHardener\Logs`
* Each run produces a timestamped transcript log:

  * `IISHardener_YYYYMMDD_HHMMSS_fff.log`

### Reports

* Stored under:

  * `C:\ProgramData\IISHardener\Reports`
* Exported as:

  * `IISHardener_Report_YYYYMMDD_HHMMSS_fff.html`

---

## Project structure

```
iis-hardener-gui/
  src/
    IIS-Hardener-GUI.ps1
  tests/
    IISHardener.Tests.ps1
  .github/
    workflows/
      ci.yml
  LICENSE
  README.md
```

---

## Development

### Run linting locally

```powershell
Install-Module PSScriptAnalyzer -Scope CurrentUser -Force
Invoke-ScriptAnalyzer -Path .\src\IIS-Hardener-GUI.ps1 -Severity Warning,Error
```

### Run tests locally

```powershell
Install-Module Pester -Scope CurrentUser -Force
Invoke-Pester -Path .\tests -Output Detailed
```

### CI

GitHub Actions runs:

* PSScriptAnalyzer linting
* Pester tests
  on `windows-latest`.

---

## Security model and philosophy

* This tool is a **configuration hardener**, not a vulnerability scanner.
* It avoids intrusive changes and prioritizes **reversibility** via IIS backups.
* It assumes:

  * you have change control,
  * you will test apps after changes,
  * you will use a reverse proxy/WAF for edge-level protections.

---

## Roadmap ideas (optional)

* “Low/Medium/High risk” grouped hardening categories
* Per-site configuration targeting instead of global-only
* Baseline comparison (before/after diff)
* Export report to JSON for SIEM ingestion
* Add more request filtering rules (file extensions, double-escaping options, etc.) behind toggles

---

## License

MIT (recommended). See `LICENSE`.

---

## Disclaimer

This tool makes changes to IIS configuration. Always test in a staging environment first. You are responsible for validating compatibility with your applications and your organization’s security policies.
