# wtfdav

**WebDAV Forensic Tool** - Find out why Windows WebClient service is running

## Overview

Analyzes Windows WebClient (WebDAV) service to identify what triggered it to start. The service starts automatically when apps need WebDAV - often without user awareness - increasing attack surface.

Relevant for **CVE-2025-33053** WebDAV vulnerability response, especially if you aren't sure whether you can safely disable or remove the service entirely without impacting users.

## Quick Start

```powershell
# Run as Administrator
iwr -useb https://raw.githubusercontent.com/adam-fff/wtfdav/main/wtfdav.ps1 | iex
```

## Usage

**Download and run locally:**
```powershell
.\wtfdav.ps1
.\wtfdav.ps1 -BeforeMinutes 5 -AfterMinutes 3
.\wtfdav.ps1 -SkipAdminCheck  # Limited functionality
```

**If blocked by execution policy:**
```powershell
powershell -ExecutionPolicy Bypass -File .\wtfdav.ps1
# Or unblock the file:
Unblock-File -Path .\wtfdav.ps1
```

### Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-BeforeMinutes` | 2 | Minutes to search before service start |
| `-AfterMinutes` | 1 | Minutes to search after service start |
| `-SkipAdminCheck` | False | Skip admin check (limited features) |

## What It Analyzes

- Service status and process tree
- System, Application, Security event logs
- Network, Task Scheduler, Office events
- Common triggers: Office cloud docs, OneDrive sync, licensing checks

## Output

Shows when WebClient started, what triggered it, and provides recommendations to disable if not needed.

## Troubleshooting

- **"Access denied"**: Run as Administrator or use `-SkipAdminCheck`
- **"Script cannot be loaded"**: See execution policy commands above
- **No events found**: Increase `-BeforeMinutes` parameter

## Security Note

Read-only analysis tool. Makes no system changes. For CVE-2025-33053 patches: https://msrc.microsoft.com/update-guide/

---

*WebDAV? More like wtfDAV amirite?* 😄
