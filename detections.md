# Detection results

Seven Atomic Red Team tests on a Windows 11 endpoint (Sysmon, PowerShell script block logging, Wazuh agent), covering two MITRE ATT&CK techniques. Rule IDs, levels and MITRE tags are as shown in the Wazuh dashboard.

## Legend

- **Detected:** an alert identified the technique or method itself (the command, or the script).
- **Partially:** only the outcome was alerted (for example, "account created"), with no alert showing how.
- **Level:** Wazuh rule level (0-15). Levels 3-4 are low severity and typically not triaged in a real SOC.

## Summary

| Test | Technique | Method | Before custom rules | After custom rules |
|:---:|:---:|:---:|:---:|:---:|
| T1136.001-4 | Create Account | `net user` (cmd) | Detected | n/a |
| T1136.001-5 | Create Account | PowerShell `New-LocalUser` | Partially | Detected (100100) |
| T1136.001-8 | Create Account | Admin via `net user` | Detected | n/a |
| T1136.001-9 | Create Account | .NET AccountManagement | Partially | Detected (100101) |
| T1053.005-2 | Scheduled Task | `schtasks` | Detected (low severity) | n/a |
| T1053.005-4 | Scheduled Task | `Register-ScheduledTask` | Partially | Detected (100102) |
| T1053.005-6 | Scheduled Task | WMI `RegisterByXml` | Partially | Detected (100103) |

## Details

### T1136.001-4: Create a new user in a command prompt
- **Command:** `net user /add "T1136.001_CMD" "T1136.001_CMD!"`
- **Main alert:** 92040, net1.exe executed a user creation command (level 12, T1136.001)
- **Supporting alerts:** 60109 account created (8), 60110 account changed (8), 60160 and 60170 group changes (5)
- **Result:** Detected at process level and in the Windows Security log.
- **Notes:** Wazuh tagged the account changes as T1098 (Account Manipulation), not T1136.001.

### T1136.001-5: Create a new user in PowerShell
- **Command:** `New-LocalUser -Name "T1136.001_PowerShell" -NoPassword` (Event ID 4104)
- **Before:** 60109 (8), 60110 (8), 60160 (5), 92027 PowerShell spawned PowerShell (4). No alert showed the command.
- **After:** custom rule 100100 (level 10, T1136.001)
- **Notes:** 92213 (level 15) fired and is a confirmed false positive (PowerShell's `__PSScriptPolicyTest` temp file).

### T1136.001-8: Create a new Windows admin user
- **Command:** `net user /add "T1136.001_Admin" "T1136_pass"`, then a second `net` command adding the account to Administrators
- **Main alerts:** 92040 (12), 60154 Administrators Group Changed (12)
- **Supporting alerts:** 92052, 92036, 92031, 60109, 60110, 60160, 60170
- **Result:** Detected at process level and in the Windows Security log.

### T1136.001-9: Create a new Windows admin user via .NET
- **Method:** a download cradle (`iex(new-object net.webclient).downloadstring(...)`) fetches a script that creates the account with `System.DirectoryServices.AccountManagement` and adds it to Administrators, without using `net`.
- **Before:** 60154 (12), 60109 (8), 60110 (8), 60160 (5), 91837 `iex` string execution (4), 92033 and 92039 discovery (3). No alert identified the account creation method.
- **After:** custom rule 100101 (level 10, T1136.001)
- **Notes:** The test needs internet access. See the [incident report](incident-reports/).

### T1053.005-2: Scheduled task, local
- **Command:** `SCHTASKS /Create /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST 20:10`
- **Main alert:** 60228 A scheduled task was created (level 4, T1053), Windows event 4698
- **Supporting alerts:** 92004 (4), 92032 suspicious cmd shell execution (3), which contains the `schtasks` command line
- **Result:** Detected, but only at levels 3-4.
- **Notes:** Wazuh tags 60228 with the parent technique T1053, not T1053.005.

### T1053.005-4: PowerShell cmdlet scheduled task
- **Command:** `Register-ScheduledTask AtomicTask -InputObject $object` (a task launching `calc.exe` at logon with highest privileges)
- **Before:** 60228 (4), 92027 (4). No alert showed the PowerShell command.
- **After:** custom rule 100102 (level 8, T1053.005)
- **Notes:** 100102 excludes script blocks containing `__cmdletization`, because the ScheduledTask module's own generated code contains the cmdlet names. False-positive check: running `Get-ScheduledTask` in a new session produced no new 100102 alerts (count 2 before and after).

### T1053.005-6: WMI Invoke-CimMethod scheduled task
- **Command:** `Invoke-CimMethod -ClassName PS_ScheduledTask -NameSpace "Root\Microsoft\Windows\TaskScheduler" -MethodName "RegisterByXml" ...`
- **Before:** 60228 (4), 92027 (4). The alert pattern was identical to test 4, so the two methods could not be told apart.
- **After:** custom rule 100103 (level 10, T1053.005)

## Cross-cutting findings
- **Outcome vs method:** Wazuh's default rules recorded account and task creation from the Windows Security log, but only identified the method for `net` and `schtasks`. PowerShell, .NET and WMI methods needed custom rules.
- **Severity:** scheduled task creation was alerted at level 4, which most SOCs would not triage.
- **False positive:** alert 92213 (level 15) fired in every PowerShell-based test because of PowerShell's execution-policy temp file.
- **MITRE tags:** several built-in tags are a loose fit (T1098 for account creation, T1053 instead of T1053.005, T1484 for local group changes).
