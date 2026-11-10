# 🛡️ Wazuh-soc-home-lab
Home SOC lab with Wazuh SIEM and Sysmon: attack simulation (Atomic Red Team), custom detection rules, MITRE ATT&amp;CK mapping and incident report

![Wazuh](https://img.shields.io/badge/Wazuh-005571?style=for-the-badge&logo=wazuh&logoColor=white)
![Ubuntu](https://img.shields.io/badge/Ubuntu-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)
![Windows 11](https://img.shields.io/badge/Windows%2011-0078D4?style=for-the-badge&logo=windows11&logoColor=white)
![VirtualBox](https://img.shields.io/badge/VirtualBox-183A61?style=for-the-badge&logo=virtualbox&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=for-the-badge&logo=powershell&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-B22222?style=for-the-badge)
![Sysmon](https://img.shields.io/badge/Sysmon-5C2D91?style=for-the-badge)
![Atomic Red Team](https://img.shields.io/badge/Atomic%20Red%20Team-D12127?style=for-the-badge)

## 📋 Goals
- Build a working SIEM pipeline: endpoint, agent, server, dashboard
- Map simulated attacks to MITRE ATT&CK and measure what the default rules detect
- Close detection gaps with custom rules and verify them on real events
- Practice investigating alerts and writing an incident report

## ⚙️ Architecture
<img width="900" height="520" alt="architecture" src="https://github.com/user-attachments/assets/8070297c-d7cc-4fb9-8237-a1c2442a546f" />

| Component | Details |
|:---:|:---:|
| Hypervisor | VirtualBox on Windows |
| Network | Isolated NAT Network (`LabNet`, 10.10.10.0/24), no access from the home LAN |
| SIEM | Wazuh [version] all-in-one (manager, indexer, dashboard) on Ubuntu Server 22.04 |
| Endpoint | Windows 11 Enterprise (evaluation) with Sysmon (SwiftOnSecurity config) and the Wazuh agent |
| Extra logging | PowerShell script block logging (Event ID 4104), Windows audit policies |
| Attack simulation | Atomic Red Team (run directly on the Windows endpoint) |

## 📊 Results
I ran 7 Atomic Red Team tests across two MITRE ATT&CK techniques. "Detected" means an alert identified the technique or method itself, and "Partially" means only the outcome was alerted.

| Technique | Test | Before custom rules | After |
|:---:|:---:|:---:|:---:|
| T1136.001 Create Account | `net user` (cmd) | Detected (92040, level 12) | n/a |
| T1136.001 Create Account | PowerShell `New-LocalUser` | Partially (outcome only) | Detected, rule 100100 |
| T1136.001 Create Account | Admin via `net user` | Detected (92040, 60154) | n/a |
| T1136.001 Create Account | .NET AccountManagement | Partially (outcome only) | Detected, rule 100101 |
| T1053.005 Scheduled Task | `schtasks` | Detected, low severity (level 3-4) | n/a |
| T1053.005 Scheduled Task | `Register-ScheduledTask` | Partially (level 4) | Detected, rule 100102 |
| T1053.005 Scheduled Task | WMI `RegisterByXml` | Partially (level 4) | Detected, rule 100103 |

Full details are in [`detections.md`](detections.md).

## 📏 Custom rules
Four custom rules in [`rules/local_rules.xml`](rules/local_rules.xml):
| Rule | Level | Detects |
|:---:|:---:|:---|
| 100100 | 10 | PowerShell `New-LocalUser` in script blocks |
| 100101 | 10 | Local account creation through .NET `UserPrincipal` |
| 100102 | 8 | `Register-ScheduledTask` in script blocks (excludes the module's own code) |
| 100103 | 10 | Scheduled task creation through WMI `PS_ScheduledTask` / `RegisterByXml` |

## 💼 Case studies and incident report
- [Case study: PowerShell account creation](case-studies/) [add links when files exist]
- [Case study: .NET account creation](case-studies/)
- [Case study: scheduled tasks](case-studies/)
- [Incident report: unauthorized local administrator](incident-reports/)

## 🧠 What I learned
- Windows logging and SIEM detection are different: an event can be recorded without any alert.
- A rule that passes the Wazuh Ruleset Test can still fail on real events. Pasted JSON is decoded differently from agent events, and custom rules often need to be children (`if_sid`) of a built-in rule.
- One attack produces a chain of alerts. The analyst's job is to separate the alert that identifies the technique from the supporting evidence.
- Built-in rules are noisy in places: a level 15 alert (92213) fired on PowerShell's own temp file in every PowerShell test.
- Detecting the method is harder than detecting the outcome, and every added rule needs a false-positive check.

## ⚠️ Limitations
- Single Windows endpoint, no Linux or network telemetry yet.
- Rules match specific strings, so obfuscated variants would likely evade them.
- Tests ran with Defender real-time protection off in an isolated lab, so they say nothing about endpoint protection.

## ⏭️ Next steps
- Python script to enrich alerts with threat intelligence lookups
- Rule for the PowerShell download cradle pattern
- Linux endpoint and SSH brute force detection
- ATT&CK Navigator coverage layer

## 📌 Safety note
All attack simulations ran only on VMs in an isolated lab network that I own.
