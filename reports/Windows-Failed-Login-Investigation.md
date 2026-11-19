# Investigation Report SOC-INV-002

## Executive summary
On November 18, 2026 (lab-local display), a controlled attempt to authenticate as nonexistent user `SOC-Lab-Test-User` was rejected on Windows endpoint `SOC-WIN11-01`. Windows Security Event ID `4625` was confirmed locally. The Wazuh manager generated rule `60122`, severity level `5`, and the same alert was visible in Threat Hunting. The event was benign authorized lab testing, not evidence of compromise.

## Scope and evidence
- Windows audit policy screenshot: Logon auditing `Success and Failure`.
- Local Windows Security `4625` event output supplied during investigation.
- Wazuh `alerts.json` output for the Windows endpoint and event `4625`.
- Wazuh rule `60122` configuration screenshot and Threat Hunting event screenshot.
- Privacy-safe crop of the detailed event document (excludes full SID and account information).

## Timeline
| Time | Event |
|---|---|
| Nov 18, 2026, 5:43:34 PM (Windows-reported local time) | Windows `4625` event shown in PowerShell output |
| Nov 19, 2026, 01:43:35.861 UTC | Wazuh alert `60122` recorded |
| Nov 18, 2026, 7:43 PM (dashboard display) | Matching alert displayed in Threat Hunting |

**Time caution:** The Windows output and Wazuh/dashboard timestamps do not all display the same local hour. The UTC alert timestamp and dashboard 7:43 PM display are consistent with UTC−6; the Windows event output showed 5:43 PM. Timezone configuration and clock alignment were **not independently verified**. Do not assume the displayed times represent synchronized clocks.

## Authentication event analysis
| Property | Value | Meaning |
|---|---|---|
| Event ID | `4625` | Failed Windows logon |
| Target | `SOC-Lab-Test-User` | Deliberately nonexistent local username |
| Subject account | `socadmin` | Account context requesting the logon |
| Logon type | `2` | Interactive |
| Status | `0xC000006D` | Authentication failed |
| Substatus | `0xC0000064` | User name does not exist |
| Source IP | `::1` | Local IPv6 loopback, not evidence of remote login |
| Workstation | `SOC-WIN11-01` | Local lab endpoint |
| Caller | `C:\Windows\System32\svchost.exe` | Reported process, not attribution to a specific service |
| Logon process | `seclogo` | As recorded in event |
| Authentication package | `Negotiate` | As recorded in event |

The earlier `runas` attempt failed with `Unable to acquire user password` and did not establish an audited authentication failure. A later PowerShell `Start-Process -Credential` call was rejected as invalid credentials, and a `4625` record for the test account was found. We do not claim an exhaustive causal trace beyond the observed controlled sequence.

## Wazuh alert validation
Observed alert excerpt:

```text
2026-11-19T01:43:35.861+0000  SOC-WIN11-01  4625  60122  Logon Failure - Unknown user or bad password
```

Rule metadata: severity `5`; groups `windows`, `windows_security`, `authentication_failed`. The dashboard returned **one matching alert in the selected 24-hour time window**. This is not a measurement of all authentication attempts on the system.

## MITRE ATT&CK mapping review
Wazuh associated the alert with **T1531 — Account Access Removal**, tactic **Impact**. This event demonstrates an unsuccessful authentication request, not account removal or modification. Therefore, **T1531 is a rule-level mapping only, not a confirmed observed technique in this case**. Do not infer threat actor identity from the technique's reference page.

## Disposition
**Benign / authorized testing — high confidence** given the known lab action, nonexistent test user, local loopback source, and matching alert. **Analyst risk:** Low in this controlled context. No evidence in the reviewed record of account compromise, successful access, or remote attacker activity. No escalation needed for this test; retain telemetry and continue monitoring future events independently.

## Lessons and follow-up
1. Validate the originating Windows event and SIEM alert rather than relying on a rule name alone.
2. Distinguish SIEM rule severity from analyst-assessed risk.
3. Verify technique mappings against actual event evidence.
4. For future investigations, correlate multiple events and test separate scenarios (e.g., repeated failures) only in authorized lab conditions.
5. Check VM timezone and clock synchronization before constructing a precise cross-system timeline.

## Privacy
Full Windows account SIDs are intentionally excluded from published narrative and screenshots. Original detailed event output was reviewed during the investigation but is not reproduced verbatim here.
