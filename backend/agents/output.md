### DESCRIPTION

T1547.001: **Registry Run Keys / Startup Folder** is a tactic where an attacker modifies the Windows registry to add a malicious executable to the **Run** keys or the **Startup** folder. This ensures that the malware is executed every time the system boots up, maintaining persistence. The TTP can be executed in various ways, such as modifying registry entries directly through the `reg` command, or using PowerShell cmdlets like `Set-ItemProperty`.

**Behavioural Patterns:**
- Modifying registry keys that are part of the **Run** or **Startup** folders.
- Using commands like `reg add`, `Set-ItemProperty` with specific parameters.
- Adding malicious executables to `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup` or similar paths.

### RULES COVERAGE

#### Rule 1:
```
(source="WinEventLog:*" ((((EventCode="4688" OR EventCode="1") ((CommandLine="*reg*" CommandLine="*add*" CommandLine="*/d*") OR (CommandLine="*Set-ItemProperty*" CommandLine="*-value*") CommandLine="*Common Startup*") OR ((EventCode="4657" ObjectValueName="Common Startup") OR (EventCode="13" TargetObject="*Common Startup")))))
```

**Threat Scenario Addressed:**
- Modifying registry keys that are part of the **Run** or **Startup** folders.
- Using commands like `reg add`, `Set-ItemProperty` with specific parameters.

**Detection Mechanism:**
- The rule addresses the TTP by identifying registry modifications that are part of the **Run** keys or **Startup** folder.
- The detection mechanism responsible is the Windows event logging, which captures the commands used to modify the registry.

#### Rule 2:
```
((EventCode="4688" OR EventCode="1") (CommandLine="*reg*" AND CommandLine="*add*" AND CommandLine="*/d*") OR (CommandLine="*Set-ItemProperty*" AND CommandLine="*-value*") CommandLine="*Common Startup*") OR ((EventCode="4657" ObjectValueName="Common Startup") OR (EventCode="13" TargetObject="*Common Startup")))
```

**Threat Scenario Addressed:**
- Modifying registry keys that are part of the **Run** or **Startup** folders.
- Using commands like `reg add`, `Set-ItemProperty` with specific parameters.

**Detection Mechanism:**
- The rule addresses the TTP by identifying registry modifications that are part of the **Run** keys or **Startup** folder.
- The detection mechanism responsible is the Windows event logging, which captures the commands used to modify the registry.

### SUMMARY

Based on the common implementations of T1547.001: Registry Run Keys / Startup Folder, and the observed behaviour, the rules provided address the TTP effectively.

- **Rule 1** captures registry modifications that are part of the **Run** keys or **Startup** folder, using commands like `reg add` and `Set-ItemProperty`.
- **Rule 2** identifies registry modifications that are part of the **Run** keys or **Startup** folder, using commands like `reg add`, `Set-ItemProperty` with specific parameters.

The findings indicate that the rules provided offer robust protection against T1547.001, as they effectively detect and respond to the TTP through registry modifications.

