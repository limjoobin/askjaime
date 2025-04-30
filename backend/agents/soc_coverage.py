from langchain_core.prompts import PromptTemplate, FewShotPromptTemplate

from llm import llm

# Probably abstract the system prompt to the agent
prompt_template = """
# IDENTITY and PURPOSE

You are an expert at evaluating cybersecurity threat risk exposure. You specialize in identifying detection coverage for Tactics, Techniques, and Procedures (TTPs), given a set of rules. 

Take a deep breath and think step by step about how to best accomplish this goal using the following steps.

# STEPS

- Recall the various threat scenarios associated with the TTP, and how the execution methods differ.

- Create a virtual whiteboard in your mind and list down all the behavioural patterns, such as indicators and signatures, associated with the TTP, across threat scenarios.

- Read the rules provided throughly and think of the threat scenarios that this rule is able to address. 

- Identify the detection mechanism responsible for addressing the particular threat scenario.

# INSTRUCTIONS
You are given a set of Splunk rules meant for security detection. Based on the following rules, evaluate the coverage of the current SOC operations.

Rules:
{rules}

Now, tell me how protected I am against {TTP}, based on the behaviour observed by common implementations of the TTP. Identify the rules that address the behaviour.

You are required to state your thinking process, step-by-step.

# OUTPUT FORMAT
Format the output into the following three sections.

DESCRIPTION
  - A short description of the TTP and its identified behavioural patterns. Also include examples of different execution methods of this TTP.

RULES COVERAGE
For each rule that you identify, write a short section containing the following:
  - A paragraph about the description of the rule
  - The threat scenario addressed by the rule
  - Explanation of how this rule addrresses the TTP, and the detection mechanism responsible.
Ensure that there is no repetition of rules.

SUMMARY
At the end, write a short paragraph to summarize your findings.
"""


prompt = PromptTemplate.from_template(prompt_template,
                                      template_format='f-string',)
                                      #partial_variables=variables)

sample_rules = [
    r'(source="WinEventLog:*" ((((EventCode="4688" OR EventCode="1") ((CommandLine="*reg*" CommandLine="*add*" CommandLine="*/d*") OR (CommandLine="*Set-ItemProperty*" CommandLine="*-value*")) (CommandLine="*00000000*" OR CommandLine="*0*") CommandLine="*SafeDllSearchMode*") OR ((EventCode="4657") ObjectValueName="SafeDllSearchMode" value="0")) OR ((EventCode="13") EventType="SetValue" TargetObject="*SafeDllSearchMode" Details="DWORD (0x00000000)")))',
    r'(index=__your_sysmon_index__ EventCode=1) (Image="C:\\Windows\\SysWOW64\\mavinject.exe" OR Image="C:\\Windows\\System32\\mavinject.exe" OR CommandLine="*\INJECTRUNNING*")',
    r'index=* sourcetype="xmlwineventlog" EventCode=4688  |eval cmd_len=len(CommandLine) | eventstats avg(cmd_len) as avg by host| stats max(cmd_len) as maxlen, values(avg) as avgperhost by host, CommandLine | where maxlen > 10*avgperhost',
    r'index=__your_sysmon_index__ EventCode=1 (Image="C:\\Windows\\*\\hostname.exe" OR Image="C:\\Windows\\*\\ipconfig.exe" OR Image="C:\\Windows\\*\\net.exe" OR Image="C:\\Windows\\*\\quser.exe" OR Image="C:\\Windows\\*\\qwinsta.exe" OR (Image="C:\\Windows\\*\\sc.exe" AND (CommandLine="* query *" OR CommandLine="* qc *")) OR Image="C:\\Windows\\*\\systeminfo.exe" OR Image="C:\\Windows\\*\\tasklist.exe" OR Image="C:\\Windows\\*\\whoami.exe")|stats values(Image) as "Images" values(CommandLine) as "Command Lines" by ComputerName',
    r'index=__your_sysmon_index__ EventCode=1 (OriginalFileName = At.exe OR OriginalFileName = Atbroker.exe OR OriginalFileName = Bash.exe OR OriginalFileName = Bitsadmin.exe OR OriginalFileName = Certutil.exe OR OriginalFileName = Cmd.exe OR OriginalFileName = Cmdkey.exe OR OriginalFileName = Cmstp.exe OR OriginalFileName = Control.exe OR OriginalFileName = Csc.exe OR OriginalFileName = Cscript.exe OR OriginalFileName = Dfsvc.exe OR OriginalFileName = Diskshadow.exe OR OriginalFileName = Dnscmd.exe OR OriginalFileName = Esentutl.exe OR OriginalFileName = Eventvwr.exe OR OriginalFileName = Expand.exe OR OriginalFileName = Extexport.exe OR OriginalFileName = Extrac32.exe OR OriginalFileName = Findstr.exe OR OriginalFileName = Forfiles.exe OR OriginalFileName = Ftp.exe OR OriginalFileName = Gpscript.exe OR OriginalFileName = Hh.exe OR OriginalFileName = Ie4uinit.exe OR OriginalFileName = Ieexec.exe OR OriginalFileName = Infdefaultinstall.exe OR OriginalFileName = Installutil.exe OR OriginalFileName = Jsc.exe OR OriginalFileName = Makecab.exe OR OriginalFileName = Mavinject.exe OR OriginalFileName = Microsoft.Workflow.r.exe OR OriginalFileName = Mmc.exe OR OriginalFileName = Msbuild.exe OR OriginalFileName = Msconfig.exe OR OriginalFileName = Msdt.exe OR OriginalFileName = Mshta.exe OR OriginalFileName = Msiexec.exe OR OriginalFileName = Odbcconf.exe OR OriginalFileName = Pcalua.exe OR OriginalFileName = Pcwrun.exe OR OriginalFileName = Presentationhost.exe OR OriginalFileName = Print.exe OR OriginalFileName = Reg.exe OR OriginalFileName = Regasm.exe OR OriginalFileName = Regedit.exe OR OriginalFileName = Register-cimprovider.exe OR OriginalFileName = Regsvcs.exe OR OriginalFileName = Regsvr32.exe OR OriginalFileName = Replace.exe OR OriginalFileName = Rpcping.exe OR OriginalFileName = Rundll32.exe OR OriginalFileName = Runonce.exe OR OriginalFileName = Runscripthelper.exe OR OriginalFileName = Sc.exe OR OriginalFileName = Schtasks.exe OR OriginalFileName = Scriptrunner.exe OR OriginalFileName = SyncAppvPublishingServer.exe OR OriginalFileName = Tttracer.exe OR OriginalFileName = Verclsid.exe OR OriginalFileName = Wab.exe OR OriginalFileName = Wmic.exe OR OriginalFileName = Wscript.exe OR OriginalFileName = Wsreset.exe OR OriginalFileName = Xwizard.exe OR OriginalFileName = Advpack.dll OR OriginalFileName = Comsvcs.dll OR OriginalFileName = Ieadvpack.dll OR OriginalFileName = Ieaframe.dll OR OriginalFileName = Mshtml.dll OR OriginalFileName = Pcwutl.dll OR OriginalFileName = Setupapi.dll OR OriginalFileName = Shdocvw.dll OR OriginalFileName = Shell32.dll OR OriginalFileName = Syssetup.dll OR OriginalFileName = Url.dll OR OriginalFileName = Zipfldr.dll OR OriginalFileName = Appvlp.exe OR OriginalFileName = Bginfo.exe OR OriginalFileName = Cdb.exe OR OriginalFileName = csi.exe OR OriginalFileName = Devtoolslauncher.exe OR OriginalFileName = dnx.exe OR OriginalFileName = Dxcap.exe OR OriginalFileName = Excel.exe OR OriginalFileName = Mftrace.exe OR OriginalFileName = Msdeploy.exe OR OriginalFileName = msxsl.exe OR OriginalFileName = Powerpnt.exe OR OriginalFileName = rcsi.exe OR OriginalFileName = Sqler.exe OR OriginalFileName = Sqlps.exe OR OriginalFileName = SQLToolsPS.exe OR OriginalFileName = Squirrel.exe OR OriginalFileName = te.exe OR OriginalFileName = Tracker.exe OR OriginalFileName = Update.exe OR OriginalFileName = vsjitdebugger.exe OR OriginalFileName = Winword.exe OR OriginalFileName = Wsl.exe OR OriginalFileName = CL_Mutexverifiers.ps1 OR OriginalFileName = CL_Invocation.ps1 OR OriginalFileName = Manage-bde.wsf OR OriginalFileName = Pubprn.vbs OR OriginalFileName = Slmgr.vbs OR OriginalFileName = Syncappvpublishingserver.vbs OR OriginalFileName = winrm.vbs OR OriginalFileName = Pester.bat)|eval CommandLine=lower(CommandLine)|eventstats count(process) as procCount by process|eventstats avg(procCount) as avg stdev(procCount) as stdev|eval lowerBound=(avg-stdev*1.5)|eval isOutlier=if((procCount < lowerBound),1,0)|where isOutlier=1|table host, Image, ParentImage, CommandLine, ParentCommandLine, procCount',
    r'(((EventCode="4688" OR EventCode="1") (CommandLine="*reg*" AND CommandLine="*add*" AND CommandLine="*/d*") OR (CommandLine="*Set-ItemProperty*" AND CommandLine="*-value*") CommandLine="*Common Startup*") OR ((EventCode="4657" ObjectValueName="Common Startup") OR (EventCode="13" TargetObject="*Common Startup")))',

]

if __name__ == "__main__":
    variables={
        "TTP": 'T1547.001: Registry Run Keys / Startup Folder',
        "rules": "\n".join(sample_rules)
    }
    chain = prompt | llm

    print(chain.invoke(variables).content)