from langchain_core.prompts import PromptTemplate, FewShotPromptTemplate
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent


from .llm import llm

system_prompt = (
"""
# IDENTITY and PURPOSE
You are an expert cybersecurity detection engineer for a SIEM company. Your task is to generate Splunk rules for detecting particular Tactics, Techniques, and Procedures (TTPs) used by threat actors.
You will be provided with a description of the TTP, and you need to create a Splunk rule that can detect them in logs.
The Splunk rule should be in YAML format and should include the following fields: name, id, version, date, author, status, type, description, data_source, search, how_to_implement, known_false_positives, references, drilldown_searches, tags.
The rule should be based on the MITRE ATT&CK framework and should include the relevant ATT&CK IDs.
"""
)

example_prompt = PromptTemplate.from_template("Input: {input}\nOutput: {output}")

# Example 1
input1 = "Help me to create a rule to detect the use of Mimikatz Pass The Ticket Command Line Parameters."
output1 = (
r"""
name: Mimikatz PassTheTicket CommandLine Parameters
id: 13bbd574-83ac-11ec-99d4-acde48001122
version: 7
date: '2025-02-10'
author: Mauricio Velazco, Splunk
status: production
type: TTP
description: The following analytic detects the use of Mimikatz command line parameters
  associated with pass-the-ticket attacks. It leverages data from Endpoint Detection
  and Response (EDR) agents, focusing on specific command-line patterns related to
  Kerberos ticket manipulation. This activity is significant because pass-the-ticket
  attacks allow adversaries to move laterally within an environment using stolen Kerberos
  tickets, bypassing normal access controls. If confirmed malicious, this could enable
  attackers to escalate privileges, access sensitive information, and maintain persistence
  within the network.
data_source:
- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2
search: '| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time)
  as lastTime from datamodel=Endpoint.Processes where (Processes.process = "*sekurlsa::tickets
  /export*" OR Processes.process = "*kerberos::ptt*") by Processes.action Processes.dest
  Processes.original_file_name Processes.parent_process Processes.parent_process_exec
  Processes.parent_process_guid Processes.parent_process_id Processes.parent_process_name
  Processes.parent_process_path Processes.process Processes.process_exec Processes.process_guid
  Processes.process_hash Processes.process_id Processes.process_integrity_level Processes.process_name
  Processes.process_path Processes.user Processes.user_id Processes.vendor_product
  | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
  | `mimikatz_passtheticket_commandline_parameters_filter`'
how_to_implement: The detection is based on data that originates from Endpoint Detection
  and Response (EDR) agents. These agents are designed to provide security-related
  telemetry from the endpoints where the agent is installed. To implement this search,
  you must ingest logs that contain the process GUID, process name, and parent process.
  Additionally, you must ingest complete command-line executions. These logs must
  be processed using the appropriate Splunk Technology Add-ons that are specific to
  the EDR product. The logs must also be mapped to the `Processes` node of the `Endpoint`
  data model. Use the Splunk Common Information Model (CIM) to normalize the field
  names and speed up the data modeling process.
known_false_positives: Although highly unlikely, legitimate applications may use the
  same command line parameters as Mimikatz.
references:
- https://github.com/gentilkiwi/mimikatz
- https://attack.mitre.org/techniques/T1550/003/
drilldown_searches:
- name: View the detection results for - "$user$" and "$dest$"
  search: '%original_detection_search% | search  user = "$user$" dest = "$dest$"'
  earliest_offset: $info_min_time$
  latest_offset: $info_max_time$
- name: View risk events for the last 7 days for - "$user$" and "$dest$"
  search: '| from datamodel Risk.All_Risk | search normalized_risk_object IN ("$user$",
    "$dest$") starthoursago=168  | stats count min(_time) as firstTime max(_time)
    as lastTime values(search_name) as "Search Name" values(risk_message) as "Risk
    Message" values(analyticstories) as "Analytic Stories" values(annotations._all)
    as "Annotations" values(annotations.mitre_attack.mitre_tactic) as "ATT&CK Tactics"
    by normalized_risk_object | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`'
  earliest_offset: $info_min_time$
  latest_offset: $info_max_time$
rba:
  message: Mimikatz command line parameters for pass the ticket attacks were used
    on $dest$
  risk_objects:
  - field: user
    type: user
    score: 36
  - field: dest
    type: system
    score: 36
  threat_objects:
  - field: parent_process_name
    type: parent_process_name
tags:
  analytic_story:
  - Sandworm Tools
  - CISA AA23-347A
  - CISA AA22-320A
  - Active Directory Kerberos Attacks
  asset_type: Endpoint
  mitre_attack_id:
  - T1550.003
  product:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  security_domain: endpoint
"""
)

# Example 2
input2 = "Help me to create a rule to detect suspicious DLL modules loaded by the calculator application"
output2 = (
r"""
name: Windows DLL Side-Loading In Calc
id: af01f6db-26ac-440e-8d89-2793e303f137
version: 7
date: '2025-04-22'
author: Teoderick Contreras, Splunk
status: production
type: TTP
description:
  The following analytic detects suspicious DLL modules loaded by calc.exe
  that are not located in the %systemroot%\system32 or %systemroot%\sysWoW64 directories.
  This detection leverages Sysmon EventCode 7 to identify DLL side-loading, a technique
  often used by Qakbot malware to execute malicious DLLs. This activity is significant
  as it indicates potential malware execution through a trusted process, which can
  bypass security controls. If confirmed malicious, this could allow attackers to
  execute arbitrary code, maintain persistence, and escalate privileges within the
  environment.
data_source:
  - Sysmon EventID 7
search:
  '`sysmon` EventCode=7 Image = "*\calc.exe" AND NOT (Image IN ("*:\\windows\\system32\\*",
  "*:\\windows\\sysWow64\\*")) AND NOT(ImageLoaded IN("*:\\windows\\system32\\*",
  "*:\\windows\\sysWow64\\*", "*:\\windows\\WinSXS\\*")) | fillnull | stats count
  min(_time) as firstTime max(_time) as lastTime by Image ImageLoaded dest loaded_file
  loaded_file_path original_file_name process_exec process_guid process_hash process_id
  process_name process_path service_dll_signature_exists service_dll_signature_verified
  signature signature_id user_id vendor_product | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)` | `windows_dll_side_loading_in_calc_filter`'
how_to_implement:
  To successfully implement this search you need to be ingesting information
  on processes that include the name of the process responsible for the changes from
  your endpoints into the `Endpoint` datamodel in the `Processes` and `Filesystem`
  node. In addition, confirm the latest CIM App 4.20 or higher is installed and the
  latest TA for the endpoint product.
known_false_positives: unknown
references:
  - https://www.bitdefender.com/blog/hotforsecurity/new-qakbot-malware-strain-replaces-windows-calculator-dll-to-infected-pcs/
drilldown_searches:
  - name: View the detection results for - "$dest$"
    search: '%original_detection_search% | search  dest = "$dest$"'
    earliest_offset: $info_min_time$
    latest_offset: $info_max_time$
  - name: View risk events for the last 7 days for - "$dest$"
    search:
      '| from datamodel Risk.All_Risk | search normalized_risk_object IN ("$dest$")
      starthoursago=168  | stats count min(_time) as firstTime max(_time) as lastTime
      values(search_name) as "Search Name" values(risk_message) as "Risk Message" values(analyticstories)
      as "Analytic Stories" values(annotations._all) as "Annotations" values(annotations.mitre_attack.mitre_tactic)
      as "ATT&CK Tactics" by normalized_risk_object | `security_content_ctime(firstTime)`
      | `security_content_ctime(lastTime)`'
    earliest_offset: $info_min_time$
    latest_offset: $info_max_time$
rba:
  message:
    a dll modules is loaded by calc.exe in $ImageLoaded$ that are not in common
    windows OS installation folder on $dest$
  risk_objects:
    - field: dest
      type: system
      score: 90
  threat_objects: []
tags:
  analytic_story:
    - Qakbot
    - Earth Alux
  asset_type: Endpoint
  mitre_attack_id:
    - T1574.001
"""
)

examples = [
    dict(input=input1, output=output1),
    dict(input=input2, output=output2)
]

prompt = FewShotPromptTemplate(
    examples=examples, example_prompt=example_prompt,
    prefix=system_prompt, suffix="Input: {input}\nOutput:",
    input_variables=["input"], example_separator="\n\n"
)

@tool
def generate_rules(user_input):
    """Use this to generate rules."""
    chain = prompt | llm
    return chain.invoke(dict(input=user_input)).content

@tool
def find_suitable_log_event(attack):
    """
    Use this to find the relevant log sources to use for detection.
    """
    # TODO: Align with logging standards in the future
    template = (
        r"You are an experienced security operations center operator. Your role is to determine the right log events to use for detecting cyber attacks."
        r"The list of log events are as follow:"
        r"Event ID 1: Process creation - The process creation event provides extended information about a newly created process. The full command line provides context on the process execution. The ProcessGUID field is a unique value for this process across a domain to make event correlation easier. The hash is a full hash of the file with the algorithms in the HashType field."
        r"Event ID 2: A process changed a file creation time - The change file creation time event is registered when a file creation time is explicitly modified by a process. This event helps tracking the real creation time of a file. Attackers may change the file creation time of a backdoor to make it look like it was installed with the operating system. Note that many processes legitimately change the creation time of a file; it does not necessarily indicate malicious activity."
        r"Event ID 3: Network connection - The network connection event logs TCP/UDP connections on the machine. It is disabled by default. Each connection is linked to a process through the ProcessId and ProcessGuid fields. The event also contains the source and destination host names IP addresses, port numbers and IPv6 status."
        r"Event ID 4: Sysmon service state changed - The service state change event reports the state of the Sysmon service (started or stopped)."
        r"Event ID 5: Process terminated - The process terminate event reports when a process terminates. It provides the UtcTime, ProcessGuid and ProcessId of the process."
        r"Event ID 6: Driver loaded - The driver loaded events provides information about a driver being loaded on the system. The configured hashes are provided as well as signature information. The signature is created asynchronously for performance reasons and indicates if the file was removed after loading."
        r"Event ID 7: Image loaded - The image loaded event logs when a module is loaded in a specific process. This event is disabled by default and needs to be configured with the '–l' option. It indicates the process in which the module is loaded, hashes and signature information. The signature is created asynchronously for performance reasons and indicates if the file was removed after loading. This event should be configured carefully, as monitoring all image load events will generate a significant amount of logging."
        r"Event ID 8: CreateRemoteThread - The CreateRemoteThread event detects when a process creates a thread in another process. This technique is used by malware to inject code and hide in other processes. The event indicates the source and target process. It gives information on the code that will be run in the new thread: StartAddress, StartModule and StartFunction. Note that StartModule and StartFunction fields are inferred, they might be empty if the starting address is outside loaded modules or known exported functions."
        r"Event ID 9: RawAccessRead - The RawAccessRead event detects when a process conducts reading operations from the drive using the \\.\ denotation. This technique is often used by malware for data exfiltration of files that are locked for reading, as well as to avoid file access auditing tools. The event indicates the source process and target device."
        r"Event ID 10: ProcessAccess - The process accessed event reports when a process opens another process, an operation that’s often followed by information queries or reading and writing the address space of the target process. This enables detection of hacking tools that read the memory contents of processes like Local Security Authority (Lsass.exe) in order to steal credentials for use in Pass-the-Hash attacks. Enabling it can generate significant amounts of logging if there are diagnostic utilities active that repeatedly open processes to query their state, so it generally should only be done so with filters that remove expected accesses."
        r"Event ID 11: FileCreate - File create operations are logged when a file is created or overwritten. This event is useful for monitoring autostart locations, like the Startup folder, as well as temporary and download directories, which are common places malware drops during initial infection."
        r"Event ID 12: RegistryEvent (Object create and delete) - Registry key and value create and delete operations map to this event type, which can be useful for monitoring for changes to Registry autostart locations, or specific malware registry modifications."
        r"Event ID 13: RegistryEvent (Value Set) - This Registry event type identifies Registry value modifications. The event records the value written for Registry values of type DWORD and QWORD."
        r"Event ID 14: RegistryEvent (Key and Value Rename) - Registry key and value rename operations map to this event type, recording the new name of the key or value that was renamed."
        r"Event ID 15: FileCreateStreamHash - This event logs when a named file stream is created, and it generates events that log the hash of the contents of the file to which the stream is assigned (the unnamed stream), as well as the contents of the named stream. There are malware variants that drop their executables or configuration settings via browser downloads, and this event is aimed at capturing that based on the browser attaching a Zone.Identifier 'mark of the web' stream."
        r"Event ID 16: ServiceConfigurationChange - This event logs changes in the Sysmon configuration - for example when the filtering rules are updated."
        r"Event ID 17: PipeEvent (Pipe Created) - This event generates when a named pipe is created. Malware often uses named pipes for interprocess communication."
        r"Event ID 18: PipeEvent (Pipe Connected) - This event logs when a named pipe connection is made between a client and a server."
        r"Event ID 19: WmiEvent (WmiEventFilter activity detected) - When a WMI event filter is registered, which is a method used by malware to execute, this event logs the WMI namespace, filter name and filter expression."
        r"Event ID 20: WmiEvent (WmiEventConsumer activity detected) - This event logs the registration of WMI consumers, recording the consumer name, log, and destination."
        r"Event ID 21: WmiEvent (WmiEventConsumerToFilter activity detected) - When a consumer binds to a filter, this event logs the consumer name and filter path."
        r"Event ID 22: DNSEvent (DNS query) - This event is generated when a process executes a DNS query, whether the result is successful or fails, cached or not. The telemetry for this event was added for Windows 8.1 so it is not available on Windows 7 and earlier."
        r"Event ID 23: FileDelete (File Delete archived) - A file was deleted. Additionally to logging the event, the deleted file is also saved in the ArchiveDirectory (which is C:\Sysmon by default)."
        r"Event ID 24: ClipboardChange (New content in the clipboard) - This event is generated when the system clipboard contents change."
        r"Event ID 25: ProcessTampering (Process image change) - This event is generated when process hiding techniques such as 'hollow' or 'herpaderp' are being detected."
        r"If none of the log events can be used to detect the attack, just tell the user: No relevant log event found."
        r"The log event to detect {attack} is: "
    )
    prompt = PromptTemplate.from_template(template)
    chain = prompt | llm
    return chain.invoke(dict(attack=attack)).content


rule_generator_agent = create_react_agent(
    model=llm,
    tools=[generate_rules, find_suitable_log_event],
    name="rule_generator"
)

if __name__ == "__main__":
    # print(generate_rules("Help create a rule to detect named pipe impersonation."))
    rule_generator_agent.get_graph().draw_mermaid_png(output_file_path="graph.png")

    def print_stream(stream):
        for s in stream:
            message = s["messages"][-1]
            if isinstance(message, tuple): print(message)
            else: message.pretty_print()

    inputs = dict(messages=[("user", "help to create a rule to detect DLL Search Order Hijacking")])
    print_stream(rule_generator_agent.stream(inputs, stream_mode="values"))