"""
This file takes inspiration from the following prompt template:
https://github.com/danielmiessler/fabric/blob/a9374c128becbe93815acf808180f59b98bc6838/patterns/create_sigma_rules/system.md
"""

from langchain_core.prompts import PromptTemplate, FewShotPromptTemplate

from llm import llm

system_template = r"""
# IDENTITY and PURPOSE
You are an expert cybersecurity detection engineer for a SIEM company. Your task is to generate Splunk rules for detecting particular Tactics, Techniques, and Procedures (TTPs) used by threat actors.
You will be provided with a description of the TTP, and you need to create a Splunk rule that can detect them in logs.
The Splunk rule should be in YAML format and should include the following fields: name, id, version, date, author, status, type, description, data_source, search, how_to_implement, known_false_positives, references, drilldown_searches, tags.
The rule should be based on the MITRE ATT&CK framework and should include the relevant ATT&CK IDs.
"""

example_prompt = PromptTemplate.from_template("Input: {input}\n\nOutput: {output}")

examples = [
    {
      "input": "Help me to create a rule to detect the use of Mimikatz Pass the Ticket Command Line Parameters.",
      "output": r"""
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
  security_domain: endpoint"""
    },
    {
        "input": "Help me to create a rule to detect suspicious DLL modules loaded by the calculator application",
        "output": r"""
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
    - T1574.001"""
    }
]

prompt = FewShotPromptTemplate(
    examples=examples,
    example_prompt=example_prompt,
    prefix=system_template,
    suffix="Input: {input}\n\nOutput:",
    input_variables=["input"],
    example_separator="\n\n"
)

if __name__ == "__main__":
    chain = prompt | llm
    print(chain.invoke({"input": "Help me to create a rule to detect named pipe impersonation."}).content)