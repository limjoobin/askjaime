import asyncio

from langchain_core.prompts import PromptTemplate, FewShotPromptTemplate
from langchain_core.tools import tool
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent

from .llm import llm

system_prompt = """
# IDENTITY and PURPOSE

You are an expert at evaluating cybersecurity threat risk exposure. You specialize in identifying detection coverage for Tactics, Techniques, and Procedures (TTPs), given a set of rules. 

Take a deep breath and think step by step about how to best accomplish this goal using the following steps.

# STEPS

- Recall the various threat scenarios associated with the TTP, and how the execution methods differ.

- Create a virtual whiteboard in your mind and list down all the behavioural patterns, such as indicators and signatures, associated with the TTP, across threat scenarios.

- Retrieve the rules currently implemented by the Security Operations Center (SOC)

- Read the rules provided throughly and think of the threat scenarios that this rule is able to address. 

- Identify the detection mechanism responsible for addressing the particular threat scenario.

# INSTRUCTIONS
Based on the rules retrieved from the Security Operations Center (SOC) listed below, evaluate the coverage of current SOC operations.
{rules}

# OUTPUT
Format the output into the following three sections.

DESCRIPTION
  - A short description of the TTP and its identified behavioural patterns. Also include examples of different execution methods of this TTP.

RULES COVERAGE
For each rule that you identify, write a short section containing the following:
  - What the rule is
  - A paragraph about the description of the rule
  - The threat scenario addressed by the rule
  - Explanation of how this rule addrresses the TTP, and the detection mechanism responsible.
Ensure that there is no repetition of rules.

SUMMARY
At the end, write a short paragraph to summarize your findings.
"""


# Probably abstract the system prompt to the agent
# prompt_template = """
# # IDENTITY and PURPOSE

# You are an expert at evaluating cybersecurity threat risk exposure. You specialize in identifying detection coverage for Tactics, Techniques, and Procedures (TTPs), given a set of rules. 

# Take a deep breath and think step by step about how to best accomplish this goal using the following steps.

# # STEPS

# - Recall the various threat scenarios associated with the TTP, and how the execution methods differ.

# - Create a virtual whiteboard in your mind and list down all the behavioural patterns, such as indicators and signatures, associated with the TTP, across threat scenarios.

# - Read the rules provided throughly and think of the threat scenarios that this rule is able to address. 

# - Identify the detection mechanism responsible for addressing the particular threat scenario.

# # INSTRUCTIONS
# You are given a set of Splunk rules meant for security detection. Based on the following rules, evaluate the coverage of the current SOC operations.

# Rules:
# {rules}

# Now, tell me how protected I am against {TTP}, based on the behaviour observed by common implementations of the TTP. Identify the rules that address the behaviour.

# You are required to state your thinking process, step-by-step.

# # OUTPUT FORMAT
# Format the output into the following three sections.

# DESCRIPTION
#   - A short description of the TTP and its identified behavioural patterns. Also include examples of different execution methods of this TTP.

# RULES COVERAGE
# For each rule that you identify, write a short section containing the following:
#   - A paragraph about the description of the rule
#   - The threat scenario addressed by the rule
#   - Explanation of how this rule addrresses the TTP, and the detection mechanism responsible.
# Ensure that there is no repetition of rules.

# SUMMARY
# At the end, write a short paragraph to summarize your findings.
# """


# prompt = PromptTemplate.from_template(prompt_template,
#                                       template_format='f-string',)
#                                       #partial_variables=variables)

@tool
async def get_soc_rules()-> str:
    """
        Retrieves the security rules currently implemented in the Security Operations Center (SOC)

        Parameters
        ----------
            None
        
        Returns
        -------
        rules: str
            A formatted string containing all the rules implemented in the SOC
    """
    async with MultiServerMCPClient(
        {
            "detection-engineering":{
                "url": "http://localhost:9000/sse",
                "transport": "sse"
            }
        }
    ) as client:
        rules = await client.get_resources(server_name="detection-engineering", uris="data://deployed-rules")
        print("Obtained rules")
        return rules[0].as_string()
    
@tool
def get_soc_coverage(rules):
    """
    Use to get the Security Operations Center (SOC) coverage given a set of rules
    """
    prompt = PromptTemplate.from_template(system_prompt)
    chain = prompt | llm
    return chain.invoke(dict(rules=rules)).content

        
async def main(agent):        
    TTP = 'T1547.001: Registry Run Keys / Startup Folder'
    # resp = await agent.ainvoke(
    #     {"messages": [{"role": "user",
    #                     "content": f"What is my SOC coverage for {TTP}"}]}
    # )
    # print(resp)
    async for event in soc_coverage_agent.astream({"user": f"What is my SOC coverage for {TTP}?"}, stream_mode="updates"):
        print(event)

soc_coverage_agent = create_react_agent(
                        model=llm,
                        tools=[get_soc_rules],
                        prompt=system_prompt,
                        name="soc-coverage-agent"
                    )

if __name__ == "__main__":
    # variables={
    #     "TTP": 'T1547.001: Registry Run Keys / Startup Folder',
    #     "rules": "\n".join(sample_rules)
    # }
    # chain = prompt | llm

    # print(chain.invoke(variables).content)

    asyncio.run(main(soc_coverage_agent))

    

    
