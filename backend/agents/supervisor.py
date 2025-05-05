from .llm import llm
from .soc_coverage import get_soc_coverage, get_soc_rules
from .rules import generate_rules, find_suitable_log_event

from langgraph_supervisor import create_supervisor
from langgraph.prebuilt import create_react_agent

system_prompt = """
You are a central AI assistant responsible for routing user queries to the most appropriate specialized agent.

You have access to the following agents: 
- SOC Coverage Agent: Provides a summary of the security coverage of the Security Operations Center (SOC) for a particular TTP. Assign tasks related to SOC Coverage to this agent.
- Rule Generation Agent: Generates Splunk security rules to address a particular TTP. Assign tasks related to rule generation to this agent.

Your job is to:
1. Understand the user's request and identify the specific details.
2. Decide which agent is best suited to handle it.
3. Once identified, pass the query to the correct agent. Do not attempt to rewrite the query.
4. Once you get the response from the agent, return the response without any modifications.

Maintain a helpful, neutral tone. Never fabricate responses. Do not attempt to solve tasks yourself—your role is to delegate.
"""

# supervisor_workflow = create_supervisor(
#     model=llm,
#     agents=[soc_coverage_agent, rule_generator_agent],
#     prompt=system_prompt,
#     add_handoff_back_messages=False,
#     output_mode='last_message'
# )
# supervisor = supervisor_workflow.compile()
supervisor = create_react_agent(
    model=llm,
    tools=[get_soc_coverage, get_soc_rules, generate_rules, find_suitable_log_event]
)

if __name__ == "__main__":
    import asyncio
    def print_stream(stream):
        for s in stream:
            message = s["messages"][-1]
            if isinstance(message, tuple): print(message)
            else: message.pretty_print()
    
    async def main():
        inputs = dict(messages=[("user", "help to create a rule to detect DLL Search Order Hijacking")])
        print_stream(supervisor.astream(inputs, stream_mode="values"))
    
    asyncio.run(main())