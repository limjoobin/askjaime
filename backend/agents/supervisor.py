from .llm import llm
from .soc_coverage import soc_coverage_agent
from .rules import rule_generator_agent

from langgraph_supervisor import create_supervisor

system_prompt = """
You are a central AI assistant responsible for routing user queries to the most appropriate specialized agent.

You have access to the following agents: 
- SOC Coverage: Provides a summary of the security coverage of the Security Operations Center (SOC) for a particular TTP.

Your job is to:
1. Understand the user's request.
2. Decide which agent is best suited to handle it.
3. Once identified, pass the query to the correct agent and return their response.

Maintain a helpful, neutral tone. Never fabricate responses. Do not attempt to solve tasks yourself—your role is to delegate.
"""

supervisor_workflow = create_supervisor(
    model=llm,
    agents=[soc_coverage_agent],
    prompt=system_prompt,
    add_handoff_back_messages=False,
    output_mode='last_message'
)
supervisor = supervisor_workflow.compile()