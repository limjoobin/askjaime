"""
    Frontend interface for askjaime platform
    Check this out: https://www.gradio.app/guides/agents-and-tool-usage
"""
import gradio as gr
from gradio import ChatMessage
import random
import asyncio

from langgraph_supervisor import create_supervisor

from backend.agents import llm, soc_coverage_agent


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

chatbot_history = [
    {"role": "system", "content": system_prompt}
]

chatbot = gr.Chatbot(value=chatbot_history,
                     placeholder="Hi, I am Jaime. You can ask me anything!",
                     show_copy_button=True,
                     type="messages")

supervisor_workflow = create_supervisor(
    model=llm,
    agents=[soc_coverage_agent],
    prompt=system_prompt,
    add_handoff_back_messages=False,
    output_mode='last_message'
)
supervisor = supervisor_workflow.compile()

async def interact_with_agents(prompt, messages):
    # TODO: FIX THE SYSTEM PROMPT, FIX THE MESSAGES AND CHATBOT TOO
    messages.append(ChatMessage(role="user", content=prompt))
    yield messages

    async for chunk in supervisor.astream({"user": prompt}):
        print(chunk)
        if "supervisor" in chunk.keys():
            message = chunk['supervisor']['messages'][0]
            print(message)
            additional_kwargs = message.additional_kwargs
            if "tool_calls" in additional_kwargs:
                tool_message = chunk['supervisor']['messages'][1].text()
                messages.append(ChatMessage(role="assistant", 
                                            content=message.text(),
                                            metadata={"title": f"🛠️ Using {tool_message}"}))
            else:
                messages.append(ChatMessage(role="assistant", content=message.text()))
            yield messages
        elif "soc-coverage-agent" in chunk.keys():
            message = chunk['soc-coverage-agent']['messages'][0]
            messages.append(ChatMessage(role="assistant", 
                                            content=message.text(),
                                            metadata={"title": f"🛠️ Answer obtained from SOC Coverage Agent"}))

with gr.Blocks() as demo:
    chat_interface= gr.ChatInterface(
        fn = interact_with_agents,
        type="messages",
        title="Ask Jaime",
        description="Powered by ...",
        chatbot=chatbot
    )

if __name__ == '__main__':
    # Use environment variable GRADIO_SERVER_NAME and GRADIO_SERVER_PORT to set host and port
    demo.launch(share=False)