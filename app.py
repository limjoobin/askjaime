"""
    Frontend interface for askjaime platform
    Check this out: https://www.gradio.app/guides/agents-and-tool-usage
"""
import gradio as gr
from gradio import ChatMessage
import random
import asyncio

from backend.agents import supervisor

chatbot = gr.Chatbot(value='',
                     placeholder="Hi, I am Jaime. You can ask me anything!",
                     show_copy_button=True,
                     type="messages")

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