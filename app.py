"""
    Frontend interface for askjaime platform
    Check this out: https://www.gradio.app/guides/agents-and-tool-usage
"""
import gradio as gr
from gradio import ChatMessage

from backend.agents.llm import llm
from backend.agents import supervisor

async def interact_with_agents(prompt, history):
    # TODO: FIX THE SYSTEM PROMPT, FIX THE MESSAGES AND CHATBOT TOO
    history.append(ChatMessage(role="user", content=prompt))
    # yield messages
    output = []
    # async for chunk in supervisor.astream({"user": prompt}):
    async for chunk in supervisor.astream(
        {"messages": [{"role": "user", "content": prompt}]},
        # config=dict(
        #     configurable=dict(thread_id=1)
        # ),
        stream_mode="updates",
    ):
        print(chunk)
        if 'agent' in chunk.keys():
            agent_response = chunk['agent']['messages'][0]
            response_text = agent_response.text()
            #if "tool_calls" in agent_response.additional_kwargs.keys():
            if agent_response.tool_calls:
                # Tool invoked
                response = ChatMessage(role="assistant", 
                                       content=response_text,
                                       metadata={"title": f"🛠️ Used Tool: {agent_response.tool_calls[0]['name']}"})
            else:
                response = ChatMessage(role="assistant", content=response_text)
            history.append(response)
            output.append(response)
            yield output



    '''if "messages" in chunk.keys():
        tool_use = []
        response_text = ""
        for response in chunk["messages"]:
            if response.type == "tool":
                # tool call
                tool_use.append(response.name)
            elif response.type == "ai":
                if len(response.text()) == 0:
                    # There is an empty response from the llm when there is a tool call
                    continue
                else:
                    response_text = response.text()
        # agent_response = chunk["messages"][-1] # presumably [0] to get latest message, if stream mode = 'updates', but i don't think we should do that, it separates the output from the tool call, and the output from llm itself       
        if tool_use:
            response = ChatMessage(role="assistant", 
                                    content=response_text,
                                    metadata={"title": f"🛠️ Used Tools: {", ".join(tool_use)}"})
        else:
            response = ChatMessage(role="assistant", content=response_text)
    else:
        response = ChatMessage(role="assistant", content="assistant")
    history.append(response)
    yield response'''

chatbot = gr.Chatbot(value='',
                     placeholder="Hi, I am Otterini. You can ask me anything!",
                     show_copy_button=True,
                     type="messages",
                     height="70vh")

with gr.Blocks() as demo:
    logo = gr.Image("otter.jpg", height=100, width=100)
    chat_interface= gr.ChatInterface(
        fn = interact_with_agents,
        type="messages",
        title="Ask Otter",
        description=f"Powered by {llm.model_name.split(':')[0]}",
        chatbot=chatbot,
        show_progress='full',
        fill_height=True, 
        fill_width=True
    )

if __name__ == '__main__':
    # Use environment variable GRADIO_SERVER_NAME and GRADIO_SERVER_PORT to set host and port
    demo.launch(share=False)