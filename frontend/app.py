"""
    Frontend interface for askjaime platform
    Check this out: https://www.gradio.app/guides/agents-and-tool-usage
"""
import gradio as gr
import random

from utils import system_prompt

chatbot_history = [
    {"role": "system", "content": system_prompt}
]

chatbot = gr.Chatbot(value=chatbot_history,
                     placeholder="Hi, I am Jaime. You can ask me anything!",
                     show_copy_button=True,
                     type="messages")


with gr.Blocks() as demo:
    chat_interface= gr.ChatInterface(
        fn=lambda message, history: random.choice(["Bombardiro Crocodillo", "Tung Tung Tung Sahur", "Tralalero Tralala", "Brr brr Patapim"]),
        type="messages",
        title="Ask Jaime",
        description="Powered by ...",
        chatbot=chatbot
    )

if __name__ == '__main__':
    # Use environment variable GRADIO_SERVER_NAME and GRADIO_SERVER_PORT to set host and port
    demo.launch(share=False)