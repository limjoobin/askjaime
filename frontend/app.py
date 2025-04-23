"""
    Frontend interface for askjaime platform
    Check this out: https://www.gradio.app/guides/agents-and-tool-usage
"""
import gradio as gr

# Put it all here for now, eventually will move it into their own individual file for easier customization.
example_messages = [
    {"text": "Give me an example of ..."}
]

chatbot = gr.Chatbot(placeholder="Hi, I am Jaime. You can ask me anything!",
                     type="messages")

with gr.Blocks() as demo:
    chat_interface= gr.ChatInterface(
        fn=lambda message, history: "dog",
        type="messages",
        title="Ask Jaime",
        description="Powered by ...",
        examples=example_messages,
        chatbot=chatbot
    )

if __name__ == '__main__':
    # Use environment variable GRADIO_SERVER_NAME and GRADIO_SERVER_PORT to set host and port
    demo.launch(share=False)