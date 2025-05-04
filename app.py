"""
    Frontend interface for askjaime platform
    Check this out: https://www.gradio.app/guides/agents-and-tool-usage
"""
import gradio as gr
import random


system_prompt = """
You are a central AI assistant responsible for routing user queries to the most appropriate specialized agent.

You have access to the following agents: 
- MathSolver: Handles math problems and calculations.
- TravelPlanner: Plans trips and recommends destinations, flights, hotels.
- ResumeCoach: Provides resume feedback and job application advice.

Your job is to:
1. Understand the user's request.
2. Decide which agent is best suited to handle it.
3. If unsure, ask clarifying questions.
4. Once identified, pass the query to the correct agent and return their response.

Maintain a helpful, neutral tone. Never fabricate responses. Do not attempt to solve tasks yourself—your role is to delegate.
"""

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