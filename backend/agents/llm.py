"""
This file is used to define the LLM agent to connect to the local LLM server.
It should be used in all the agents to refer to the llm
"""
from dotenv import dotenv_values
from langchain_openai import ChatOpenAI

configs = dotenv_values()

llm = ChatOpenAI(
        base_url=f"{configs['llm_server']}/v1",
        api_key=f"{configs['api_key']}",
        model="llama3.3:70b-instruct-q6_K",
        temperature=0
    )

if __name__ == "__main__":
    print(llm.invoke("The meaning of life is"))