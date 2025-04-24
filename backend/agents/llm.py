"""
This file is used to define the LLM agent to connect to the local LLM server.
It should be used in all the agents to refer to the llm
"""
from langchain_openai import OpenAI

llm = OpenAI(base_url="http://localhost:8080/v1",
             api_key="not_needed")

if __name__ == "__main__":
    print(llm.invoke("The meaning of life is"))