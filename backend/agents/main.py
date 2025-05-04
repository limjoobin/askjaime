from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import StateGraph, START, END
from langgraph.graph.state import CompiledStateGraph

from llm import llm
from state import State

def chatbot(state: State):
    return State(messages=[llm.invoke(state["messages"])])

def build_graph():
    graph_builder = StateGraph(State)
    graph_builder.add_node(chatbot)
    graph_builder.add_edge(START, "chatbot")
    graph_builder.add_edge("chatbot", END)
    
    # TODO: Replace the checkpointer with a persistent storage
    graph = graph_builder.compile(MemorySaver())
    return graph

def stream_graph_updates(graph: CompiledStateGraph, user_input: str):
    for event in graph.stream(
            {"messages": [{"role": "user", "content": user_input}]},
            config=dict(
                configurable=dict(thread_id=1)
            )
        ):
        for value in event.values():
            yield value["messages"][-1].content

def main(debug=False):
    graph = build_graph()
    if debug: graph.get_graph().draw_mermaid_png(output_file_path="graph.png")

    while True:
        user_input = input("User > ")
        if user_input.lower() in ("quit", "exit", "q"):
            print("Agent >", "Goodbye!")
            break
        for msg in stream_graph_updates(graph, user_input):
            print("Agent >", msg)

if __name__ == "__main__":
    main(debug=True)