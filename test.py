import asyncio

from backend.agents import supervisor

if __name__ == "__main__":
    def print_stream(stream):
        for s in stream:
            message = s["messages"][-1]
            if isinstance(message, tuple): print(message)
            else: message.pretty_print()
    
    async def main():
        inputs = dict(messages=[("user", "am I covered against DLL sideloading?")])
        async for event in supervisor.astream(inputs, stream_mode="values"):
            message = event["messages"][-1]
            try:
                if isinstance(message, tuple): print(message)
                else: message.pretty_print()
            except:
                print(message)
    
    asyncio.run(main())