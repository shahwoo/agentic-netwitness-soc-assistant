from langchain.agents import create_agent
from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import HumanMessage, SystemMessage
from langchain.tools import tool
from langchain.agents.middleware import wrap_model_call, ModelRequest, ModelResponse

llm = ChatOllama(
        model="hf.co/Mungert/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M", 
        temperature=0
    )

@tool
def my_custom_tool(user_input: str) -> str:
    """Useful for processing user requests. Input should be a string."""
    return f"Successfully processed: {user_input}"

SYSTEM_PROMPT = """You are an SOC investigative analyst.
"""

tools = [my_custom_tool]

agent = create_agent(
    model=llm, 
    tools=tools,
    system_prompt=SystemMessage(content=SYSTEM_PROMPT)
)


result = agent.invoke(
    {"messages": [{"role": "user", "content": "What is your role?"}]}
)