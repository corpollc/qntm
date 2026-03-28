# How to Add End-to-End Encryption to Your LangChain Agents

Your multi-agent system passes tasks, results, and sometimes API keys between agents. If those agents run on different machines — or even different cloud accounts — that communication is probably plaintext.

This tutorial shows how to give each LangChain agent a persistent cryptographic identity and encrypted communication channel using qntm. Setup takes about 2 minutes.

## What you'll build

Two LangChain agents that:
1. Each have a persistent Ed25519 identity
2. Communicate over end-to-end encrypted channels (the relay can't read messages)
3. Can be extended with multi-sig API approval (optional)

## Prerequisites

- Python 3.10+
- `pip install langchain langchain-openai` (or your preferred LLM provider)
- `pip install qntm`

## Step 1: Create identities for each agent

Each agent gets its own identity directory. Keys persist across restarts.

```bash
# Agent 1: Research Agent
export QNTM_HOME=~/.qntm-research-agent
qntm identity generate

# Agent 2: Writer Agent
export QNTM_HOME=~/.qntm-writer-agent
qntm identity generate
```

## Step 2: Create a conversation and exchange invites

```bash
# Research Agent creates the channel
QNTM_HOME=~/.qntm-research-agent qntm convo create --name "research-pipeline"
# Note the conv_id from the output

# Research Agent creates an invite
QNTM_HOME=~/.qntm-research-agent qntm convo invite <conv-id>
# Note the invite token

# Writer Agent joins
QNTM_HOME=~/.qntm-writer-agent qntm convo join <invite-token>
```

## Step 3: Create a qntm messaging tool for LangChain

```python
import subprocess
import json
import os
from langchain.tools import tool

def qntm_cmd(args: list[str], home: str) -> dict:
    """Run a qntm CLI command with a specific identity."""
    env = {**os.environ, "QNTM_HOME": home}
    result = subprocess.run(
        ["uvx", "qntm"] + args,
        capture_output=True, text=True, env=env
    )
    return json.loads(result.stdout)

CONV_ID = "your-conv-id-here"

@tool
def send_encrypted_message(message: str) -> str:
    """Send an end-to-end encrypted message to the research pipeline."""
    result = qntm_cmd(["send", CONV_ID, message], os.environ["QNTM_HOME"])
    if result["ok"]:
        return f"Message sent (seq {result['data']['sequence']})"
    return f"Send failed: {result.get('error', 'unknown')}"

@tool
def receive_encrypted_messages() -> str:
    """Receive new encrypted messages from the research pipeline."""
    result = qntm_cmd(["recv", CONV_ID], os.environ["QNTM_HOME"])
    if result["ok"]:
        messages = result["data"]["messages"]
        if not messages:
            return "No new messages"
        return "\n".join(
            f"[{m['sender']}]: {m['unsafe_body']}" for m in messages
        )
    return f"Receive failed: {result.get('error', 'unknown')}"
```

## Step 4: Wire into your LangChain agents

```python
from langchain_openai import ChatOpenAI
from langchain.agents import create_tool_calling_agent, AgentExecutor
from langchain_core.prompts import ChatPromptTemplate

llm = ChatOpenAI(model="gpt-4o")

# Research Agent
os.environ["QNTM_HOME"] = os.path.expanduser("~/.qntm-research-agent")
research_tools = [send_encrypted_message, receive_encrypted_messages]

research_prompt = ChatPromptTemplate.from_messages([
    ("system", """You are a research agent. When you find relevant information,
    send it to the writer agent via encrypted messaging. Always use
    send_encrypted_message to communicate your findings."""),
    ("human", "{input}"),
    ("placeholder", "{agent_scratchpad}"),
])

research_agent = AgentExecutor(
    agent=create_tool_calling_agent(llm, research_tools, research_prompt),
    tools=research_tools,
    verbose=True
)

# Writer Agent (in a separate process or thread, with different QNTM_HOME)
os.environ["QNTM_HOME"] = os.path.expanduser("~/.qntm-writer-agent")
writer_tools = [send_encrypted_message, receive_encrypted_messages]

writer_prompt = ChatPromptTemplate.from_messages([
    ("system", """You are a writer agent. Check for new encrypted messages
    from the research agent, then write content based on what you receive.
    Use receive_encrypted_messages to check for new findings."""),
    ("human", "{input}"),
    ("placeholder", "{agent_scratchpad}"),
])

writer_agent = AgentExecutor(
    agent=create_tool_calling_agent(llm, writer_tools, writer_prompt),
    tools=writer_tools,
    verbose=True
)
```

## Step 5: Run it

```python
# In process/machine 1:
research_agent.invoke({"input": "Research the latest developments in quantum computing and send your findings"})

# In process/machine 2:
writer_agent.invoke({"input": "Check for new research findings and write a summary"})
```

The messages between these agents are encrypted end-to-end. Even if the relay (inbox.qntm.corpo.llc) is compromised, the attacker sees only opaque ciphertext.

## What's happening under the hood

1. **Identity**: Each agent has an Ed25519 signing key and X25519 key agreement key
2. **Key exchange**: When the writer joins the conversation, X3DH establishes a shared secret
3. **Encryption**: Every message is AEAD-encrypted with a unique key derived from the Double Ratchet
4. **Relay**: The relay stores CBOR-encoded ciphertext blobs — it cannot decrypt them
5. **Verification**: Each message includes an Ed25519 signature — recipients verify sender identity

## Next: Add multi-sig API approval

Want to add a Stripe integration where 2-of-3 agents must approve before any charge executes?

```bash
# Promote the conversation to require 2-of-3 approval
qntm gate-promote <conv-id> --url https://gateway.corpo.llc --threshold 2

# Store the Stripe key (encrypted to the gateway, not readable by agents or relay)
qntm gate-secret <conv-id> --name stripe --value sk_live_xxx

# Agent proposes a charge
qntm gate-run <conv-id> --recipe stripe.create-charge \
  --arg amount=5000 --arg currency=usd

# Two agents must approve before it executes
qntm gate-approve <conv-id> <request-id>
```

See the [API Gateway docs](../api-gateway.md) for the full walkthrough.

## Summary

| What | How |
|------|-----|
| Identity | Ed25519 keys in `QNTM_HOME` directory |
| Encryption | X3DH + Double Ratchet (same as Signal) |
| Transport | HTTPS to relay, which stores ciphertext only |
| Integration | JSON CLI output → easy to parse from any language |
| Multi-sig | API Gateway with m-of-n cryptographic approval |

Questions? Open an issue on [GitHub](https://github.com/corpollc/qntm) or visit [chat.corpo.llc](https://chat.corpo.llc).
po.llc).
