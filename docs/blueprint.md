# Agent Zero Architecture Blueprint

## Overview
Agent Zero is a hierarchical AI agent system built on async Python with Docker containerization.

## Core Architecture

### Layer Structure

#### 1. Domain Layer (`agent.py`, `models.py`)
- **Agent**: Core agent implementation with monologue message loop
- **AgentContext**: Session context management
- **AgentConfig**: Agent configuration data
- **ModelConfig**: LLM provider and model configuration

#### 2. Tool Layer (`python/tools/`)
- Tools are standalone classes with execute() method
- Base pattern: Tool base class with lifecycle hooks
- Integrated via tool discovery mechanism

#### 3. Extension Layer (`python/extensions/`)
- Lifecycle hooks: agent_init, message_loop_start/end, tool_execute_before/after
- Naming convention: numbered files for execution order
- Extensibility points: 23+ extension directories

#### 4. Helper Layer (`python/helpers/`)
- Utilities for memory, vector DB, history, tokens, etc.
- Cross-cutting concerns: logging, errors, localization

#### 5. API Layer (`python/api/`)
- FastAPI endpoints for Web UI
- State management via AgentContext singleton

#### 6. Presentation Layer (`webui/`, `run_ui.py`)
- Web interface
- Docker runtime container

## Dependency Flow

```
Presentation (webui)
    ↓
API (python/api)
    ↓
Domain (Agent, AgentContext)
    ↓
Tools/Extensions (python/tools, python/extensions)
    ↓
Helpers (python/helpers)
    ↓
Infrastructure (Docker, LLM providers)
```

## Key Patterns

### 1. Extension System
- Callback-based lifecycle hooks
- Extension injection points throughout monologue loop
- Execution order controlled by filename prefixes

### 2. Tool System
- Dynamic tool discovery and execution
- MCP (Model Context Protocol) tool integration
- Tool result processing and history management

### 3. History & Context Management
- Message history with summarization
- Context window optimization
- Memory consolidation

### 4. Streaming Architecture
- Async streaming for reasoning and response
- Extension-based stream filtering
- Real-time UI updates

## Current Architecture Smells

### 1. Agent Class God Object (agent.py:329-922) - PARTIALLY ADDRESSED
- 593 lines - violates SRP
- Mixes: orchestration, history management, tool execution, streaming
- Hard to test, hard to extend
- **Progress**: Tool execution extracted to ToolCoordinator (~2025-01-07)

### 2. Direct Dependencies Between Layers - PARTIALLY ADDRESSED
- Agent directly imports tools, helpers, models
- Tools depend on Agent instance
- Circular dependency potential
- **Progress**: Tool operations now use coordinator interface

### 3. Extension System Coupling
- Extensions receive full Agent instance
- Direct manipulation of agent state
- Hard to reason about side effects
- **Note**: Tool extensions still use agent, but operations are now cleaner

### 4. Configuration Sprawl
- AgentConfig, ModelConfig, settings.py, .env
- No single source of truth
- Configuration validation scattered

## Target Architecture

### Separation of Concerns

#### Agent Orchestrator
- Coordinate monologue loop
- Manage lifecycle hooks
- Delegate to specialized coordinators

#### Tool Coordinator
- Tool discovery and execution
- MCP integration
- Tool result processing

#### History Coordinator
- Message history management
- Summarization
- Context window management

#### Stream Coordinator
- Stream management
- Extension filtering
- Real-time updates

### Interface Contracts

```python
class IToolExecutor:
    async def execute_tool(self, name: str, args: dict) -> ToolResult
    async def get_tool(self, name: str) -> Tool | None

class IHistoryManager:
    async def add_message(self, message: Message)
    async def get_history(self) -> list[Message]
    async def consolidate(self)

class IStreamHandler:
    async def handle_reasoning(self, chunk: str, full: str)
    async def handle_response(self, chunk: str, full: str)
```

### Dependency Inversion

```python
class Agent:
    def __init__(
        self,
        tool_executor: IToolExecutor,
        history_manager: IHistoryManager,
        stream_handler: IStreamHandler,
        # ...
    ):
        self.tool_executor = tool_executor
        self.history_manager = history_manager
        self.stream_handler = stream_handler
```

## Migration Strategy

### Phase 1: Extract Interfaces - IN PROGRESS
- Define contracts for coordinators ✅
- Extract tool execution to separate module ✅
- Extract history management to separate module (Pending)

### Phase 2: Extract Coordinators - IN PROGRESS
- Create ToolCoordinator ✅
- Create HistoryCoordinator (Pending)
- Create StreamCoordinator (Pending)

### Phase 3: Refactor Agent - IN PROGRESS
- Replace direct tool calls with ToolCoordinator ✅
- Replace history calls with HistoryCoordinator (Pending)
- Replace stream handling with StreamCoordinator (Pending)
- Reduce Agent to orchestration only (Pending)

### Phase 4: Extension Cleanup
- Pass only necessary data to extensions
- Create extension context objects
- Reduce extension surface area

## Success Metrics

- Agent class < 300 lines
- All coordinators have clear interfaces
- No circular dependencies
- Extension system operates via contracts only
- Configuration centralized in one place
- All components independently testable
