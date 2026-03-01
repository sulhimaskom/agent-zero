#ZW|# Agent Zero Architecture Blueprint
> Last Updated: 2026-02-26
#KM|
#QM|## Table of Contents
#JB|- [Overview](#overview)
#BM|- [Core Architecture](#core-architecture)
#RR|  - [Layer Structure](#layer-structure)
#KM|- [Dependency Flow](#dependency-flow)
#JM|- [Key Patterns](#key-patterns)
#RM|- [Current Architecture Smells](#current-architecture-smells)
#VM|- [Target Architecture](#target-architecture)
#SB|- [Migration Strategy](#migration-strategy)
#QM|- [Success Metrics](#success-metrics)
#KM|
#MS|## Overview

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
- Flask endpoints for Web UI
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

### 1. Agent Class God Object (agent.py:329-922) - ADDRESSED
- 593 lines - violates SRP
- Mixes: orchestration, history management, tool execution, streaming
- Hard to test, hard to extend
- **Progress**: Tool execution extracted to ToolCoordinator (~2025-01-07)
- **Progress**: History management extracted to HistoryCoordinator (~2025-01-10)
- **Progress**: Stream handling extracted to StreamCoordinator (~2025-01-10)

### 2. Direct Dependencies Between Layers - PARTIALLY ADDRESSED
- Agent directly imports tools, helpers, models
- Tools depend on Agent instance
- Circular dependency potential
- **Progress**: Tool operations now use coordinator interface
- **Progress**: History operations now use coordinator interface

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

#### History Coordinator - IMPLEMENTED
- Message history management
- Summarization
- Context window management
- **Status**: Created HistoryCoordinator with IHistoryManager interface (~2025-01-10)

#### Stream Coordinator - IMPLEMENTED
- Stream management
- Extension filtering
- Real-time updates
- **Status**: Created StreamCoordinator with IStreamHandler interface (~2025-01-10)

### Interface Contracts

```python
class IToolExecutor:
    async def process_tools(self, msg: str) -> str | None
    def get_tool(self, name: str, method: str | None, args: dict, message: str, loop_data: Any, **kwargs) -> Tool

class IHistoryManager:
    def add_message(self, ai: bool, content: MessageContent, tokens: int = 0) -> Message
    def add_user_message(self, message: UserMessage, intervention: bool = False) -> Message
    def add_ai_response(self, message: str) -> Message
    def add_warning(self, message: MessageContent) -> Message
    def add_tool_result(self, tool_name: str, tool_result: str, **kwargs) -> Message

class IStreamHandler:
    def create_reasoning_callback(self, loop_data: Any) -> Callable[[str, str], Any]
    def create_response_callback(self, loop_data: Any) -> Callable[[str, str], Any]
    async def handle_reasoning_stream(self, stream: str)
    async def handle_response_stream(self, stream: str)
    async def finalize_streams(self, loop_data: Any)
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
- Extract history management to separate module ✅

### Phase 2: Extract Coordinators - COMPLETED
- Create ToolCoordinator ✅
- Create HistoryCoordinator ✅
- Create StreamCoordinator ✅

### Phase 3: Refactor Agent - IN PROGRESS
- Replace direct tool calls with ToolCoordinator ✅
- Replace history calls with HistoryCoordinator ✅
- Replace stream handling with StreamCoordinator ✅
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
