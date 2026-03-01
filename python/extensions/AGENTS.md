# /workspaces/agent-zero/python/extensions

Lifecycle hook extensions for agent message loop - 35 files in 23 hook directories.

## STRUCTURE

Extensions organized by hook points in agent execution flow. Each hook directory contains `.py` files executed at that point.

## WHERE TO LOOK

**agent_init/** - Agent initialization (`_10_initial_message.py`, `_15_load_profile_settings.py`)

**before_main_llm_call/** - Before LLM invocation (`_10_log_for_stream.py`)

**message_loop_start/** - Start of message processing (`_10_iteration_no.py`)

**message_loop_end/** - End of message processing (`_10_organize_history.py`, `_90_save_chat.py`)

**message_loop_prompts_after/** - After prompt building (`_50_recall_memories.py`, `_60_include_current_datetime.py`, `_70_include_agent_info.py`, `_75_include_project_extras.py`, `_91_recall_wait.py`)

**message_loop_prompts_before/** - Before prompt building (`_90_organize_history_wait.py`)

**system_prompt/** - System prompt construction (`_10_system_prompt.py`, `_20_behaviour_prompt.py`)

**response_stream/** - Response streaming (`_10_log_from_stream.py`, `_15_replace_include_alias.py`, `_20_live_response.py`)

**response_stream_chunk/** - Streaming response chunks (`_10_mask_stream.py`)

**response_stream_end/** - End of response stream (`_10_mask_end.py`)

**reasoning_stream/** - Reasoning streaming (`_10_log_from_stream.py`)

**reasoning_stream_chunk/** - Reasoning chunks (`_10_mask_stream.py`)

**reasoning_stream_end/** - End of reasoning (`_10_mask_end.py`)

**monologue_start/** - Monologue start (`_10_memory_init.py`, `_60_rename_chat.py`)

**monologue_end/** - Monologue end (`_50_memorize_fragments.py`, `_51_memorize_solutions.py`, `_90_waiting_for_input_msg.py`)

**tool_execute_before/** - Before tool execution (`_10_replace_last_tool_output.py`, `_10_unmask_secrets.py`)

**tool_execute_after/** - After tool execution (`_10_mask_secrets.py`)

**hist_add_before/** - Before history add (`_10_mask_content.py`)

**hist_add_tool_result/** - Before tool result add (`_90_save_tool_call_file.py`)

**error_format/** - Error formatting (`_10_mask_errors.py`)

**user_message_ui/** - User message UI updates (`_10_update_check.py`)

**util_model_call_before/** - Before utility model calls (`_10_mask_secrets.py`)

## CONVENTIONS

Numeric prefixes determine execution order: `_10_*.py` runs before `_20_*.py`, which runs before `_90_*.py`. Files in `/agents/{profile}/extensions/{hook}/` override default extensions in `/python/extensions/{hook}/`. All extension classes inherit from `Extension` base class and implement async `execute()` method.
