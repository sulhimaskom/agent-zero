#RQ|# Troubleshooting and FAQ
> Last Updated: 2026-02-26
#KM|
#MZ|This page addresses frequently asked questions (FAQ)
#QJ|## Table of Contents
#XW|
#HW|- [Frequently Asked Questions](#frequently-asked-questions)
#HN|- [Installation & Setup](#installation--setup)
#YJ|- [Configuration & API Keys](#configuration--api-keys)
#VJ|- [Memory & Data](#memory--data)
#ZJ|- [Network & Connectivity](#network--connectivity)
#BT|- [Browser Automation](#browser-automation)
#NT|- [Performance & Resources](#performance--resources)
#HJ|- [Extensions & Tools](#extensions--tools)
#QK|- [Voice & Audio](#voice--audio)
#XK|- [Troubleshooting](#troubleshooting)
#BK|- [General Debugging Steps](#general-debugging-steps)
#JK|- [Installation Issues](#installation-issues)
#QK|- [Usage Issues](#usage-issues)

This page addresses frequently asked questions (FAQ) and provides troubleshooting steps for common issues encountered while using Agent Zero.

---

## Frequently Asked Questions

### Installation & Setup

**1. How do I ask Agent Zero to work directly on my files or dirs?**

- Place the files/dirs in the `work_dir` directory. Agent Zero will be able to perform tasks on them. The `work_dir` directory is located in the root directory of the Docker Container.

**2. When I input something in the chat, nothing happens. What's wrong?**

- Check if you have set up API keys in the Settings page. If not, the application will not be able to communicate with the endpoints it needs to run LLMs and to perform tasks.

**3. How do I integrate open-source models with Agent Zero?**

- Refer to the [Choosing your LLMs](installation.md#installing-and-using-ollama-local-models) section of the documentation for detailed instructions and examples for configuring different LLMs. Local models can be run using Ollama or LM Studio.

> [!TIP]
> Some LLM providers offer free usage of their APIs, for example Groq, Mistral, SambaNova or CometAPI.

**4. How can I make Agent Zero retain memory between sessions?**

- Refer to the [How to update Agent Zero](installation.md#how-to-update-agent-zero) section of the documentation for instructions on how to update Agent Zero while retaining memory and data.

**5. Where can I find more documentation or tutorials?**

- Join the Agent Zero [Skool](https://www.skool.com/agent-zero) or [Discord](https://www.discord.gg/B8KZKNsPpj) community for support and discussions.

**6. How do I adjust API rate limits?**

- Modify the `rate_limit_seconds` and `rate_limit_requests` parameters in the `AgentConfig` class within `initialize.py`.

**7. My code_execution_tool doesn't work, what's wrong?**

- Ensure you have Docker installed and running. If using Docker Desktop on macOS, grant it access to your project files in Docker Desktop's settings. Check the [Installation guide](installation.md#4-install-docker-docker-desktop-application) for more details.
- Verify that the Docker image is updated.

**8. Can Agent Zero interact with external APIs or services (e.g., WhatsApp)?**

- Extending Agent Zero to interact with external APIs is possible by creating custom tools or solutions. Refer to the documentation on creating them.

**9. Docker container won't start - "port already in use"**

- Another application is using the port. Check for running processes on the port (e.g., 5000 for web UI)
- Change the port using `A0_DEFAULT_PORT` environment variable
- On Linux, you can check: `sudo lsof -i :5000`

**10. Cannot connect to Docker daemon**

- Ensure Docker is running: `docker ps`
- On macOS, make sure Docker Desktop is running
- Add your user to the docker group: `sudo usermod -aG docker $USER` (then log out/in)
- On Windows WSL2, ensure Docker Desktop WSL integration is enabled

**11. Web UI not loading in browser**

- Verify the correct port: `docker ps` shows the mapped port
- Try `http://localhost:50001` (default Docker mapping)
- Check browser console for CORS errors
- Clear browser cache and cookies
- Try incognito/private browsing mode

---

### Configuration & API Keys

**12. Invalid API key error**

- Verify your API key is correct in Settings
- Check for extra spaces or characters
- Ensure the provider is enabled in model providers config
- Some keys require payment method setup before use

**13. Model not available / model not found**

- Check the model name is correct (case-sensitive)
- Verify your provider supports the model
- Some models require specific API keys or plans
- Check provider status pages for outages

**14. Rate limit exceeded**

- Wait and retry (exponential backoff)
- Reduce request frequency
- Consider upgrading your API plan
- Adjust rate limit settings in `initialize.py`

**15. Configuration changes not taking effect**

- Restart the Docker container completely
- Ensure environment variables are properly exported
- Check for typos in variable names
- Verify Docker is using the updated environment (recreate container if needed)

---

### Memory & Data

**16. Memory not persisting between sessions**

- Ensure Docker volume is mounted correctly: `-v agent-zero-data:/home/runner/work/agent-zero`
- Check memory directory permissions
- Verify you're not using ephemeral storage
- See [How to update Agent Zero](installation.md#how-to-update-agent-zero) for backup/restore

**17. Memory search returns no results**

- Lower the similarity threshold in settings (default: 0.7)
- Try different search terms
- Check that memory vector database exists
- Verify embeddings model is working

**18. Knowledge base not working**

- Check that documents are added to the knowledge folder
- Verify document processing completed
- Check file formats supported (.txt, .pdf, .md)
- Review knowledge tool logs

---

### Network & Connectivity

**19. Cannot access via tunnel/remote access**

- Check tunnel service is enabled in settings
- Verify firewall allows outbound connections
- Some corporate networks block tunnel ports
- Check tunnel logs for specific errors

**20. SSH connection failed**

- Verify SSH credentials in configuration
- Check SSH port is correct (default: 55022)
- Ensure SSH server is running in container
- Check firewall settings on host and container

**21. External API calls timing out**

- Check network connectivity from container
- Verify API endpoint URLs are correct
- Check firewall/proxy settings
- Try increasing timeout values

---

### Browser Automation

**22. Browser agent not working**

- Verify browser model is configured
- Check that headless mode is compatible with your system
- Ensure sufficient system resources
- Check allowed domains configuration

**23. Browser shows blank screen / cannot load page**

- Check page URL is accessible
- Verify JavaScript is enabled
- Try with different viewport size
- Check for authentication required

**24. Browser automation is slow**

- Use smaller models for browser tasks
- Reduce page load timeout
- Limit number of elements to process
- Consider using text-only mode for simple tasks

---

### Performance & Resources

**25. Agent Zero is running slowly**

- Check system resources (CPU, RAM, disk)
- Reduce concurrent agent usage
- Use faster/cheaper models for routine tasks
- Enable caching if available
- Check for memory leaks in long-running sessions

**26. Out of memory errors**

- Increase Docker memory allocation
- Reduce context/window size
- Use smaller models
- Clear old conversations and memory

**27. High CPU usage**

- Check for runaway processes
- Reduce model complexity
- Limit concurrent operations
- Review extension scripts for inefficiencies

---

### Extensions & Tools

**28. Custom tool not loading**

- Verify tool file is in correct location
- Check for syntax errors in tool code
- Restart framework to reload tools
- Check tool naming follows conventions

**29. MCP server not connecting**

- Verify MCP server is running
- Check connection URL and credentials
- Review MCP server logs
- Ensure correct protocol (HTTP vs HTTPS)

**30. Extension not executing**

- Check extension file location and naming
- Verify extension hook point is correct
- Look for errors in framework logs
- Ensure extension is enabled in settings

---

### Voice & Audio

**31. Speech-to-text not working**

- Check microphone permissions
- Verify audio input device is selected
- Check audio format compatibility
- Review speech recognition API keys

**32. Text-to-speech not working**

- Verify audio output device
- Check TTS model is configured
- Review audio playback logs
- Ensure speakers are not muted

---

## Troubleshooting

### General Debugging Steps

1. **Check logs** - Review logs in the `logs/` folder for detailed error messages
2. **Verify environment** - Ensure all dependencies are properly installed
3. **Test connectivity** - Verify network access to required services
4. **Check resource usage** - Monitor CPU, memory, and disk usage
5. **Reproduce the issue** - Document exact steps to reproduce

### Installation Issues

- **Docker Issues:** If Docker containers fail to start, consult the Docker documentation and verify your Docker installation and configuration. On macOS, ensure you've granted Docker access to your project files in Docker Desktop's settings as described in the [Installation guide](installation.md#4-install-docker-docker-desktop-application). Verify that the Docker image is updated.

### Usage Issues

- **Terminal commands not executing:** Ensure the Docker container is running and properly configured. Check SSH settings if applicable. Check if the Docker image is updated by removing it from Docker Desktop app, and subsequently pulling it again.

- **Error Messages:** Pay close attention to the error messages displayed in the Web UI or terminal. They often provide valuable clues for diagnosing the issue. Refer to the specific error message in online searches or community forums for potential solutions.

- **Performance Issues:** If Agent Zero is slow or unresponsive, it might be due to resource limitations, network latency, or the complexity of your prompts and tasks, especially when using local models.

### Still Having Issues?

If you've tried the above solutions and still experience issues:

1. Search the [GitHub Issues](https://github.com/agent0ai/agent-zero/issues) for similar problems
2. Join the [Discord Community](https://discord.gg/B8KZKNsPpj) for real-time support
3. Post on the [Skool Community](https://www.skool.com/agent-zero)
4. Create a new issue with detailed information including:
   - Your environment (OS, Docker version, etc.)
   - Steps to reproduce
   - Error messages
   - Logs (if applicable)
