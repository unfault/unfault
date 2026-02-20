---
name: unfault-config
description: >-
  Show or change unfault's configuration, including the LLM provider used for AI-powered insights (unfault review). Use when asked about unfault setup, to switch models, or to check API key status.
disable-model-invocation: true
---

## unfault config — manage configuration

Show the current unfault configuration or set up the LLM provider used by
`unfault review` for AI-powered insights.

### Commands

```bash
# Show all current configuration
unfault config show

# Show with unmasked API keys
unfault config show --show-secrets

# Configure OpenAI
unfault config llm openai --model gpt-4 --api-key <KEY>

# Configure Anthropic (Claude)
unfault config llm anthropic --model claude-3-5-sonnet-latest --api-key <KEY>

# Configure local Ollama
unfault config llm ollama --endpoint http://localhost:11434 --model llama3.2

# Configure a custom OpenAI-compatible endpoint
unfault config llm custom --endpoint https://api.example.com/v1 --model my-model --api-key <KEY>

# Show LLM configuration only
unfault config llm show

# Remove LLM configuration
unfault config llm remove
```

### LLM providers

| Provider | Default model | API key env var |
|----------|--------------|-----------------|
| `openai` | `gpt-4` | `OPENAI_API_KEY` |
| `anthropic` | `claude-3-5-sonnet-latest` | `ANTHROPIC_API_KEY` |
| `ollama` | `llama3.2` | *(none required)* |
| `custom` | *(required)* | *(optional)* |

### Notes

- API keys can be passed via `--api-key` or set as environment variables (preferred).
- The LLM is only used by `unfault review`. Graph commands (`graph impact`, `graph critical`,
  etc.) are fully local and do not require any LLM configuration.
- Configuration is stored at `~/.config/unfault/config.json`.
