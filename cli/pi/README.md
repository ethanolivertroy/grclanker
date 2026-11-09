# Pi terminal host

This directory implements grclanker's default terminal application, setup wizard, session launching, and compute backends. The entry point is `cli/index.ts`, launched by `cli/bin/grclanker.js`. It embeds Pi 1.4 and adds grclanker's GRC role, workflows, skills, and native tools.

For a source installation, use Git, npm, and Node.js 22.19 or newer. From the repository root:

```bash
npm --prefix cli ci
npm --prefix cli run build
node cli/bin/grclanker.js tools
node cli/bin/grclanker.js setup
```

For a local model, install Ollama, start it with a large context window, and pull the model before setup:

```bash
OLLAMA_CONTEXT_LENGTH=128000 ollama serve
```

In a second terminal:

```bash
ollama pull gemma4
node cli/bin/grclanker.js setup
```

Choose `Local-first` and `gemma4`. If Ollama already runs as an app or service, change that instance's context setting instead of starting a second server. Setup also supports hosted OpenAI, Anthropic, and Google models. For hosted use, provide `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or `GEMINI_API_KEY` for the selected provider, or use `/login` in a session.

Anthropic setup defaults to `claude-sonnet-4-6`. Use a full model ID: Pi still expands shorthand names through its own matching. New hosted sessions use the configured model, while a resumed session restores its saved model. Cancelling setup exits without launching Pi or persisting a partial model choice.

Run a first task:

```bash
node cli/bin/grclanker.js env doctor
node cli/bin/grclanker.js investigate "Check CVE-2024-3400 in the CISA KEV catalog. Cite the evidence and explain uncertainty."
```

The workflow opens an interactive session. Public lookups need network access; organization assessments additionally need that vendor's credentials. Settings, stored login credentials, and conversations live under `~/.grclanker/agent`. Exit with `/quit` or Ctrl+D and reopen conversations with `/resume` or the session command printed on exit.

Set `GRCLANKER_HOME` to a separate base directory, or directly to its `.grclanker` directory, to move this state and Pi's managed `fd`/`rg` cache together. The same cache location is used by `grclanker env exec`; env helpers do not require model setup.

The Pi host registers the shared domain tools plus its seven compute tools. Common GRC implementations live in `cli/extensions/grc-tools/`; `cli/core/` contains the domain-only registry and common tool handling used by other hosts. Pi-specific session, setup, and compute behavior belongs here. Pi settings do not configure SDK adapter sessions or their shell/file capabilities.

The source package and dependency build are shared with the SDK adapters. This directory is not an independently published package. The release installer provides the Pi application without requiring a source checkout:

```bash
curl -fsSL https://grclanker.com/install | bash
grclanker setup
```

See the complete [Pi deployment guide](https://grclanker.com/docs/getting-started/pi-runtime/) for tenant setup, workflow examples, persistence, and troubleshooting.
