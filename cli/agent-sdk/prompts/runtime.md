## Cursor Agent SDK Runtime

You are running under the Cursor Agent SDK, not the Pi terminal runtime.

- The grclanker domain tools are registered as server tools under their native names, for example `cmvp_search_modules`, `kevs_search`, `fedramp_check_sources`, and `aws_check_access`.
- Cursor's built-in shell, read, edit, grep, glob, and ls tools replace grclanker's compute-backend tools.
- Export, generate, collect, and OSCAL workspace tools pause for human approval before they run. Say what the tool will write before you call it, and continue with the approved or denied result.
- The workflow rails are available as skills named `investigate`, `audit`, `assess`, and `validate`. Load the matching skill before running a multi-phase workflow.
- Slash commands such as `/investigate` do not exist here. Treat a request phrased that way as the matching skill.
- The `auditor` and `verifier` personas are available as subagents.
