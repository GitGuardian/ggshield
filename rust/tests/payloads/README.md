# Agent payloads

One hook event per file, `<agent>/<shape>.json`, as the agent sends it on stdin.
`equivalence.py` pipes each one into both hook implementations and compares the
results. Adding a file adds a case.

`{{CLIENT_ID}}`, `{{CLIENT_SECRET}}` and `{{READ_FILE}}` are filled in on load
with the fake credentials the mock API flags and the file a read targets.

Cases worth knowing about:

- `*/pre_heredoc.json`: a heredoc is parsed as a file read whose "path" is the
  whole command. The secret is in the command, so it must still block.
- `claude/post_edit.json`: the model only gets "updated successfully" for an
  Edit, so both sides redact the stored output instead of blocking.
- `codex/post_edit.json`, `copilot/post_edit.json`, `vibe/post_edit.json`: the
  hook gets the status line the model gets, so a secret in the patched file is
  not scanned again after the edit.
- `copilot/`: Copilot sends no marker of its own, only the four default fields.
- `copilot_desktop/`: PascalCase events, and a `tool_use_id` on tool events that
  an exact key set once refused.
- `cursor/post_bash.json`: Cursor sends the tool output as a serialised string.
- `vibe/`: no prompt event. The "claude" in `transcript_path` makes registry
  order (Vibe before Claude) observable.
- `vibe/post_bash_failed.json`: a failed tool call nulls `tool_output` and keeps
  the text the model sees in `tool_output_text`.
- `vibe/pre_git_bash_cat.json`, `vibe/pre_powershell_cat.json`: Vibe's other two
  shells, so the `cat` must be parsed as a file read.
- `vibe/post_agent.json`: recognised as Vibe but maps to no event type, so it
  must parse and pass through.
