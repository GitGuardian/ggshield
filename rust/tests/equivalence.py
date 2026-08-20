"""Equivalence harness: ggshield-hook vs the Python ai-hook.

Runs both implementations against the same payloads, the same
`.gitguardian.yaml`, and the same localhost mock API, then compares stdout AND
the request body each one POSTed. Nothing is ever sent to the real GitGuardian
API.

The comparison is semantic, not byte-for-byte: JSON is compared as data, so key
order and separator style are free to differ, but every *value* must match --
including warning and `systemMessage` prose, which is user-facing. The one
deliberate exception is a content-derived sha256 document identifier, which both
sides must produce but whose value is allowed to differ (see `same_request`).

  python3 tests/equivalence.py            # equivalence only
  python3 tests/equivalence.py --bench N  # also time both, N iterations/side

Five matrices:
  agents   5 assistants x 6 payload shapes x {clean, secret}
  config   .gitguardian.yaml cases: discovery, precedence, and every key that
           changes the verdict or the request
  range    ranged reads: the lines an agent reads are the lines that
           reach the API, LF and CRLF, plus the agents that have no range
  content  what a file's *bytes* do: byte-order marks, a NUL byte, a legacy
           code page, and a file too large to scan at all
  mention  relative and absolute `@`-mentions, resolved against the event cwd
  batch    a prompt mentioning more files than fit in one scan
  mcp      MCP tool calls: the activity report each side sends, the server name
           it resolves, and the policy verdict it honours
  cache    the clean-verdict cache: what gets remembered, what does
           not, and that both implementations share one cache file
  dotenv   a `.env` naming GITGUARDIAN_* settings: the instance and token both
           implementations resolve from it
  extra    fail-open, and the unrecognized-agent case

Every payload fixture is copied from tests/unit/verticals/ai/test_hooks.py, so
the shapes are the ones ggshield's own tests consider realistic.

Both sides get a *fresh* cache dir per run, otherwise the payload debounce
(`has_already_been_seen`) makes the second implementation exit silently and the
comparison is meaningless.
"""

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
REPO = ROOT.parent
# The venv lives in the main checkout; PYTHONPATH below points the interpreter
# at *this* worktree's sources so we compare against the same commit the Rust
# port was written from.
PYTHON = Path(
    os.environ.get(
        "GGSHIELD_VENV_PYTHON",
        Path.home() / "ggworkspace" / "ggshield" / ".venv" / "bin" / "python",
    )
)
# Which ggshield sources the Python side imports. This worktree by default;
# override it to compare against a tree that carries a Python PR this port
# depends on, which is the only way to tell "the Rust port is wrong" apart from
# "the Python PR has not merged yet".
PY_SOURCES = Path(os.environ.get("GGSHIELD_PYTHON_SOURCES", REPO))
# The dispatcher, named `ggshield`: it answers `secret scan ai-hook` natively and
# execs `ggshield-py` for anything else, so RS_CMD carries that exact argv.
RUST = ROOT / "target" / "release" / "ggshield"

PY_CMD = [str(PYTHON), "-m", "ggshield", "secret", "scan", "ai-hook"]
RS_CMD = [str(RUST), "secret", "scan", "ai-hook"]
# The shipped PyInstaller bundle, if this machine has one installed. It is the
# real baseline: a source checkout and a frozen binary do not start alike.
FROZEN = Path("/usr/local/bin/ggshield")
FROZEN_CMD = [str(FROZEN), "secret", "scan", "ai-hook"]

# Fabricated credentials, shaped like AWS keys. Must match mock_api.py.
CLIENT_ID = "AKIA4SVQEXAMPLE01"
CLIENT_SECRET = "bB0mVX8s2example5zRq7Nn1LxKp9Wc3TyUvGh4Jd"
READ_FILE = "/tmp/ggshield-hook-equivalence-creds.env"
# A multi-line fixture, for the ranged-read matrix.
RANGE_FILE = "/tmp/ggshield-hook-equivalence-range.txt"
# Byte-identical to READ_FILE, under a different name: proves the filename
# is part of the verdict cache key.
COPY_FILE = "/tmp/ggshield-hook-equivalence-creds-copy.env"
# The file the encoding/size matrix rewrites for each of its cases. Its directory
# is also the `cwd` the @-mention cases resolve against, so a relative mention
# and an absolute file_path must land on this same path.
CONTENT_DIR = "/tmp"
CONTENT_NAME = "ggshield-hook-equivalence-content.env"
CONTENT_FILE = f"{CONTENT_DIR}/{CONTENT_NAME}"


def agent_bases():
    """The envelope each agent wraps its events in.

    These matter because `_detect_agent` keys off them, and nothing else.
    """
    claude = {
        "session_id": "69cc6a03-7034-4c49-8cf9-3805c292a15c",
        "transcript_path": "/home/user1/.claude/projects/foo/3b7ae0c5.jsonl",
        "cwd": "/home/user1/foo",
    }
    codex = {
        "session_id": "273ad859-3608-4799-9971-fa15ecb1a65c",
        "transcript_path": "/home/user/.codex/sessions/2026/04/30/session.jsonl",
        "cwd": "/home/user/project",
        "turn_id": "turn_123",
        "model": "gpt-5.4",
    }
    # Copilot CLI is detected by an EXACT key set, so its envelope must carry
    # nothing beyond the four default fields.
    copilot = {
        "timestamp": "2026-02-26T11:28:53.112Z",
        "session_id": "69cc6a03-7034-4c49-8cf9-3805c292a15c",
        "cwd": "/home/user1/foo",
    }
    vscode = {
        "timestamp": "2026-02-26T11:28:53.112Z",
        "session_id": "69cc6a03-7034-4c49-8cf9-3805c292a15c",
        "transcript_path": (
            "/home/user1/.config/Code/User/workspaceStorage/"
            "abc123/GitHub.copilot-chat/transcripts/69cc6a03.jsonl"
        ),
        "cwd": "/home/user1/foo",
    }
    cursor = {
        "conversation_id": "75fed8a8-2078-4e49-80d2-776b20d441c3",
        "generation_id": "1501ede6-b8ac-43f4-9943-0e218610c5c6",
        "model": "default",
        "cursor_version": "2.5.25",
        "workspace_roots": ["/home/user1/foo"],
        "transcript_path": (
            "/home/user1/.cursor/projects/foo/agent-transcripts/75fed8a8/75fed8a8.jsonl"
        ),
    }
    return {
        "claude": claude,
        "codex": codex,
        "copilot": copilot,
        "cursor": cursor,
        "vscode": vscode,
    }


def agent_payloads():
    """5 agents x 6 payload shapes, each in that agent's own dialect.

    Shapes are copied from tests/unit/verticals/ai/test_hooks.py.
    """
    bases = agent_bases()
    claude, codex = bases["claude"], bases["codex"]
    copilot, cursor, vscode = bases["copilot"], bases["cursor"], bases["vscode"]

    command = (
        f"aws configure set aws_access_key_id {CLIENT_ID} --secret {CLIENT_SECRET}"
    )
    prompt = f"deploy with key {CLIENT_ID} please"

    def shapes(base, *, prompt_event, pre, post, bash, read, output_key, output_value):
        return {
            "user_prompt": {**base, "hook_event_name": prompt_event, "prompt": prompt},
            "pre_bash": {
                **base,
                "hook_event_name": pre,
                "tool_name": bash,
                "tool_input": {"command": command},
            },
            "pre_read": {
                **base,
                "hook_event_name": pre,
                "tool_name": read,
                "tool_input": {"file_path": READ_FILE},
            },
            "pre_other": {
                **base,
                "hook_event_name": pre,
                "tool_name": "WebFetch",
                "tool_input": {"url": "https://example.com", "token": CLIENT_ID},
            },
            "post_bash": {
                **base,
                "hook_event_name": post,
                "tool_name": bash,
                "tool_input": {"command": "printenv"},
                output_key: output_value,
            },
            # Regression: a heredoc is parsed as a file read whose
            # "path" is the entire command, which used to make Path.is_file()
            # raise ENAMETOOLONG and abandon the scan. The secret is in the
            # command, so this must still block.
            "pre_heredoc": {
                **base,
                "hook_event_name": pre,
                "tool_name": bash,
                "tool_input": {
                    "command": f"cat > /tmp/out.env <<'EOF'\nAWS_KEY={CLIENT_ID}\nEOF",
                },
            },
        }

    return {
        "claude": shapes(
            claude,
            prompt_event="UserPromptSubmit",
            pre="PreToolUse",
            post="PostToolUse",
            bash="Bash",
            read="Read",
            output_key="tool_response",
            output_value={"stdout": CLIENT_ID, "stderr": "", "interrupted": False},
        ),
        "codex": shapes(
            codex,
            prompt_event="UserPromptSubmit",
            pre="PreToolUse",
            post="PostToolUse",
            bash="Bash",
            read="Read",
            output_key="tool_output",
            output_value={"output": CLIENT_ID, "exit_code": 0},
        ),
        "copilot": shapes(
            copilot,
            prompt_event="userPromptSubmitted",
            pre="PreToolUse",
            post="PostToolUse",
            bash="bash",
            read="view",
            output_key="tool_result",
            output_value={"output": CLIENT_ID},
        ),
        "cursor": shapes(
            cursor,
            prompt_event="beforeSubmitPrompt",
            pre="preToolUse",
            post="postToolUse",
            bash="Shell",
            read="Read",
            output_key="tool_output",
            # Cursor sends the tool output as an already-serialised string.
            output_value=json.dumps({"output": CLIENT_ID, "exitCode": 0}),
        ),
        "vscode": shapes(
            vscode,
            prompt_event="UserPromptSubmit",
            pre="PreToolUse",
            post="PostToolUse",
            bash="run_in_terminal",
            read="read_file",
            output_key="tool_response",
            output_value={"output": CLIENT_ID},
        ),
    }


def config_cases(ignore_sha):
    """`.gitguardian.yaml` cases: (name, local yaml, global yaml, expected).

    `None` for a yaml means "do not write this file at all". `expected` is the
    verdict the config should produce for the `pre_read` payload against a mock
    returning one known "AWS Keys" secret — asserted so the matrix cannot pass
    vacuously. Two implementations that both fail to read the config would
    agree with each other on every line and prove nothing.
    """
    return [
        ("no_config", None, None, "block"),
        ("minimal", "version: 2\n", None, "block"),
        # The secret is ignored by its literal value -> must not block.
        (
            "ignored_match_by_value",
            f"version: 2\nsecret:\n  ignored_matches:\n  - match: {CLIENT_ID}\n    name: fp\n",
            None,
            "allow",
        ),
        # ...and by the ignore sha of the whole policy break.
        (
            "ignored_match_by_sha",
            f"version: 2\nsecret:\n  ignored_matches:\n  - match: {ignore_sha}\n    name: fp\n",
            None,
            "allow",
        ),
        # A non-matching ignore entry must leave the block intact.
        (
            "ignored_match_irrelevant",
            "version: 2\nsecret:\n  ignored_matches:\n  - match: something-else\n    name: fp\n",
            None,
            "block",
        ),
        (
            "ignored_detector",
            "version: 2\nsecret:\n  ignored_detectors:\n  - AWS Keys\n",
            None,
            "allow",
        ),
        (
            "ignored_detector_other",
            "version: 2\nsecret:\n  ignored_detectors:\n  - Generic Password\n",
            None,
            "block",
        ),
        # source_uuid used to decline: it routed the scan to the
        # incident-creating endpoint. The hook now clears it on both sides, so
        # this must scan and block exactly like a config without it.
        (
            "source_uuid",
            "version: 2\nsecret:\n  source_uuid: 8b7e1f1a-0000-4000-8000-000000000000\n",
            None,
            "block",
        ),
        (
            "ignore_known_secrets",
            "version: 2\nsecret:\n  ignore_known_secrets: true\n",
            None,
            "allow",
        ),
        # all_secrets keeps ignored secrets, so the block comes back.
        (
            "all_secrets_overrides_ignore",
            "version: 2\nsecret:\n  all_secrets: true\n  ignored_matches:\n  - match: "
            f"{CLIENT_ID}\n    name: fp\n",
            None,
            "block",
        ),
        # Changes the filename in the POSTed request, not the verdict.
        (
            "filename_only",
            "version: 2\nsecret:\n  filename_only: true\n",
            None,
            "block",
        ),
        # ignored_paths must be a no-op on this path: the file is still scanned.
        (
            "ignored_paths_is_a_noop_here",
            "version: 2\nsecret:\n  ignored_paths:\n  - '**/*.env'\n  - 'tmp/*'\n",
            None,
            "block",
        ),
        # Dash spelling, and the root-level ignore_known_secrets legacy key.
        (
            "dashed_keys",
            "version: 2\nsecret:\n  ignore-known-secrets: true\n",
            None,
            "allow",
        ),
        (
            "root_ignore_known_secrets",
            "version: 2\nignore_known_secrets: true\n",
            None,
            "allow",
        ),
        # Global only.
        (
            "global_only",
            None,
            f"version: 2\nsecret:\n  ignored_matches:\n  - match: {CLIENT_ID}\n    name: fp\n",
            "allow",
        ),
        # Both: ignore lists accumulate across files.
        (
            "global_and_local_merge",
            "version: 2\nsecret:\n  ignored_matches:\n  - match: nothing\n    name: x\n",
            f"version: 2\nsecret:\n  ignored_matches:\n  - match: {CLIENT_ID}\n    name: fp\n",
            "allow",
        ),
        # Scalars: the local file wins.
        (
            "local_scalar_wins_over_global",
            "version: 2\nsecret:\n  ignore_known_secrets: false\n",
            "version: 2\nsecret:\n  ignore_known_secrets: true\n",
            "block",
        ),
        # --- v1 (legacy) configs. Python converts them; it does not reject.
        # A versionless file IS v1, which is why declining on v1 would have
        # disabled scanning for a large share of real configs.
        (
            "v1_matches_ignore_dict",
            f"version: 1\nmatches-ignore:\n  - name: fp\n    match: {CLIENT_ID}\n",
            None,
            "allow",
        ),
        (
            "v1_matches_ignore_bare_string",
            f"version: 1\nmatches-ignore:\n  - {ignore_sha}\n",
            None,
            "allow",
        ),
        (
            "v1_versionless",
            f"matches-ignore:\n  - name: fp\n    match: {CLIENT_ID}\n",
            None,
            "allow",
        ),
        (
            "v1_dashed_banlisted_detectors",
            "version: 1\nbanlisted-detectors:\n  - AWS Keys\n",
            None,
            "allow",
        ),
        (
            "v1_irrelevant_ignore",
            "version: 1\nmatches-ignore:\n  - name: fp\n    match: something-else\n",
            None,
            "block",
        ),
        # v1 keys that only produce a deprecation message.
        (
            "v1_deprecated_keys",
            "version: 1\nall_policies: true\nignore_default_excludes: true\n",
            None,
            "block",
        ),
        # paths-ignore converts to ignored_paths, still a no-op on this path.
        (
            "v1_paths_ignore_is_a_noop_here",
            "version: 1\npaths-ignore:\n  - '**/*.env'\n",
            None,
            "block",
        ),
        # A v1 global config merged with a v2 local one.
        (
            "v1_global_v2_local",
            "version: 2\nsecret:\n  ignored_matches:\n  - match: nothing\n    name: x\n",
            f"version: 1\nmatches-ignore:\n  - name: fp\n    match: {CLIENT_ID}\n",
            "allow",
        ),
        # Keys with no effect on this path must not change anything.
        (
            "irrelevant_keys",
            "version: 2\nverbose: true\nsecret:\n  show_secrets: true\n  "
            "prereceive_remediation_message: hello\n",
            None,
            "block",
        ),
        # insecure disables TLS certificate verification (session.verify=False in
        # core/client.py). It must SCAN, not decline: over the HTTP mock the flag
        # is a no-op on the wire, so both sides still block on the secret and the
        # stdout verdict is identical. The two mandatory warnings go to stderr,
        # which this harness does not diff. v1 `allow_self_signed` maps to it.
        (
            "insecure",
            "version: 2\ninsecure: true\n",
            None,
            "block",
        ),
        (
            "v1_allow_self_signed",
            "allow-self-signed: true\n",
            None,
            "block",
        ),
    ]


def read_range_cases():
    """Ranged reads. `(name, payload, lines, newline, verdict, window)`.

    A `Tool.READ` must scan the lines the agent is actually reading. Only those
    enter the model's context, and — the part that bites — a document over the
    API's 1 MiB limit is skipped client-side, so over-scanning a large file ends
    up scanning nothing at all and allowing the read.

    `window` is the 1-based inclusive slice of `lines` that must reach the API,
    stated outright rather than derived: one line of slack on each side of the
    requested range (see `line_slice`), because being one line out must never
    turn into content reaching the model unscanned. `None` means the whole file,
    and an empty list means nothing was sent at all.

    Every window case runs against an LF *and* a CRLF fixture. A CRLF file
    really does have "\\r" at the end of each line, so what we send must be a
    verbatim extract of it, not a normalised lookalike — that exact gap is what
    broke ranged reads on Windows.
    """
    # 60 lines, the fake credential on line 30.
    lines = [f"line {i}" for i in range(1, 61)]
    lines[29] = f"AWS_KEY={CLIENT_ID}"
    # Over the 1 MiB document limit, credential on line 3.
    big = ["x" * 100 for _ in range(13_000)]
    big[2] = f"AWS_KEY={CLIENT_ID}"

    bases = agent_bases()

    def read(agent, key, **tool_input):
        tool_name = {"vscode": "read_file", "copilot": "view"}.get(agent, "Read")
        return {
            **bases[agent],
            "hook_event_name": "preToolUse" if agent == "cursor" else "PreToolUse",
            "tool_name": tool_name,
            "tool_input": {key: RANGE_FILE, **tool_input},
        }

    cases = []
    for newline, tag in (("\n", "lf"), ("\r\n", "crlf")):
        cases += [
            # Claude Code: offset = first line, limit = number of lines.
            (
                f"claude_range_covers_the_secret_{tag}",
                read("claude", "file_path", offset=28, limit=5),
                lines,
                newline,
                "block",
                (27, 33),
            ),
            (
                f"claude_range_misses_the_secret_{tag}",
                read("claude", "file_path", offset=1, limit=5),
                lines,
                newline,
                "allow",
                (1, 6),
            ),
            # Open-ended: to the end of the file, not to some assumed cap.
            (
                f"claude_offset_only_reads_to_the_end_{tag}",
                read("claude", "file_path", offset=29),
                lines,
                newline,
                "block",
                (28, 60),
            ),
            # No offset means "from the first line", not "from nowhere".
            (
                f"claude_limit_only_starts_at_the_top_{tag}",
                read("claude", "file_path", limit=5),
                lines,
                newline,
                "allow",
                (1, 6),
            ),
            # Absent parameters mean everything: the previous behaviour.
            (
                f"claude_no_range_scans_the_whole_file_{tag}",
                read("claude", "file_path"),
                lines,
                newline,
                "block",
                None,
            ),
            # VS Code: startLine/endLine, 1-based and inclusive.
            (
                f"vscode_range_covers_the_secret_{tag}",
                read("vscode", "filePath", startLine=28, endLine=32),
                lines,
                newline,
                "block",
                (27, 33),
            ),
            (
                f"vscode_range_misses_the_secret_{tag}",
                read("vscode", "filePath", startLine=1, endLine=5),
                lines,
                newline,
                "allow",
                (1, 6),
            ),
        ]

    cases += [
        # Cursor's Read payload mimics Claude's and may well carry a range of
        # its own, but we have never seen one: reading Claude's key names here
        # would be a guess, and a wrong guess under-scans in silence.
        (
            "cursor_ignores_claude_style_range",
            read("cursor", "file_path", offset=1, limit=5),
            lines,
            "\n",
            "block",
            None,
        ),
        # Every Copilot CLI `view` payload we have carries only `path`.
        (
            "copilot_view_has_no_range",
            read("copilot", "path"),
            lines,
            "\n",
            "block",
            None,
        ),
        # Codex reads files by shelling out, and `cat` reads the whole file.
        (
            "codex_cat_has_no_range",
            {
                **bases["codex"],
                "hook_event_name": "PreToolUse",
                "tool_name": "shell",
                "tool_input": {"command": f"cat {RANGE_FILE}"},
            },
            lines,
            "\n",
            "block",
            None,
        ),
        # The headline case. Whole file: over the document limit, so it is
        # skipped outright — allowed, with nothing sent to the API at all.
        (
            "oversized_file_read_whole_is_never_scanned",
            read("claude", "file_path"),
            big,
            "\n",
            "allow",
            [],
        ),
        # ...the slice the agent actually reads scans, and blocks.
        (
            "oversized_file_read_in_range_still_blocks",
            read("claude", "file_path", offset=1, limit=10),
            big,
            "\n",
            "block",
            (1, 11),
        ),
    ]
    return cases


def compare_read_ranges(tmp):
    """Ranged reads must send exactly the lines the agent asked for."""
    failures = []
    print("\nRead ranges: the lines an agent reads are the lines we scan")
    log = tmp / "requests-read-range.jsonl"
    mock, port = start_mock("secret", log)
    try:
        for name, payload, lines, newline, expected, window in read_range_cases():
            content = newline.join(lines)

            def setup(content=content):
                # Bytes, not write_text: on Windows the latter would translate
                # "\n" to os.linesep and the CRLF fixture would stop being a
                # fixture.
                Path(RANGE_FILE).write_bytes(content.encode())

            verdict_ok, request_ok, py, rs, bodies = compare_one(
                tmp, log, port, f"range-{name}", payload, setup=setup
            )
            report(failures, f"range/{name}", verdict_ok, request_ok, py, rs)

            actual = "block" if b"deny" in py.stdout else "allow"
            if actual != expected:
                failures.append(f"range/{name} (expected {expected}, got {actual})")
                print(f"        ^ expected this read to {expected}, but it did not")

            # Teeth: the exact bytes that reached the API, on both sides. Two
            # properties, and both matter:
            #  - the document is a *verbatim* extract of the file. No newline
            #    rewriting, no stripped "\r": we scan what the agent reads, not
            #    a normalised lookalike of it.
            #  - it is the right window. `splitlines()` here just makes the
            #    check terminator agnostic, so LF and CRLF assert the same
            #    expectation.
            for side in ("python", "rust"):
                sent = [json.loads(body)[0]["document"] for body in bodies[side]]
                if window == []:
                    wanted_lines = None  # nothing must be sent at all
                elif window is None:
                    wanted_lines = lines
                else:
                    wanted_lines = lines[window[0] - 1 : window[1]]
                ok = (
                    sent == []
                    if wanted_lines is None
                    else len(sent) == 1
                    and sent[0] in content
                    and sent[0].splitlines() == wanted_lines
                )
                if not ok:
                    failures.append(f"range/{name} ({side} scanned the wrong lines)")
                    print(
                        f"        ^ {side} sent {len(sent)} document(s), "
                        f"wanted lines {window}: {str(sent)[:160]}"
                    )
    finally:
        mock.kill()
        Path(RANGE_FILE).unlink(missing_ok=True)
    return failures


def content_cases():
    """What a file's *bytes* do. `(name, bytes, verdict, posts, same_document)`.

    A file this hook cannot turn into text is not "skipped", it is **allowed**:
    the read goes through with nothing scanned and nothing said. So every one of
    these has to reach the API, except the oversized one, which Python answers
    from the file size alone and never reads.

    `same_document` is False for the one case where the two sides legitimately
    send different text: charset_normalizer guesses a code page for a BOM-less
    legacy encoding, the native hook decodes lossily. Secrets are ASCII and ASCII
    survives both, so the verdict still has to match — which is what is asserted.
    """
    secret = f"AWS_KEY={CLIENT_ID}\n".encode()
    text = f"AWS_KEY={CLIENT_ID}\n"
    return [
        ("utf8", secret, "block", 1, True),
        # What Notepad's "Unicode" and PowerShell's `Out-File` write.
        ("utf16le_bom", b"\xff\xfe" + text.encode("utf-16-le"), "block", 1, True),
        ("utf16be_bom", b"\xfe\xff" + text.encode("utf-16-be"), "block", 1, True),
        (
            "utf32le_bom",
            b"\xff\xfe\x00\x00" + text.encode("utf-32-le"),
            "block",
            1,
            True,
        ),
        ("utf8_bom", b"\xef\xbb\xbf" + secret, "block", 1, True),
        # The API answers 400 on a raw NUL byte, which used to fail the whole
        # event open; both sides substitute it before sending.
        ("nul_byte", secret + b"\x00trailing\n", "block", 1, True),
        # One byte of a legacy code page in a comment. The two sides render that
        # byte differently, so only the verdict is compared.
        ("one_latin1_byte", b"# caf\xe9\n" + secret, "block", 1, False),
        # Past four times the document ceiling no encoding could bring it under,
        # so Python never reads the file. Reading it first is how a multi-GB
        # `@big.log` became an OOM: no JSON, non-zero exit, unscanned read.
        (
            "over_four_times_the_ceiling",
            b"x" * (5 * 1024 * 1024) + secret,
            "allow",
            0,
            True,
        ),
    ]


def compare_content(tmp):
    """A file's bytes must reach the API whatever encoded them."""
    failures = []
    print("\nFile content: an undecodable or oversized file is an ALLOWED read")
    log = tmp / "requests-content.jsonl"
    mock, port = start_mock("secret", log)
    claude = agent_bases()["claude"]
    payload = {
        **claude,
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": CONTENT_FILE},
    }
    try:
        for name, raw, expected, posts, same_document in content_cases():

            def setup(raw=raw):
                Path(CONTENT_FILE).write_bytes(raw)

            before = len(read_requests(log))
            verdict_ok, request_ok, py, rs, bodies = compare_one(
                tmp, log, port, f"content-{name}", payload, setup=setup
            )
            # One side's requests only; `compare_one` ran both.
            per_side = (len(read_requests(log)) - before) // 2
            label = f"content/{name}"
            if same_document:
                report(failures, label, verdict_ok, request_ok, py, rs)
            else:
                print(f"  [{'MATCH' if verdict_ok else 'DIFF '}] {label}  (req=n/a)")
                if not verdict_ok:
                    failures.append(label)

            actual = verdict_of(py.stdout)
            if actual != expected or per_side != posts:
                failures.append(f"{label} (wanted {expected}/{posts} posts)")
                print(
                    f"        ^ wanted {expected} with {posts} post(s), "
                    f"got {actual} with {per_side}"
                )
            # Teeth for the NUL case: the substitute must be what went out.
            if name == "nul_byte":
                for side in ("python", "rust"):
                    document = json.loads(bodies[side][0])[0]["document"]
                    if "\0" in document or "\x1a" not in document:
                        failures.append(f"{label} ({side} sent a raw NUL)")
                        print(f"        ^ {side}: {document!r}")
    finally:
        mock.kill()
        Path(CONTENT_FILE).unlink(missing_ok=True)
    return failures


def mention_cases():
    """`@`-mentions in a prompt. `(name, prompt, verdict, filename)`.

    A mention is usually relative, and it is resolved against the event's `cwd`;
    a tool `file_path` for the same file is usually absolute. Both must produce
    the same identifier, or the file is scanned twice and cached under two keys.
    """
    return [
        ("relative", f"please check @{CONTENT_NAME}", "block", CONTENT_FILE),
        ("absolute", f"please check @{CONTENT_FILE}", "block", CONTENT_FILE),
        (
            "dot_segments",
            f"please check @./{CONTENT_NAME}",
            "block",
            CONTENT_FILE,
        ),
        (
            "parent_segment",
            f"please check @sub/../{CONTENT_NAME}",
            "block",
            CONTENT_FILE,
        ),
        # A mention of something that is not a file: the prompt itself is all
        # there is to scan, and it carries no secret.
        ("not_a_file", "please check @docs/nope.md", "allow", None),
    ]


def compare_mentions(tmp):
    """A relative `@`-mention resolves to the same file a tool call would read."""
    failures = []
    print("\n@-mentions: a relative mention is the file the agent will read")
    log = tmp / "requests-mentions.jsonl"
    mock, port = start_mock("secret", log)
    claude = {**agent_bases()["claude"], "cwd": CONTENT_DIR}
    try:
        for name, prompt, expected, filename in mention_cases():
            payload = {
                **claude,
                "hook_event_name": "UserPromptSubmit",
                "prompt": prompt,
            }

            def setup():
                Path(CONTENT_FILE).write_text(f"AWS_KEY={CLIENT_ID}\n")

            verdict_ok, request_ok, py, rs, bodies = compare_one(
                tmp, log, port, f"mention-{name}", payload, setup=setup
            )
            report(failures, f"mention/{name}", verdict_ok, request_ok, py, rs)

            actual = verdict_of(py.stdout)
            if actual != expected:
                failures.append(f"mention/{name} (expected {expected}, got {actual})")
                print(f"        ^ expected this mention to {expected}")
            if filename is None:
                continue
            # Teeth: the mention resolved to the absolute path, on both sides.
            for side in ("python", "rust"):
                names = {
                    document["filename"]
                    for body in bodies[side]
                    for document in json.loads(body)
                }
                if filename not in names:
                    failures.append(f"mention/{name} ({side} resolved it elsewhere)")
                    print(f"        ^ {side} sent {sorted(names)}")
    finally:
        mock.kill()
        Path(CONTENT_FILE).unlink(missing_ok=True)
    return failures


# One more file than `maximum_documents_per_scan` (20 in mock_api), so the batch
# has to be split -- and one chunk failing must not discard the others.
MENTIONED_FILES = 21
BATCH_DIR = "/tmp/ggshield-hook-equivalence-batch"


def compare_batches(tmp):
    """A prompt mentioning more files than fit one scan.

    `find_filepaths` returns a set on the Python side, so the *order* of the
    documents is not defined; what must match is which documents were sent and
    how they were split. The secret sits in the last file by name, so it is only
    found if every chunk is scanned.
    """
    failures = []
    print(f"\nBatching: one prompt mentioning {MENTIONED_FILES} files")
    log = tmp / "requests-batch.jsonl"
    mock, port = start_mock("secret", log)
    directory = Path(BATCH_DIR)
    names = [f"file{i:02d}.env" for i in range(MENTIONED_FILES)]
    claude = {**agent_bases()["claude"], "cwd": BATCH_DIR}
    payload = {
        **claude,
        "hook_event_name": "UserPromptSubmit",
        "prompt": "review " + " ".join(f"@{name}" for name in names),
    }

    def setup():
        shutil.rmtree(directory, ignore_errors=True)
        directory.mkdir(parents=True)
        for index, name in enumerate(names):
            content = f"AWS_KEY={CLIENT_ID}\n" if index == len(names) - 1 else "clean\n"
            (directory / name).write_text(content)

    try:
        verdict_ok, _, py, rs, bodies = compare_one(
            tmp, log, port, "batch-many-mentions", payload, setup=setup
        )
        print(f"  [{'MATCH' if verdict_ok else 'DIFF '}] batch/many_mentions")
        if not verdict_ok:
            failures.append("batch/many_mentions")
            print(f"        python exit={py.returncode} stdout={py.stdout[:200]!r}")
            print(f"          rust exit={rs.returncode} stdout={rs.stdout[:200]!r}")
        if verdict_of(py.stdout) != "block":
            failures.append("batch/many_mentions (expected a block)")
            print("        ^ the secret in the last mentioned file did not block")
        for side in ("python", "rust"):
            batches = [json.loads(body) for body in bodies[side]]
            sent = sorted(
                document["filename"] for batch in batches for document in batch
            )
            # The prompt payload is scanned too, under a sha256 of its text.
            wanted = sorted(
                [f"{BATCH_DIR}/{name}" for name in names]
                + [next(n for n in sent if IS_SHA256.match(n))]
            )
            if sent != wanted or sorted(len(b) for b in batches) != [2, 20]:
                failures.append(f"batch/many_mentions ({side} split it differently)")
                print(
                    f"        ^ {side} sent {[len(b) for b in batches]} "
                    f"document(s) per scan, {len(sent)} in total"
                )
    finally:
        mock.kill()
        shutil.rmtree(directory, ignore_errors=True)
    return failures


def cached_read_payloads():
    """A Claude Code `Read`, at PreToolUse and then at PostToolUse.

    The pair is the whole point of the verdict cache: both events resolve to the
    same document, but the two *stdin payloads* differ (event name, and Post
    carries the tool response), so `has_already_been_seen` — which debounces on
    raw stdin — cannot collapse them. Only a cache keyed on what we send the API
    can.
    """
    claude = agent_bases()["claude"]

    def read(path, event="PreToolUse"):
        payload = {
            **claude,
            "hook_event_name": event,
            "tool_name": "Read",
            "tool_input": {"file_path": path},
        }
        if event == "PostToolUse":
            payload["tool_response"] = {"content": "whatever the agent got back"}
        return payload

    return read


def write_read_files():
    """READ_FILE and a byte-identical copy under a different name."""
    write_read_file()
    Path(COPY_FILE).write_text(f"AWS_KEY={CLIENT_ID}\n")


def verdict_cache_cases():
    """Clean-verdict cache. `(name, mode, yaml, payloads, posts)`.

    `posts` is the number of /v1/multiscan calls the sequence must produce, and
    it is the assertion: caching is invisible in stdout, so agreeing on the
    verdict proves nothing here.
    """
    read = cached_read_payloads()
    pre_post = [read(READ_FILE), read(READ_FILE, "PostToolUse")]
    ignored = f"version: 2\nsecret:\n  ignored_matches:\n  - match: {CLIENT_ID}\n    name: fp\n"
    return [
        # The saving: one round trip for a read instead of two.
        ("clean_read_costs_one_round_trip", "clean", None, pre_post, 1),
        # A block is never cached — nothing to cache, and nothing that may be
        # answered locally.
        ("a_blocking_verdict_is_never_cached", "secret", None, pre_post, 2),
        # ...and neither is a verdict that is only clean because of *this*
        # project's ignore rules. Caching it would let one project's exclusion
        # allow the same content in a project that does not have it.
        ("a_locally_filtered_verdict_is_never_cached", "secret", ignored, pre_post, 2),
        # Identical content under a different name is a different document: the
        # filename is part of what we send, so it is part of the key.
        (
            "the_filename_is_part_of_the_key",
            "clean",
            None,
            [read(READ_FILE), read(COPY_FILE)],
            2,
        ),
    ]


def run_sequence(tmp, log, port, name, payloads, sides, *, local_config=None):
    """Run several hook events in ONE workdir, so cache state carries over.

    Returns, per side, the request bodies POSTed and the stdout of each run.
    Unlike `compare_one`, the point here is what the *second* invocation does
    with what the first one left behind.
    """
    posts, stdouts = {}, {}
    for side, cmd in sides:
        workdir = make_workdir(tmp, f"{name}-{side}", local_config=local_config)
        write_read_files()
        before = len(read_requests(log))
        stdouts[side] = [
            run(cmd, payload, port, workdir)[0].stdout for payload in payloads
        ]
        posts[side] = [r["body"] for r in read_requests(log)[before:]]
    return posts, stdouts


def compare_verdict_cache(tmp):
    """A clean verdict is remembered; anything else is asked again."""
    failures = []
    print("\nVerdict cache: a clean document is not scanned twice")
    both = (("python", PY_CMD), ("rust", RS_CMD))
    for case, mode, local, payloads, expected in verdict_cache_cases():
        log = tmp / f"requests-cache-{case}.jsonl"
        mock, port = start_mock(mode, log)
        try:
            posts, stdouts = run_sequence(
                tmp, log, port, f"cache-{case}", payloads, both, local_config=local
            )
        finally:
            mock.kill()
        ok = (
            same_requests(posts["python"], posts["rust"])
            and len(stdouts["python"]) == len(stdouts["rust"])
            and all(
                same_stdout(a, b) for a, b in zip(stdouts["python"], stdouts["rust"])
            )
            and len(posts["python"]) == expected
        )
        print(
            f"  [{'MATCH' if ok else 'DIFF '}] cache/{case}  "
            f"(python={len(posts['python'])} rust={len(posts['rust'])} "
            f"scans, wanted {expected})"
        )
        if not ok:
            failures.append(f"cache/{case}")
            for side in ("python", "rust"):
                print(f"        {side} stdout={str(stdouts[side])[:200]}")

    # The two implementations write the same file, in the same format, under the
    # same key. On a machine running both, one warm cache instead of two — and a
    # format drift would show up here rather than as a silent extra round trip.
    print("\nVerdict cache interop: one cache file, either implementation")
    read = cached_read_payloads()
    log = tmp / "requests-cache-interop.jsonl"
    mock, port = start_mock("clean", log)
    # Run it under a non-default `secret:` config too. The config fingerprint is
    # the third NUL-separated field of the key, so a drift in how it is rendered
    # is invisible when every setting is at its default.
    configs = {
        "default": None,
        "filename_only": "version: 2\nsecret:\n  filename_only: true\n",
    }
    try:
        for label, local in configs.items():
            for first, second in (("python", "rust"), ("rust", "python")):
                cmds = {"python": PY_CMD, "rust": RS_CMD}
                name = f"cache-interop-{label}-{first}"
                posts, _ = run_sequence(
                    tmp,
                    log,
                    port,
                    name,
                    [read(READ_FILE)],
                    ((first, cmds[first]),),
                    local_config=local,
                )
                wrote = len(posts[first])
                # Same workdir, so the same cache dir *and* the same config: the
                # second implementation must answer the PostToolUse event from
                # what the first left.
                workdir = tmp / f"{name}-{first}"
                before = len(read_requests(log))
                run(cmds[second], read(READ_FILE, "PostToolUse"), port, workdir)
                reused = len(read_requests(log)) - before == 0
                ok = wrote == 1 and reused
                print(
                    f"  [{'OK  ' if ok else 'FAIL'}] {label}: {first} scanned "
                    f"({wrote} call), "
                    f"{second} {'reused it' if reused else 'scanned again'}"
                )
                if not ok:
                    failures.append(f"cache-interop/{label}/{first}-then-{second}")
    finally:
        mock.kill()
        Path(COPY_FILE).unlink(missing_ok=True)
    return failures


# One MCP server, as `save_discovery_cache()` writes it. Schema-valid on purpose:
# `AIDiscovery.from_dict` rejects a partial configuration, and a rejected cache
# sends the Python side off to redo the whole discovery walk — which would probe
# the developer's real machine and make this matrix meaningless.
#
# "git hub" covers Claude Code, Codex and VS Code, "git.hub" is Copilot's (which
# only looks at its own), and the tool covers Cursor, which reports no server at
# all. All of them must come back as the canonical "GitHub".
#
# "Decoy" comes first and mangles to the same VS Code key ("git_hub") and the same
# Copilot key ("git-hub") as GitHub's own configurations, which is the interesting
# case: the two sides have to agree on *which* of the two servers answers, or a
# policy denying a tool on one is checked against the other. Its own names differ
# in case, so Claude Code and Codex — which do not lower-case, and where the first
# match wins on both sides — still resolve to GitHub.
AI_DISCOVERY = {
    "user": {
        "hostname": "equivalence-host",
        "username": "equivalence-user",
        "machine_id": "00000000-0000-4000-8000-00000000dead",
        "user_email": None,
    },
    "discovery_duration": 0.125,
    "agents": [],
    "servers": [
        {
            "name": "Decoy",
            "display_name": "Decoy",
            "tools": [],
            "resources": [],
            "prompts": [],
            "configurations": [
                {
                    "name": "GIT HUB",
                    "agent": "claude-code",
                    "scope": "user",
                    "transport": "stdio",
                    "project": None,
                    "command": "npx",
                    "args": [],
                    "env": {},
                    "url": None,
                    "headers": {},
                },
                {
                    "name": "GIT.HUB",
                    "agent": "copilot",
                    "scope": "user",
                    "transport": "stdio",
                    "project": None,
                    "command": "npx",
                    "args": [],
                    "env": {},
                    "url": None,
                    "headers": {},
                },
            ],
        },
        {
            "name": "GitHub",
            "display_name": "GitHub",
            "tools": [
                {"name": "delete_repository", "description": None, "arguments": None}
            ],
            "resources": [],
            "prompts": [],
            "configurations": [
                {
                    "name": "git hub",
                    "agent": "claude-code",
                    "scope": "user",
                    "transport": "stdio",
                    "project": None,
                    "command": "npx",
                    "args": [],
                    "env": {},
                    "url": None,
                    "headers": {},
                },
                {
                    "name": "git.hub",
                    "agent": "copilot",
                    "scope": "user",
                    "transport": "stdio",
                    "project": None,
                    "command": "npx",
                    "args": [],
                    "env": {},
                    "url": None,
                    "headers": {},
                },
            ],
        },
    ],
}

# What each agent calls the same tool on the same server. Three of the five cannot
# be split without the inventory above.
MCP_TOOL_NAMES = {
    "claude": "mcp__git_hub__delete_repository",
    "codex": "mcp__git_hub__delete_repository",
    # Copilot joins with "-" and its configuration name contains one.
    "copilot": "git-hub-delete_repository",
    # Cursor names the tool and nothing else.
    "cursor": "MCP:delete_repository",
    # VS Code joins with "_", and so do both halves.
    "vscode": "mcp_git_hub_delete_repository",
}

MCP_ARGUMENTS = {"owner": "acme", "repo": "prod", "confirm": True}


def mcp_payloads():
    """One MCP `PreToolUse` per agent, in that agent's own dialect."""
    bases = agent_bases()
    return {
        agent: {
            **bases[agent],
            "hook_event_name": "preToolUse" if agent == "cursor" else "PreToolUse",
            "tool_name": tool_name,
            "tool_input": MCP_ARGUMENTS,
        }
        for agent, tool_name in MCP_TOOL_NAMES.items()
    }


def seed_discovery_cache(workdir):
    """Install a *fresh* inventory, which is what makes the native path eligible.

    Both sides read this same file: Python trusts a cache younger than its TTL
    instead of re-walking, and the Rust hook has no walk at all — with a stale or
    absent file it declines the event to `ggshield-py`.
    """
    cache = workdir / "cache"
    cache.mkdir(parents=True, exist_ok=True)
    (cache / "ai_discovery.json").write_text(json.dumps(AI_DISCOVERY))


def activity_bodies(entries):
    """Every MCP activity report in `entries`, timestamps dropped.

    Filtered by path rather than compared in order: Python overlaps the activity
    report with the scan on a thread, so their arrival order is not a property to
    assert on. `timestamp` is the moment the hook ran, so it can only differ.
    """
    bodies = []
    for entry in entries:
        if "mcp-activity" not in entry["path"]:
            continue
        body = json.loads(entry["body"])
        body.pop("timestamp", None)
        bodies.append(body)
    return bodies


def compare_mcp(tmp):
    """An MCP tool call is two questions, and the hook has to ask both.

    Both sides must report the call, resolve the server to its canonical name, and
    honour the verdict — an organisation that denies `delete_repository` denies it
    whether or not the arguments carry a secret.
    """
    failures = []
    print("\nMCP activity: the call itself is checked, not just its arguments")
    for case, deny, expected in (
        ("permitted", "", "allow"),
        (
            "denied",
            "Deleting repositories is not allowed by your organization.",
            "block",
        ),
    ):
        log = tmp / f"requests-mcp-{case}.jsonl"
        # Clean, so the verdict on show is the policy one and not a secret.
        mock, port = start_mock("clean", log, mcp_deny=deny)
        try:
            for agent, payload in mcp_payloads().items():
                name = f"mcp/{case}/{agent}"
                results, entries = {}, {}
                for side, cmd in (("python", PY_CMD), ("rust", RS_CMD)):
                    workdir = make_workdir(tmp, f"mcp-{case}-{agent}-{side}")
                    seed_discovery_cache(workdir)
                    before = len(read_requests(log))
                    results[side], _ = run(cmd, payload, port, workdir)
                    entries[side] = read_requests(log)[before:]
                py, rs = results["python"], results["rust"]
                reports = {side: activity_bodies(entries[side]) for side in entries}

                verdict_ok = (
                    same_stdout(py.stdout, rs.stdout) and py.returncode == rs.returncode
                )
                request_ok = reports["python"] == reports["rust"]
                report(failures, name, verdict_ok, request_ok, py, rs)
                if not request_ok:
                    print(f"        python sent {reports['python']}")
                    print(f"          rust sent {reports['rust']}")

                # Teeth. Without these the two could agree by both doing nothing.
                for side, sent in reports.items():
                    if len(sent) != 1:
                        failures.append(f"{name} ({side} sent {len(sent)} reports)")
                        print(
                            f"        ^ {side} reported {len(sent)} activities, wanted 1"
                        )
                        continue
                    # The canonical server name, which is what a policy names.
                    wanted = {
                        "server": "GitHub",
                        "tool": "delete_repository",
                        "input": MCP_ARGUMENTS,
                    }
                    got = {key: sent[0].get(key) for key in wanted}
                    if got != wanted:
                        failures.append(f"{name} ({side} reported the wrong call)")
                        print(f"        ^ {side} reported {got}, wanted {wanted}")

                actual = "block" if b"deny" in py.stdout else "allow"
                if actual != expected:
                    failures.append(f"{name} (expected {expected}, got {actual})")
                    print(
                        f"        ^ expected the policy to {expected}, but it did not"
                    )
        finally:
            mock.kill()
    return failures


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_mock(mode, request_log, mcp_deny=""):
    port = free_port()
    env = {
        **os.environ,
        "MODE": mode,
        "REQUEST_LOG": str(request_log),
        "MCP_DENY": mcp_deny,
    }
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "tests" / "mock_api.py"), str(port)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(200):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.05):
                return proc, port
        except OSError:
            time.sleep(0.02)
    proc.kill()
    raise RuntimeError("mock API did not start")


def make_workdir(
    tmp, name, *, local_config=None, global_config=None, dotenv_files=None
):
    """A throwaway repo: its own HOME, its own config dir, its own git root.

    `dotenv_files` maps a filename to its content, written at the root of the
    repo -- which is both the cwd the hook runs in and its git root, the two
    places `_find_dot_env()` looks.
    """
    workdir = tmp / name
    (workdir / "config").mkdir(parents=True, exist_ok=True)
    (workdir / "home").mkdir(exist_ok=True)
    # `find_local_config_path` resolves the git root, so the fixture has to be
    # a git checkout for a local .gitguardian.yaml to be discoverable at all.
    subprocess.run(
        ["git", "init", "-q"],
        cwd=workdir,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if local_config is not None:
        (workdir / ".gitguardian.yaml").write_text(local_config)
    if global_config is not None:
        (workdir / "home" / ".gitguardian.yaml").write_text(global_config)
    for filename, content in (dotenv_files or {}).items():
        (workdir / filename).write_text(content)
    return workdir


def run(cmd, payload, port, workdir, env_extra=None):
    """Run one hook implementation in a clean, isolated environment.

    `env_extra` overrides that environment; a `None` value *removes* a variable,
    which is how a case proves a setting came from a `.env` and not from the
    environment the hook was started with.
    """
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(workdir / "home"),
        # The token never reaches the mock's decision logic; it just has to exist.
        "GITGUARDIAN_API_KEY": "mock-token-not-a-real-secret",
        "GITGUARDIAN_API_URL": f"http://localhost:{port}",
        "GG_CACHE_DIR": str(workdir / "cache"),
        "GG_CONFIG_DIR": str(workdir / "config"),
        "GG_USER_HOME_DIR": str(workdir / "home"),
        # Keep the Python side off the OS keychain entirely.
        "GGSHIELD_NO_KEYRING": "1",
        "GITGUARDIAN_DONT_LOAD_ENV": "1",
        "PYTHONPATH": str(PY_SOURCES),
    }
    for key, value in (env_extra or {}).items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    started = time.perf_counter()
    proc = subprocess.run(
        cmd,
        input=json.dumps(payload).encode(),
        capture_output=True,
        cwd=workdir,
        env=env,
    )
    return proc, time.perf_counter() - started


def read_requests(log):
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text().splitlines()]


def write_read_file():
    Path(READ_FILE).write_text(f"AWS_KEY={CLIENT_ID}\n")


def compare_one(
    tmp,
    log,
    port,
    name,
    payload,
    *,
    local_config=None,
    global_config=None,
    setup=None,
    dotenv_files=None,
    env_extra=None,
):
    """Run both sides on one payload.

    Returns (verdict_ok, request_ok, py, rs, bodies), `bodies` being the request
    bodies each side POSTed, keyed by side. `setup` writes the fixture file the
    payload points at, and runs again for each side so neither inherits the
    other's state.
    """
    results, bodies = {}, {}
    for side, cmd in (("python", PY_CMD), ("rust", RS_CMD)):
        workdir = make_workdir(
            tmp,
            f"{name}-{side}",
            local_config=local_config,
            global_config=global_config,
            dotenv_files=dotenv_files,
        )
        (setup or write_read_file)()
        before = len(read_requests(log))
        proc, _ = run(cmd, payload, port, workdir, env_extra=env_extra)
        results[side] = proc
        bodies[side] = [r["body"] for r in read_requests(log)[before:]]
    py, rs = results["python"], results["rust"]
    verdict_ok = same_stdout(py.stdout, rs.stdout) and py.returncode == rs.returncode
    # The scanned document itself must match, not just the verdict: a verdict
    # can agree by luck while the wrong bytes were sent.
    request_ok = same_requests(bodies["python"], bodies["rust"])
    return verdict_ok, request_ok, py, rs, bodies


def verdict_of(stdout):
    """ "block" or "allow", whichever schema the agent's verdict uses.

    A tool event blocks with `permissionDecision: deny`, a prompt event with
    `decision: block`.
    """
    return "block" if b"deny" in stdout or b'"block"' in stdout else "allow"


def as_json(raw):
    """`(True, value)` if `raw` parses as JSON, else `(False, raw)`."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    try:
        return True, json.loads(raw)
    except (ValueError, TypeError):
        return False, raw


def same_stdout(py, rs):
    """Same verdict on stdout.

    Compared as JSON, so key order and separators are free. Every value still has
    to match exactly, `systemMessage` included: that string is prose the user
    reads.
    """
    if py == rs:
        return True
    py_ok, py_value = as_json(py)
    rs_ok, rs_value = as_json(rs)
    return py_ok and rs_ok and py_value == rs_value


IS_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def same_document(py, rs):
    """One POSTed document: same content, and a filename that means the same.

    `content`: compared as JSON when both sides parse as JSON (an MCP or
    unrecognised tool's `tool_input` is re-serialised, and the two
    implementations' separators differ), otherwise byte for byte -- a file's
    content must be a verbatim extract.

    `filename`: when it is a content-derived sha256, both sides must produce one
    but the values are allowed to differ, because they are hashes of the two
    serialisations. Anything else is a real path and must match exactly.
    """
    if py.keys() != rs.keys():
        return False
    for key, py_value in py.items():
        rs_value = rs[key]
        if key == "document":
            py_ok, py_json = as_json(py_value)
            rs_ok, rs_json = as_json(rs_value)
            if py_ok and rs_ok:
                if py_json != rs_json:
                    return False
            elif py_value != rs_value:
                return False
        elif key == "filename":
            if IS_SHA256.match(str(py_value)) or IS_SHA256.match(str(rs_value)):
                if not (
                    IS_SHA256.match(str(py_value)) and IS_SHA256.match(str(rs_value))
                ):
                    return False
            elif py_value != rs_value:
                return False
        elif py_value != rs_value:
            return False
    return True


def same_request(py, rs):
    """The /v1/multiscan bodies each side POSTed, document by document."""
    if py == rs:
        return True
    py_ok, py_docs = as_json(py)
    rs_ok, rs_docs = as_json(rs)
    if not (py_ok and rs_ok):
        return False
    if not (isinstance(py_docs, list) and isinstance(rs_docs, list)):
        return py_docs == rs_docs
    if len(py_docs) != len(rs_docs):
        return False
    return all(
        isinstance(a, dict) and isinstance(b, dict) and same_document(a, b)
        for a, b in zip(py_docs, rs_docs)
    )


def same_requests(py, rs):
    """Every request, in order: same count, each one equivalent."""
    return len(py) == len(rs) and all(same_request(a, b) for a, b in zip(py, rs))


def report(failures, label, verdict_ok, request_ok, py, rs):
    status = "MATCH" if verdict_ok else "DIFF "
    req = "req=same" if request_ok else "req=DIFF"
    print(f"  [{status}] {label}  ({req})")
    if verdict_ok and request_ok:
        return
    failures.append(label)
    print(f"        python exit={py.returncode} stdout={py.stdout[:220]!r}")
    print(f"          rust exit={rs.returncode} stdout={rs.stdout[:220]!r}")
    if py.stderr:
        print(f"        python stderr={py.stderr.decode()[:200]!r}")
    if rs.stderr:
        print(f"          rust stderr={rs.stderr.decode()[:200]!r}")


def compare_agents(tmp):
    failures = []
    print("Agents: 5 assistants x 6 payload shapes x {clean, secret}")
    for mode in ("clean", "secret"):
        log = tmp / f"requests-agents-{mode}.jsonl"
        mock, port = start_mock(mode, log)
        try:
            for agent, shapes in agent_payloads().items():
                for shape, payload in shapes.items():
                    name = f"{mode}/{agent}/{shape}"
                    verdict_ok, request_ok, py, rs, _ = compare_one(
                        tmp, log, port, name.replace("/", "-"), payload
                    )
                    report(failures, name, verdict_ok, request_ok, py, rs)
        finally:
            mock.kill()
    return failures


def compare_configs(tmp, ignore_sha):
    failures = []
    print("\n.gitguardian.yaml: every key that reaches this path")
    log = tmp / "requests-config.jsonl"
    mock, port = start_mock("secret", log)
    # One payload shape is enough here: the variable under test is the config.
    payload = agent_payloads()["claude"]["pre_read"]
    requests_by_case = {}
    try:
        for case, local, global_, expected in config_cases(ignore_sha):
            before = len(read_requests(log))
            verdict_ok, request_ok, py, rs, _ = compare_one(
                tmp,
                log,
                port,
                f"cfg-{case}",
                payload,
                local_config=local,
                global_config=global_,
            )
            report(failures, f"config/{case}", verdict_ok, request_ok, py, rs)
            requests_by_case[case] = [r["body"] for r in read_requests(log)[before:]]

            # Teeth: the config must actually have changed the verdict.
            # `pre_read` blocks via permissionDecision: deny.
            actual = "block" if b"deny" in py.stdout else "allow"
            if actual != expected:
                failures.append(f"config/{case} (expected {expected}, got {actual})")
                print(f"        ^ expected the config to {expected}, but it did not")
    finally:
        mock.kill()

    # filename_only must change the document filename we send, not the verdict.
    default = requests_by_case.get("no_config", [""])
    only = requests_by_case.get("filename_only", [""])
    if same_requests(default, only):
        failures.append("config/filename_only had no effect on the request")
        print("  [DIFF ] config/filename_only did not change the POSTed filename")
    return failures


# The token each `.env` case installs, and the one the hook is *started* with.
# They differ so the Authorization header the mock logs says which of the two
# won -- python loads the file with `override=True`, so it must be the file's.
DOTENV_TOKEN = "dotenv-token-not-a-real-secret"
ENV_TOKEN = "environment-token-not-a-real-secret"


def dotenv_cases(live, dead):
    """`.env` cases: (name, files, env overrides).

    `live` is the mock this harness started, `dead` a port with nothing on it.

    The harness normally injects credentials through the environment, so every
    case here has to make the `.env` the *only* way to reach the mock: the
    environment either points `GITGUARDIAN_API_URL` at the dead port or carries
    no token at all. An implementation that ignored the file would fail open on a
    dead socket or on a missing token instead of blocking, so none of these can
    pass vacuously.

    Every case is hook-observable: which instance got the POST, which token
    authenticated it, or whether the file was read at all. Parsing forms
    (quoting, `export`, comments) are the `.env` parser's own business and are
    not enumerated here.

    Every case expects a block, because only a scan against the mock can
    produce one.
    """

    return [
        # Precedence: the file beats the same variable already exported.
        (
            "instance_overrides_the_environment",
            {".env": f"GITGUARDIAN_INSTANCE=http://localhost:{live}\n"},
            {"GITGUARDIAN_INSTANCE": f"http://localhost:{dead}"},
        ),
        # A token that exists only in the file: without it there is nothing to
        # authenticate with, so the scan cannot happen at all.
        (
            "api_key_only_in_the_dotenv",
            {".env": f"GITGUARDIAN_API_KEY={DOTENV_TOKEN}\n"},
            {"GITGUARDIAN_API_KEY": None},
        ),
        # ...and one that overrides the exported token. Both sides block either
        # way, so the assertion is the Authorization header the mock logged.
        (
            "api_key_overrides_the_environment",
            {".env": f"GITGUARDIAN_API_KEY={DOTENV_TOKEN}\n"},
            {"GITGUARDIAN_API_KEY": ENV_TOKEN},
        ),
        # The other direction: with loading disabled the file must be ignored, so
        # the block has to come from the environment instead.
        (
            "dont_load_env_ignores_the_file",
            {".env": f"GITGUARDIAN_INSTANCE=http://localhost:{dead}\n"},
            {"GITGUARDIAN_DONT_LOAD_ENV": "1"},
        ),
        # An explicit path wins over the .env in the working directory.
        (
            "dotenv_path_selects_another_file",
            {
                ".env": f"GITGUARDIAN_INSTANCE=http://localhost:{dead}\n",
                "custom.env": f"GITGUARDIAN_INSTANCE=http://localhost:{live}\n",
            },
            {
                "GITGUARDIAN_DOTENV_PATH": "custom.env",
                "GITGUARDIAN_API_URL": f"http://localhost:{dead}",
            },
        ),
        # The common case: a project .env that has nothing to do with ggshield
        # must change nothing, and must not cost a scan.
        (
            "unrelated_variables_change_nothing",
            {".env": "DATABASE_URL=postgres://localhost/app\nDEBUG=1\n"},
            {},
        ),
        # `${...}` interpolation: both sides expand it against the environment,
        # so the instance that gets the POST is the expanded one.
        (
            "interpolated_instance_expands",
            {".env": "GITGUARDIAN_INSTANCE=${GG_MOCK_URL}\n"},
            {
                "GG_MOCK_URL": f"http://localhost:{live}",
                "GITGUARDIAN_INSTANCE": f"http://localhost:{dead}",
            },
        ),
    ]


def compare_dotenv(tmp):
    """A `.env` naming a GITGUARDIAN_* setting must resolve the same both sides.

    Not a detail: a self-hosted customer's `.env` names *their* instance, so
    reading it wrong does not mean "no scan", it means their document content
    posted to somebody else's API.
    """
    failures = []
    print("\n.env: the same instance and token ggshield resolves")
    log = tmp / "requests-dotenv.jsonl"
    mock, port = start_mock("secret", log)
    dead = free_port()
    payload = agent_payloads()["claude"]["pre_read"]
    try:
        for name, files, env_extra in dotenv_cases(port, dead):
            before = len(read_requests(log))
            verdict_ok, request_ok, py, rs, _ = compare_one(
                tmp,
                log,
                port,
                f"dotenv-{name}",
                payload,
                dotenv_files=files,
                # `run()` keeps .env loading off for every other matrix; here it
                # is the thing under test, so clear it -- unless the case sets it
                # back, which is how "disabled means disabled" is asserted.
                env_extra={"GITGUARDIAN_DONT_LOAD_ENV": None, **env_extra},
            )
            entries = read_requests(log)[before:]

            report(failures, f"dotenv/{name}", verdict_ok, request_ok, py, rs)

            # Teeth: a block can only come from a scan against the mock. In the
            # instance cases the .env is the only route to it; the token cases
            # reach it either way, and are asserted on the header below instead.
            # One POST per side, so two in the slice.
            if not (b"deny" in py.stdout and len(entries) == 2):
                failures.append(f"dotenv/{name} (expected block, {len(entries)} scans)")
                print(
                    f"        ^ expected both sides to reach the mock and block, "
                    f"got {len(entries)} scan(s)"
                )
            # ...and for the token cases, *which* token got there.
            if name.startswith("api_key"):
                tokens = {entry["token"] for entry in entries}
                if tokens != {f"Token {DOTENV_TOKEN}"}:
                    failures.append(f"dotenv/{name} (wrong token)")
                    print(f"        ^ the .env token did not win: {sorted(tokens)}")
    finally:
        mock.kill()
    return failures


def extra_cases(tmp):
    """Cases that never reach the API: fail-open, and the deliberate declines."""
    failures = []
    payload = agent_payloads()["claude"]["pre_bash"]

    # 1. Unreachable API. Both sides must fail open: exit 0, continue true,
    #    plus a systemMessage. The wording differs, so only the shape is checked.
    print("\nFail-open (API unreachable, nothing listening):")
    dead_port = free_port()
    for side, cmd in (("python", PY_CMD), ("rust", RS_CMD)):
        workdir = make_workdir(tmp, f"failopen-{side}")
        proc, _ = run(cmd, payload, dead_port, workdir)
        try:
            body = json.loads(proc.stdout.decode())
        except Exception:
            body = None
        ok = (
            proc.returncode == 0
            and isinstance(body, dict)
            and body.get("continue") is True
            and bool(body.get("systemMessage"))
        )
        print(
            f"  [{'OK  ' if ok else 'FAIL'}] {side}: exit={proc.returncode} {proc.stdout[:100]!r}"
        )
        if not ok:
            failures.append(f"failopen/{side}")

    # 2. Broken config. These are raised while *loading* config, which in
    #    Python happens in the `cli` group callback — before the command's
    #    try/except exists — so they do NOT fail open: stderr, exit 128, no
    #    stdout. Compared against Python rather than asserted, because that
    #    claim is exactly the kind this harness exists to check (the first
    #    version of this port got it wrong).
    print("\nBroken config (exit code and stdout compared against Python):")
    log = tmp / "requests-broken-config.jsonl"
    mock, port = start_mock("secret", log)
    try:
        for case, local in (
            ("unknown_version", "version: 3\n"),
            ("malformed_yaml", "version: 2\nsecret:\n  - [unclosed\n"),
            ("not_a_mapping", "- just\n- a\n- list\n"),
            (
                "ignored_matches_entry_without_match",
                "version: 2\nsecret:\n  ignored_matches:\n  - name: no match key\n",
            ),
        ):
            verdict_ok, request_ok, py, rs, _ = compare_one(
                tmp, log, port, f"broken-{case}", payload, local_config=local
            )
            report(failures, f"config/{case}", verdict_ok, request_ok, py, rs)
    finally:
        mock.kill()

    # 3. A cleartext instance. `validate_instance_url` refuses it, so the token
    #    and the document never leave over plain http; the refusal surfaces as an
    #    ordinary fail-open, warning text included.
    print("\nCleartext instance (compared against Python, warning included):")
    for case, env_extra in (
        ("http_instance", {"GITGUARDIAN_INSTANCE": "http://gg.example.com"}),
        ("http_api_url", {"GITGUARDIAN_API_URL": "http://gg.example.com/exposed"}),
    ):
        log = tmp / f"requests-{case}.jsonl"
        mock, port = start_mock("secret", log)
        try:
            before = len(read_requests(log))
            verdict_ok, request_ok, py, rs, _ = compare_one(
                tmp, log, port, f"cleartext-{case}", payload, env_extra=env_extra
            )
            report(failures, f"cleartext/{case}", verdict_ok, request_ok, py, rs)
            if len(read_requests(log)) != before:
                failures.append(f"cleartext/{case} (something was posted)")
                print("        ^ a document was sent over cleartext http")
        finally:
            mock.kill()

    # 4. A payload from no known agent: no verdict at all, exit 1.
    print("\nUnrecognized agent (both sides): no stdout, exit 1")
    for side, cmd in (("python", PY_CMD), ("rust", RS_CMD)):
        workdir = make_workdir(tmp, f"unknown-{side}")
        proc, _ = run(
            cmd,
            {"hook_event_name": "somethingElse", "prompt": "hi"},
            dead_port,
            workdir,
        )
        ok = proc.returncode == 1 and proc.stdout == b""
        print(
            f"  [{'OK  ' if ok else 'FAIL'}] {side}: exit={proc.returncode} "
            f"stdout={proc.stdout!r}"
        )
        if not ok:
            failures.append(f"unknown-agent/{side}")
    return failures


def bench(tmp, iterations):
    """Latency, alternating sides so machine load hits both equally.

    Two scenarios per side:
      no-api   a payload with nothing to scan, so no /multiscan call is made.
               This is pure startup + config + token resolution.
      full     a real scan against the localhost mock.

    Each side keeps ONE workdir across iterations, warmed by a throwaway run
    first. That is the steady state a developer actually sees: ggshield's
    auth-check cache is already populated, so it does not re-verify the token
    over the network on every hook call. The payload changes every iteration so
    the duplicate-payload debounce never short-circuits either side.
    """
    mock, port = start_mock("clean", tmp / "bench-requests.jsonl")

    def payload_for(i, scannable):
        base = {
            "session_id": f"bench-{i}",
            "transcript_path": "/home/u/.claude/projects/p/x.jsonl",
            "cwd": "/tmp",
        }
        if scannable:
            return {
                **base,
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": f"echo benchmark iteration {i}"},
            }
        # Nothing to scan: no tool_input at all, so no API call is made.
        return {
            **base,
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {},
        }

    results = {}
    try:
        for scenario, scannable in (("no-api", False), ("full", True)):
            sides = [("python", PY_CMD), ("rust", RS_CMD)]
            if FROZEN.exists():
                sides.insert(1, ("frozen", FROZEN_CMD))
            timings = {side: [] for side, _ in sides}

            for side, cmd in sides:
                # Warm-up run, not measured: fills the auth-check cache.
                workdir = make_workdir(tmp, f"bench-{scenario}-{side}")
                run(cmd, payload_for(-1, scannable), port, workdir)

            for i in range(iterations):
                order = list(sides)
                if i % 2:
                    order.reverse()
                for side, cmd in order:
                    workdir = tmp / f"bench-{scenario}-{side}"
                    _, elapsed = run(cmd, payload_for(i, scannable), port, workdir)
                    timings[side].append(elapsed * 1000)
            results[scenario] = timings
    finally:
        mock.kill()

    print(f"\nLatency, {iterations} runs per side per scenario, alternating sides.")
    print(
        "Wall clock of the whole process, measured by the parent (fork+exec included)."
    )
    for scenario, timings in results.items():
        print(f"\n  {scenario}:")
        p50s = {}
        for side, samples in timings.items():
            samples.sort()
            p50s[side] = samples[len(samples) // 2]
            print(
                f"    {side:7} p50={p50s[side]:7.1f} ms  "
                f"p90={samples[int(len(samples) * 0.9)]:7.1f} ms  "
                f"min={samples[0]:7.1f} ms  max={samples[-1]:7.1f} ms"
            )
        for baseline in ("python", "frozen"):
            if baseline in p50s:
                print(
                    f"    -> vs {baseline}: {p50s[baseline] / p50s['rust']:.0f}x faster "
                    f"at p50, {p50s[baseline] - p50s['rust']:.0f} ms saved per hook call"
                )


def main():
    if not RUST.exists():
        sys.exit(f"build it first: cargo build --release ({RUST} missing)")
    if not PYTHON.exists():
        sys.exit(f"missing Python venv at {PYTHON}")

    sys.path.insert(0, str(ROOT / "tests"))
    import mock_api

    tmp = Path(tempfile.mkdtemp(prefix="ggshield-hook-eq-"))
    try:
        failures = compare_agents(tmp)
        # The config matrix uses the `pre_read` payload, which scans
        # READ_FILE — so the ignore sha must be the one for that file.
        failures += compare_configs(tmp, mock_api.ignore_sha(f"AWS_KEY={CLIENT_ID}\n"))
        failures += compare_read_ranges(tmp)
        failures += compare_content(tmp)
        failures += compare_mentions(tmp)
        failures += compare_batches(tmp)
        failures += compare_mcp(tmp)
        failures += compare_verdict_cache(tmp)
        failures += compare_dotenv(tmp)
        failures += extra_cases(tmp)
        if "--bench" in sys.argv:
            n = int(sys.argv[sys.argv.index("--bench") + 1])
            bench(tmp, n)
        # Expected, tracked divergences: the gate stays green for these but
        # still reddens on anything new. Keep this list empty in the steady
        # state; every entry needs a reason and a removal condition.
        known_divergences = {}
        known = [f for f in failures if f in known_divergences]
        unexpected = [f for f in failures if f not in known_divergences]
        for name in known:
            print(f"\nKNOWN DIVERGENCE (expected, tracked): {name}")
            print(f"  reason: {known_divergences[name]}")
        if unexpected:
            print(f"\nRESULT: {len(unexpected)} UNEXPECTED DIFFERENCES")
            for name in unexpected:
                print(f"  - {name}")
            return 1
        if known:
            print(f"\nRESULT: OK ({len(known)} known divergence(s), 0 unexpected)")
        else:
            print("\nRESULT: EQUIVALENT")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        Path(READ_FILE).unlink(missing_ok=True)


if __name__ == "__main__":
    sys.exit(main())
