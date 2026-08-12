import hashlib
import json
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Pattern, Sequence, Set, Tuple

import filelock
from notifypy import Notify
from pygitguardian.config import DOCUMENT_SIZE_THRESHOLD_BYTES

from ggshield.core import ui
from ggshield.core.dirs import get_cache_dir
from ggshield.core.errors import AuthError
from ggshield.core.filter import censor_match
from ggshield.core.scan import Scannable, ScannerProtocol
from ggshield.core.scan import SecretProtocol as Secret
from ggshield.core.scanner_ui import create_message_only_scanner_ui
from ggshield.core.text_utils import pluralize, translate_validity
from ggshield.utils.files import is_path_excluded
from ggshield.utils.os import getenv_bool
from ggshield.verticals.ai.mcp import is_mcp_activity_payload, send_mcp_activity

from .agents import AGENTS
from .cache import has_clean_verdict, store_clean_verdict, verdict_key
from .models import (
    Agent,
    EventType,
    HookPayload,
    HookResult,
    Tool,
    markdown_hard_breaks,
)


HOOK_NAME_TO_EVENT_TYPE = {
    "userpromptsubmit": EventType.USER_PROMPT,
    "userpromptsubmitted": EventType.USER_PROMPT,  # Copilot CLI's native event name
    "beforesubmitprompt": EventType.USER_PROMPT,
    "pretooluse": EventType.PRE_TOOL_USE,
    "pre_tool": EventType.PRE_TOOL_USE,
    "posttooluse": EventType.POST_TOOL_USE,
    "post_tool": EventType.POST_TOOL_USE,
}

TOOL_NAME_TO_TOOL = {
    "shell": Tool.BASH,  # Cursor
    "bash": Tool.BASH,  # Claude Code, Mistral Vibe
    "git_bash": Tool.BASH,  # Mistral Vibe
    "powershell": Tool.BASH,  # Mistral Vibe, on Windows
    "run_in_terminal": Tool.BASH,  # Copilot
    "read": Tool.READ,  # Claude/Cursor
    "read_file": Tool.READ,  # Copilot
    "view": Tool.READ,  # Copilot CLI
}


def has_already_been_seen(content: str) -> bool:
    """Return True if the payload is identical to the most recent hook call.

    Some agents install hooks from multiple assistants, which can invoke ggshield
    twice with the same payload.
    """
    payload_hash = hashlib.sha256(content.strip().encode()).hexdigest()
    debounce_path = get_cache_dir() / "latest_ai_hook.txt"
    try:
        debounce_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        return False

    # Make sure only one process can read/write the debounce file at a time
    # to avoid having the same payload being processed twice.
    with filelock.FileLock(debounce_path.with_suffix(".lock")):
        try:
            stored = debounce_path.read_text()
        except FileNotFoundError:
            stored = ""
        if payload_hash == stored:
            return True
        debounce_path.write_text(payload_hash)
        return False


def lookup(data: Dict[str, Any], keys: Sequence[str], default: Any = None) -> Any:
    """Returns the value of the first key found in a dictionary."""
    for key in keys:
        if key in data:
            return data[key]
    return default


# Regex (and method) to look for any @file_path in the prompt.
# A list of test cases can be found in test_hooks.py.
_FILE_PATH_REGEX = re.compile(
    r'@"((?:[^"\\]|\\.)*)"'  # quoted: @"..."
    r"|"
    r"(?:\W|^)@"  # unquoted: @path
    r"(?:file:)?"  # some agents add a "file:" prefix
    r"([\w/\\.-]+)",
    re.MULTILINE,
)


def find_filepaths(prompt: str) -> Set[str]:
    """Find all file paths in the prompt."""
    paths = set()
    for m in _FILE_PATH_REGEX.finditer(prompt):
        path = m.group(1) or m.group(2) or ""
        path = path.strip()
        # Don't include trailing dots in the path
        path = path.removesuffix(".")
        if path:
            paths.add(path)
    return paths


def _abs_read_path(identifier: str, cwd: str) -> str:
    """Resolve a READ file path to an absolute path against the event's cwd.

    The verdict cache is keyed on the filename, so the same physical file must
    yield the same identifier whether it came from an @-mention in a prompt
    (usually relative) or a tool's file_path (usually absolute) -- otherwise the
    file is scanned twice. os.path.join leaves an already-absolute path alone,
    and abspath normalizes it; realpath is deliberately avoided so the key stays
    deterministic and matches how the file is referenced.

    Never break the scan: with no cwd, or if resolution fails, the identifier is
    returned unchanged (today's behavior).
    """
    if not identifier or not cwd:
        return identifier
    try:
        return os.path.abspath(os.path.join(cwd, identifier))
    except Exception:
        return identifier


def parse_hook_input(raw_content: str) -> list[HookPayload]:
    """Parse the input content. Raises a ValueError if the input is not valid.

    Returns:
        A list of payloads. Most of the time the list will contain only one payload,
        but in some cases files mentioned in the prompt will be read but the
        PreToolUse event will not be called. So we need to handle this case ourselves.
    """
    timestamp = datetime.now(timezone.utc)

    # Parse the content as JSON
    if not raw_content.strip():
        raise ValueError("Error: No input received on stdin")
    try:
        data = json.loads(raw_content)
    except json.JSONDecodeError as e:
        raise ValueError(f"Error: Failed to parse JSON from stdin: {e}") from e

    payloads = []

    # Try to guess which AI coding assistant is calling us
    agent = _detect_agent(data)

    # Infer the event type
    event_name = lookup(data, ["hook_event_name", "hookEventName"], None)
    if event_name is None:
        raise ValueError("Error: couldn't find event type")
    event_type = HOOK_NAME_TO_EVENT_TYPE.get(event_name.lower(), EventType.OTHER)

    identifier = ""
    content = ""
    tool = None
    read_range = None

    # The event's working directory, used to canonicalize READ file paths to
    # absolute so a prompt @-mention and a tool read of the same file share one
    # verdict-cache key (see _abs_read_path). Agent-specific; "" when unknown.
    cwd = agent.event_cwd(data)

    # Extract the identifier and content based on the event type
    if event_type == EventType.USER_PROMPT:
        content = data.get("prompt", "")
        # Look for files mentioned in the prompt that could be read
        # without triggering a PRE_TOOL_USE event.
        payloads.extend(_parse_user_prompt(content, event_type, agent, timestamp, cwd))

    elif event_type == EventType.PRE_TOOL_USE:
        tool = _parse_tool(data)
        # NOTE: if we ever support agents that use another field than "tool_input.command",
        # remember to update the line that reads the command to fill the notification message.
        tool_input = data.get("tool_input", {})
        # Select the content based on the tool
        if tool == Tool.BASH:
            content = tool_input.get("command", "")
            identifier = content
            # Try to detect a command that could be used to read a file.
            payloads.extend(_parse_command(content, event_type, agent, timestamp, cwd))
        elif tool == Tool.READ:
            # We only need to deal with the identifier, the content will be read by the Scannable
            identifier = _abs_read_path(
                lookup(tool_input, ["file_path", "filePath", "path"], ""), cwd
            )
            read_range = agent.read_range(tool_input)
        elif tool_input:
            # MCP and unrecognized tool arguments can carry secrets bound for
            # potentially external servers. Scan them, like tool_output below.
            # Also covers agents whose MCP tools are only identified later, in
            # post_process_payload (e.g. Copilot).
            content = json.dumps(tool_input)

    elif event_type == EventType.POST_TOOL_USE:
        tool = _parse_tool(data)
        content = lookup(data, ["tool_output", "tool_response", "tool_result"], {})
        if content is None:
            # Vibe reports a null structured output on tool failure, while the
            # text shown to the model remains available in tool_output_text.
            content = data.get("tool_output_text", "")
        # Some agents return a dict for the tool output. Also support lists just in case.
        if isinstance(content, (dict, list)):
            content = json.dumps(content)
        if tool == Tool.READ:
            # Same tool_input as PreToolUse, hence the same range and the same
            # canonicalized path: both events scan the exact same bytes for one
            # read, which the verdict cache (keyed on the document) relies on.
            tool_input = data.get("tool_input", {})
            identifier = _abs_read_path(
                lookup(tool_input, ["file_path", "filePath", "path"], ""), cwd
            )
            read_range = agent.read_range(tool_input)

    # If identifier was not set, hash the content
    if not identifier:
        identifier = hashlib.sha256((content or "").encode()).hexdigest()

    payloads.append(
        HookPayload(
            event_type=event_type,
            tool=tool,
            content=content,
            identifier=identifier,
            agent=agent,
            raw=data,
            timestamp=timestamp,
            read_range=read_range,
        )
    )

    # Allow the agent to post-process the payloads (e.g overriding the tool)
    for payload in payloads:
        agent.post_process_payload(payload)

    return payloads


def emit_fail_open_response(stdin_content: str, error: Exception) -> int:
    """Emit an "allow" response carrying a warning instead of crashing.

    A failure to scan (missing or unreadable token, unreachable server...)
    must never break the agent: agents interpret a non-zero exit or a raw
    traceback as a block or an error, and the user is never told that
    scanning is broken. Instead we allow the action and surface a warning
    through the agent.

    Returns the exit code to use.
    """
    warning = _cannot_scan_warning(error)
    ui.display_warning(warning)
    try:
        payload = parse_hook_input(stdin_content)[-1]
    except Exception:
        # We can't even tell which agent is calling us, so we can't emit a
        # well-formed response. Agents treat exit 1 as a non-blocking error.
        return 1
    return payload.agent.output_result(HookResult.allow_with_warning(payload, warning))


def _cannot_scan_warning(error: Exception) -> str:
    if isinstance(error, AuthError):
        reason = "ggshield could not authenticate to GitGuardian"
        remediation = (
            "Run 'ggshield auth login' to authenticate. If you are already "
            "logged in, run 'ggshield api-status' once in a terminal: your OS "
            "credentials store may require an interactive approval before "
            "agent-spawned processes can read the token."
        )
    else:
        # Only keep the first line: error details such as connection errors
        # can span several lines and don't belong in an agent message.
        detail = str(error).splitlines()[0] if str(error) else error.__class__.__name__
        reason = f"ggshield could not scan ({detail})"
        remediation = "Run 'ggshield api-status' to diagnose."
    return f"{reason} — this action was NOT scanned for secrets. {remediation}"


def _parse_tool(data: Dict[str, Any]) -> Tool:
    """Parse the tool name."""
    tool_name = data.get("tool_name", "").lower()
    if tool_name.startswith("mcp"):
        return Tool.MCP
    return TOOL_NAME_TO_TOOL.get(tool_name, Tool.OTHER)


def _detect_agent(data: Dict[str, Any]) -> Agent:
    """Detect the AI code assistant."""
    for agent in AGENTS.values():
        if agent.is_caller(data):
            return agent
    raise ValueError("Unrecognized agent")


def build_agent_headers(content: str) -> Dict[str, str]:
    """Additional headers to identify the agent."""
    try:
        agent = _detect_agent(json.loads(content))
        return {"Agent-Name": agent.name}
    except Exception:
        return {}


def _parse_user_prompt(
    content: str,
    event_type: EventType,
    agent: Agent,
    timestamp: datetime,
    cwd: str = "",
) -> List[HookPayload]:
    """Parse the user prompt for additional payloads that we may miss."""
    payloads = []
    # Scenario 1 (the only one we know about so far):
    # Code assistants don't always trigger a PRE_TOOL_USE event when
    # a file is mentioned in the prompt, especially with an "@" prefix.
    matches = find_filepaths(content)
    for match in matches:
        payloads.append(
            HookPayload(
                event_type=event_type,
                tool=Tool.READ,
                content="",
                # Canonicalize so this matches the PreToolUse Read of the same
                # file and both share one verdict-cache key (see _abs_read_path).
                identifier=_abs_read_path(match, cwd),
                agent=agent,
                raw={},
                timestamp=timestamp,
            )
        )
    return payloads


def _parse_command(
    content: str,
    event_type: EventType,
    agent: Agent,
    timestamp: datetime,
    cwd: str = "",
) -> List[HookPayload]:
    """Parse the command for additional payloads that we may miss."""
    # In Windows, some agents (at least Codex) use the Get-Content command to read a file.
    # We might as well try to detect other commands like "cat".
    payloads = []

    if content.startswith(("Get-Content ", "cat ")):
        # Extract the filename (remove the command)
        identifier = _abs_read_path(content.partition(" ")[2].strip(), cwd)
        payloads.append(
            HookPayload(
                event_type=event_type,
                tool=Tool.READ,
                content="",
                identifier=identifier,
                agent=agent,
                raw={},
                timestamp=timestamp,
            )
        )
    return payloads


def _send_desktop_notification(title: str, message: str) -> None:
    """Deliver a desktop notification, dispatching to the right backend per OS.

    On macOS we shell out to the native ``osascript``: it ships with every
    macOS (so it works on Homebrew installs, which strip notifypy's bundled
    Notificator.app), is arm64-native (notifypy's applet is Intel-only and
    Apple-deprecated) and produces a normal Notification Center banner. The
    strings are passed as run-handler arguments rather than interpolated into
    the AppleScript source: this is injection-safe (the message embeds
    attacker-influenced command text) and correctness-safe, as an AppleScript
    string literal can't represent non-ASCII or control characters (accented
    paths, emoji, tabs...). ``stdin`` is detached and a timeout enforced so a
    misbehaving notifier can't stall the hook. Other platforms use notifypy.
    """
    if getenv_bool("GGSHIELD_NO_NOTIFICATION", default=False):
        return
    if sys.platform == "darwin":
        subprocess.run(
            [
                "osascript",
                "-e",
                "on run argv",
                "-e",
                "display notification (item 1 of argv) with title (item 2 of argv)",
                "-e",
                "end run",
                "--",
                message,
                title,
            ],
            check=False,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=10,
        )
    else:
        notification = Notify()
        notification.title = title
        notification.message = message
        notification.application_name = "ggshield"
        notification.send()


# Block messages, one template per (event, tool) case. Placeholders are filled by
# AIHookScanner._message_from_secrets(). {post_remediation_steps} depends on the
# detected secrets, see _post_remediation_steps().

_USER_PROMPT_TEMPLATE = """\
**🚨 Detected {count} {secrets} in your prompt 🚨**
{secret_lines}

The prompt was not sent to the agent and the {secrets} {were} not leaked.

> How to remediate

  Since the {secrets} {were} detected before the prompt was sent:
  1. remove the {secrets} from your prompt.
  2. submit your prompt again.

{false_positive_instructions}"""

_PRE_BASH_TEMPLATE = """\
**🚨 Detected {count} {secrets} in the command 🚨**
{secret_lines}

The command was not executed and the {secrets} {were} not leaked.

> How to remediate

  Since the {secrets} {were} detected before the command was run:
  1. consider moving the {secrets} to a secrets manager.

{false_positive_instructions}"""

_PRE_READ_TEMPLATE = """\
**🚨 Detected {count} {secrets} in {identifier} 🚨**
{secret_lines}

The file content was not shown to the agent and the {secrets} {were} not leaked.

> How to remediate

  Since the {secrets} {were} detected before the file was read:
  1. avoid sharing this file with the agent.
  2. if the agent needs other values from this file, share only the non-sensitive parts.

{false_positive_instructions}"""

_PRE_OTHER_TEMPLATE = """\
**🚨 Detected {count} {secrets} in the tool input 🚨**
{secret_lines}

The tool call was not executed and the {secrets} {were} not leaked.

> How to remediate

  Since the {secrets} {were} detected before the tool call was made:
  1. consider moving the {secrets} to a secrets manager.

{false_positive_instructions}"""

_POST_BASH_TEMPLATE = """\
**🚨 Detected {count} {secrets} in the command output 🚨**
{secret_lines}

The {secrets} {were} exposed to the AI agent and may persist in conversation logs. Consider {them} compromised.

> How to remediate

  Since the {secrets} {were} leaked after the command was run:
{post_remediation_steps}

{false_positive_instructions}"""

_POST_READ_TEMPLATE = """\
**🚨 Detected {count} {secrets} in {identifier} 🚨**
{secret_lines}

The {secrets} {were} exposed to the AI agent and may persist in conversation logs. Consider {them} compromised.

> How to remediate

  Since the {secrets} {were} leaked after the file was read:
{post_remediation_steps}

{false_positive_instructions}"""

_POST_OTHER_TEMPLATE = """\
**🚨 Detected {count} {secrets} in the tool output 🚨**
{secret_lines}

The {secrets} {were} exposed to the AI agent and may persist in conversation logs. Consider {them} compromised.

> How to remediate

  Since the {secrets} {were} leaked after the tool call was made:
{post_remediation_steps}

{false_positive_instructions}"""

_PRE_TEMPLATES: Dict[Optional[Tool], str] = {
    Tool.BASH: _PRE_BASH_TEMPLATE,
    Tool.READ: _PRE_READ_TEMPLATE,
}
_POST_TEMPLATES: Dict[Optional[Tool], str] = {
    Tool.BASH: _POST_BASH_TEMPLATE,
    Tool.READ: _POST_READ_TEMPLATE,
}


def _secret_lines(secrets: List[Secret], escape_markdown: bool) -> List[str]:
    """One line per secret, plus its incident URL when it is a known secret:

    - Generic High Entropy Secret (**valid**): byIvS••••TXHU
      Incident URL: https://dashboard.gitguardian.com/workspace/1/incidents/9
    """
    lines: List[str] = []
    for secret in secrets:
        validity = translate_validity(secret.validity).lower()
        if validity == "valid":
            validity = f"**{validity}**"
        match_str = ", ".join(censor_match(m) for m in secret.matches)
        if escape_markdown:
            match_str = match_str.replace("*", "•")
        lines.append(f"  - {secret.detector_display_name} ({validity}): {match_str}")
        if secret.known_secret and secret.incident_url:
            lines.append(f"    Incident URL: {secret.incident_url}")
    return lines


def _post_remediation_steps(secrets: List[Secret]) -> str:
    """The numbered steps of the post-leak "How to remediate" section."""
    count = len(secrets)
    nb_incidents = sum(
        1 for secret in secrets if secret.known_secret and secret.incident_url
    )
    steps = [
        pluralize(
            "revoke the secret and issue a new one with its provider.",
            count,
            "revoke the secrets and issue new ones with their providers.",
        ),
        f"consider moving the new {pluralize('secret', count)} to a secrets manager.",
    ]
    if nb_incidents:
        steps.append(
            f"resolve the {pluralize('incident', nb_incidents)} linked above "
            "in your GitGuardian dashboard."
        )
    return "\n".join(f"  {i}. {step}" for i, step in enumerate(steps, start=1))


def _false_positive_block(secrets: Sequence[Secret]) -> str:
    """The remediation for a false positive, with the entries it would write.

    The shas are spelled out because the message censors every match, so the sha
    is otherwise unknowable and a hand-written `ignored_matches` entry silently
    never matches. The sha is a digest, not the secret, and `secret ignore`
    already writes it in clear.
    """
    count = len(secrets)
    this_is_a_false_positive = pluralize(
        "this is a false positive", count, "these are false positives"
    )
    # dict, not set: one entry per sha, in the order the secrets are reported.
    shas = dict.fromkeys(secret.get_ignore_sha() for secret in secrets)
    entries = "\n".join(f"    - match: {sha}" for sha in shas)
    return f"""\
> If {this_is_a_false_positive}, run:

    ggshield secret ignore --last-found

  which adds to secret.ignored_matches in .gitguardian.yaml:

{entries}"""


class AIHookScanner:
    """AI hook scanner.

    It is called with the payload of a hook event.
    Note that instead of having a base class with common method and a subclass per supported AI tool,
    we instead have a single class which detects which protocol to use.
    This is because some tools sloppily support hooks from others. For instance,
    Cursor will call hooks defined in the Claude Code format, but send payload in its own format.
    So we can't assume which tool will call us based on the command line/hook configuration only.

    Raises:
        ValueError: If the input is not valid.
    """

    def __init__(
        self,
        scanner: ScannerProtocol,
        exclusion_regexes: Optional[Set[Pattern[str]]] = None,
    ):
        self.scanner = scanner
        self.exclusion_regexes = exclusion_regexes or set()

    def _is_excluded(self, payload: HookPayload) -> bool:
        """Whether `secret.ignored_paths` covers what this payload would scan.

        READ only: every other tool's identifier is a command or a content hash,
        which a path pattern must not be tested against. A USER_PROMPT
        @-mention is a READ too, so both ways of naming a file are covered.
        """
        if not self.exclusion_regexes or payload.tool != Tool.READ:
            return False
        return is_path_excluded(payload.identifier, self.exclusion_regexes)

    def scan(self, content: str) -> int:
        """Scan the content, print the result and return the exit code."""
        if content.strip() and has_already_been_seen(content):
            return 0

        payloads = parse_hook_input(content)
        result = self._scan_payloads(payloads)
        payload = result.payload

        # Sometimes the secret has already leaked to the agent. Notify the user.
        if result.block and payload.agent.has_secret_already_leaked(payload):
            self._send_secret_notification(result)

        return payload.agent.output_result(result)

    def _scan_payloads(self, payloads: List[HookPayload]) -> HookResult:
        """Scan payloads. Scan for secrets and log MCP activity.

        Returns:
            The result of the first blocking payload, or a non-blocking result.
            Raises a ValueError if the list is empty (we must have at least one to emit a result).
        """
        if not payloads:
            raise ValueError("Error: no payloads to scan")
        mcp_indices = [
            index
            for index, payload in enumerate(payloads)
            if is_mcp_activity_payload(payload)
        ]
        mcp_results: Dict[int, HookResult] = {}

        if not mcp_indices:
            # No activity to send: keep the plain, single-threaded path.
            scan_results = self._scan_contents(payloads)
        else:
            # Both are blocking round trips to the same API, so overlap them. The
            # activity is logged even when the scan blocks.
            with ThreadPoolExecutor(
                max_workers=1, thread_name_prefix="mcp_activity"
            ) as executor:
                activities = {
                    index: executor.submit(self._send_mcp_activity, payloads[index])
                    for index in mcp_indices
                }
                scan_results = self._scan_contents(payloads)
                mcp_results = {
                    index: activity.result() for index, activity in activities.items()
                }

        # All of an event's payloads are scanned in one call; verdicts are applied
        # one payload at a time, in order, and the scan verdict takes precedence over
        # the MCP activity verdict.
        for index, scan_result in enumerate(scan_results):
            if scan_result.block:
                return scan_result
            mcp_result = mcp_results.get(index)
            if mcp_result is not None and mcp_result.block:
                return mcp_result
        return HookResult.allow(payloads[0])

    def _send_mcp_activity(self, payload: HookPayload) -> HookResult:
        """Send MCP activity to the GitGuardian API."""
        # This works even if the payload is not an MCP pre-tool use.
        result = send_mcp_activity(self.scanner.client, payload)
        return HookResult(
            block=not result.allowed,
            message=result.reason,
            nbr_secrets=0,
            payload=payload,
        )

    def _scan_content(self, payload: HookPayload) -> HookResult:
        """Scan a single payload for secrets."""
        return self._scan_contents([payload])[0]

    def _scan_contents(self, payloads: List[HookPayload]) -> List[HookResult]:
        """Scan the payloads for secrets in as few API calls as possible.

        Everything that needs scanning is handed to the SecretScanner in one call,
        which chunks it to the API's per-document and per-batch limits. Returns one
        HookResult per payload, in order.
        """
        results = [HookResult.allow(payload) for payload in payloads]

        # (index in `payloads`, document to scan, verdict cache key).
        to_scan: List[Tuple[int, Scannable, Optional[str]]] = []
        for index, payload in enumerate(payloads):
            # Excluded by secret.ignored_paths: never read, never sent, allowed.
            # Before payload.scannable, which would read the file.
            if self._is_excluded(payload):
                continue
            # One Scannable for both the cache key and the scan, so the two can
            # never disagree about what was scanned.
            scannable = payload.scannable
            try:
                # Short path: if there is no content, no need to do an API call.
                if payload.empty:
                    continue
                # is_longer_than() answers from the byte size when it can, so an
                # oversized document is not pulled into memory just to key the cache.
                content = (
                    ""
                    if scannable.is_longer_than(DOCUMENT_SIZE_THRESHOLD_BYTES)
                    else scannable.content
                )
            except OSError:
                # A candidate path that stats but cannot be opened is not a
                # document: SecretScanner only skips a missing file, so batching
                # it raises there and fails the whole event open, leaving the
                # command or prompt text of that same event unscanned.
                continue
            except Exception:
                # Undecodable: no cache key, and it still goes to the scanner,
                # which decides how to skip it and says so.
                content = ""

            key = (
                verdict_key(
                    self.scanner.client.base_uri,
                    self.scanner.client.api_key,
                    self.scanner.secret_config,
                    scannable.filename,
                    content,
                )
                if content
                else None
            )

            # Shortest path: this exact document already came back clean recently, so
            # it never goes in the batch. A Read is scanned twice -- PreToolUse and
            # PostToolUse both resolve to File(file_path) (see HookPayload.scannable),
            # so both send an identical document. has_already_been_seen() does not
            # catch that pair, as it debounces on the raw stdin payload, which differs
            # between the two events.
            if key and has_clean_verdict(key):
                continue

            to_scan.append((index, scannable, key))

        if not to_scan:
            return results

        # A batch is looked up by url, so each url must appear at most once per round;
        # a repeat waits for the next round. Today's parsers never repeat a url (BASH:
        # command text, READ: path, else a content sha256), but nothing upstream
        # enforces it.
        remaining = to_scan
        while remaining:
            batch: List[Tuple[int, Scannable, Optional[str]]] = []
            leftover: List[Tuple[int, Scannable, Optional[str]]] = []
            batched_urls: Set[str] = set()
            for entry in remaining:
                url = entry[1].url
                if url in batched_urls:
                    leftover.append(entry)
                else:
                    batched_urls.add(url)
                    batch.append(entry)

            with create_message_only_scanner_ui() as scanner_ui:
                scan = self.scanner.scan(
                    [scannable for _, scannable, _ in batch], scanner_ui=scanner_ui
                )

            # The scan answers out of send order, so each document is looked up by url.
            answers = scan.by_url()

            for index, scannable, key in batch:
                result = answers.get(scannable.url)
                if result is None:
                    # Scan said nothing about this document (skipped or degraded): not
                    # a verdict, so nothing to cache and nothing to block on.
                    continue
                secrets: List[Secret] = list(result.secrets)
                if not secrets:
                    # Per-document: cache only if nothing was filtered out locally,
                    # else "no secret" is a verdict about the config, not the content.
                    if key and not result.ignored_secrets_count_by_kind:
                        store_clean_verdict(key)
                    continue
                payload = payloads[index]
                results[index] = HookResult(
                    block=True,
                    message=self._message_from_secrets(
                        secrets,
                        payload,
                        escape_markdown=True,
                    ),
                    nbr_secrets=len(secrets),
                    payload=payload,
                )

            remaining = leftover

        return results

    @staticmethod
    def _message_from_secrets(
        secrets: List[Secret],
        payload: HookPayload,
        escape_markdown: bool = False,
    ) -> str:
        """
        Format detected secrets into a user-friendly message.

        Args:
            secrets: List of detected secrets
            payload: The hook payload the secrets were found in
            escape_markdown: If True, make the message robust to markdown
                rendering (agents render it as markdown): escape asterisks and
                turn single newlines into hard breaks so they don't collapse
                into spaces

        Returns:
            Formatted message describing the detected secrets
        """
        # Dispatch event-first, then tool: what the message should say depends
        # first on *when* the secret was caught (before vs. after it reached
        # the agent), and only then on how the offending tool is named.
        # Exception: a USER_PROMPT event also carries a Tool.READ payload per file
        # mentioned in the prompt (see _parse_user_prompt). The secret is in that
        # file, not the prompt, so it gets the file wording, not the prompt wording.
        if payload.event_type == EventType.USER_PROMPT and payload.tool != Tool.READ:
            template = _USER_PROMPT_TEMPLATE
        elif payload.event_type == EventType.POST_TOOL_USE:
            template = _POST_TEMPLATES.get(payload.tool, _POST_OTHER_TEMPLATE)
        else:
            # PRE_TOOL_USE, and any other event type (EventType.OTHER) falls
            # back to the same "not leaked yet" wording.
            template = _PRE_TEMPLATES.get(payload.tool, _PRE_OTHER_TEMPLATE)

        count = len(secrets)
        message = template.format(
            count=count,
            secrets=pluralize("secret", count),
            were=pluralize("was", count, "were"),
            them=pluralize("it", count, "them"),
            identifier=payload.identifier,
            secret_lines="\n".join(_secret_lines(secrets, escape_markdown)),
            post_remediation_steps=_post_remediation_steps(secrets),
            false_positive_instructions=_false_positive_block(secrets),
        )
        if escape_markdown:
            message = markdown_hard_breaks(message)
        return message

    @staticmethod
    def _send_secret_notification(
        result: HookResult,
    ) -> None:
        """
        Send a best-effort desktop notification when secrets are detected.

        This runs on the security-critical PostToolUse path (the secret has
        already leaked to the agent), so it must NEVER crash the hook: the
        whole body is guarded and any failure is swallowed, letting the block
        decision still be emitted.

        Args:
            result: The blocking scan result.
        """
        try:
            tool = result.payload.tool
            source = "using a tool"
            if tool == Tool.READ:
                source = "reading a file"
            elif tool == Tool.BASH:
                # This should always be present, unless agents changed their
                # payload in an update.
                command = result.payload.raw.get("tool_input", {}).get("command", "")
                source = (
                    f"running the command `{command}`"
                    if command
                    else "running a command"
                )
            title = "ggshield - Secrets Detected"
            message = (
                f"{result.payload.agent.display_name} got access to {result.nbr_secrets}"
                f" {pluralize('secret', result.nbr_secrets)} by {source}"
            )
            _send_desktop_notification(title, message)
        except Exception:
            # This is best effort, we don't want to propagate an error
            # if the notification fails.
            pass
