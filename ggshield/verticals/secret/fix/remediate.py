import difflib
import json
import os
import subprocess
from enum import Enum
from itertools import islice
from pathlib import Path
from typing import Dict, List

import click
import requests
from rich.progress import Progress

from ggshield.verticals.secret.fix.list import Location


OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
LIMIT_READ_FILES = 5
CHATGPT_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "read-file",
            "description": "Read content of a file",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write-file",
            "description": "Write content to a file",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "append-file",
            "description": "Append content to a file",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
            },
        },
    },
]


def prompt(
    filepath: Path,
    locations: List[Location],
    file_content: str,
    directory_tree: str,
    rejected: List[str],
) -> List[Dict[str, str]]:
    secrets = "\n".join(
        f" - {location.detector_name}: {location.string_matched}"
        for location in locations
    )
    messages = [
        {
            "role": "system",
            "content": f"""
You are a code security expert, specializing in helping developers remove secrets from their code, also known as remediation.
You should read the affected file and any related files if necessary to understand how secrets should be handled within this repository.
When possible and applicable, prefer appending to the end of the file rather than reading and rewriting it.
Once you have gathered enough information, re-write the affected file and related files if necessary, but limit your changes strictly to the remediation of the secret.

You have access to the following tools with specific restrictions:
- read-file (path): limited to {LIMIT_READ_FILES} distinct files
- write-file (path, content): only for files that have been previously read
- append-file (path, content): any file

The discussion concludes once the affected file is written, and this should be done last.
            """.strip(),  # noqa: E501
        },
        {
            "role": "user",
            "content": f"Filename: {filepath}\nSecrets:\n{secrets}\nRepository tree:\n{directory_tree}",
        },
        *[
            {
                "role": "user",
                "content": f"The following remediation is not accepted:\n```\n{diff}\n```",
            }
            for diff in rejected
        ],
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "call_file_read",
                    "type": "function",
                    "function": {
                        "name": "read-file",
                        "arguments": json.dumps({"path": str(filepath)}),
                    },
                }
            ],
        },
        {
            "role": "tool",
            "tool_call_id": "call_file_read",
            "content": file_content,
        },
    ]
    return messages


class Choice(Enum):
    ACCEPT = "accept"
    REJECT = "reject"
    SKIP = "skip"


def prompt_choice():
    value_mapping = {
        choice.value[: i + 1]: choice
        for choice in Choice
        for i in range(len(choice.value))
    }

    def value_proc(x: str) -> Choice:
        try:
            return value_mapping[x]
        except KeyError:
            raise click.UsageError("The value you entered was invalid.")

    return click.prompt(
        "Accept fix? [Accept,reject,skip]",
        value_proc=value_proc,
        default=Choice.ACCEPT.value,
        show_default=False,
    )


def openai(
    filepath: Path, locations: List[Location], rejected: List[str], progress: Progress
) -> Dict[Path, str]:
    directory_tree = subprocess.run(
        ["tree", "-n"], capture_output=True, encoding="utf-8"
    ).stdout
    file_content = filepath.read_text()

    read = {filepath}
    changes = {}
    messages = prompt(filepath, locations, file_content, directory_tree, rejected)
    stop = False

    progress_task = progress.add_task("GPT is working...", total=None)
    while not stop:
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            json={
                "model": "gpt-4o",
                "messages": messages,
                "tools": CHATGPT_TOOLS,
                "tool_choice": "required",
                "user": "ggshield",
            },
            headers={"Authorization": f"Bearer {OPENAI_API_KEY}"},
        )

        if "error" in response.json():
            raise click.ClickException(response.json()["error"]["message"])
        answer = response.json()["choices"][0]
        messages.append(answer["message"])
        if "tool_calls" in answer["message"]:
            for tool_call in answer["message"]["tool_calls"]:
                tool_name = tool_call["function"]["name"]
                tool_args = json.loads(tool_call["function"]["arguments"])

                if tool_name == "read-file":
                    file = Path(tool_args["path"])
                    if len(read) <= LIMIT_READ_FILES:
                        progress.print("Read " + str(file))
                        read.add(file)
                        messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": tool_call["id"],
                                "content": (
                                    (
                                        changes[file]
                                        if file in changes
                                        else file.read_text()
                                    )
                                    if file.exists()
                                    else "ERROR: File does not exists"
                                ),
                            }
                        )
                    else:
                        progress.print(
                            f"Reached limit of {LIMIT_READ_FILES} files to read"
                        )
                        messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": tool_call["id"],
                                "content": f"ERROR: Limit of {LIMIT_READ_FILES} files reached",
                            }
                        )
                elif tool_name == "write-file":
                    file = Path(tool_args["path"])
                    if file.exists() and file in read:
                        progress.print("Write to " + str(file))
                        changes[file] = tool_args["content"]
                        messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": tool_call["id"],
                                "content": "OK",
                            }
                        )
                    else:
                        if not file.exists():
                            progress.print("Try to write nonexistent file " + str(file))
                            error = "File does not exists"
                        else:
                            progress.print("Try to write unread file " + str(file))
                            error = "File must be read first"
                        messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": tool_call["id"],
                                "content": f"ERROR: {error}",
                            }
                        )

                    if file == filepath:
                        stop = True
                elif tool_name == "append-file":
                    file = Path(tool_args["path"])
                    if file.exists():
                        progress.print("Append to " + str(file))
                        file_content = changes.get(file, file.read_text())
                        need_newline = not file_content.endswith("\n")
                        changes[file] = (
                            file_content
                            + ("\n" if need_newline else "")
                            + tool_args["content"]
                        )
                        messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": tool_call["id"],
                                "content": "OK",
                            }
                        )
                    else:
                        progress.print("Try to append nonexistent file " + str(file))
                        messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": tool_call["id"],
                                "content": "ERROR: File does not exists",
                            }
                        )
                else:
                    raise click.ClickException(f"Unknown tool {tool_name}")

    progress.update(progress_task, completed=True)
    return changes


def remediate(filepath: Path, locations: List[Location]) -> None:
    rejected = []
    while True:
        with Progress() as progress:
            changes = openai(filepath, locations, rejected, progress)

        content_diff = ""
        for file, remediated_content in changes.items():
            click.echo("")
            click.secho(file, fg="blue")

            current_content = file.read_text()

            content_diff = "\n".join(
                islice(
                    difflib.unified_diff(
                        current_content.splitlines(), remediated_content.splitlines()
                    ),
                    2,
                    None,
                )
            )
            colored_diff = ""
            for i, line in enumerate(content_diff.splitlines(keepends=True)):
                if line.startswith("+"):
                    colored_diff += click.style(line, fg="green")
                elif line.startswith("-"):
                    colored_diff += click.style(line, fg="red")
                elif line.startswith("@@ ") and i == 0:
                    colored_diff += click.style(line, fg="blue")
                else:
                    colored_diff += line

            click.echo(colored_diff)

        choice = prompt_choice()
        if choice == Choice.ACCEPT:
            break
        elif choice == Choice.REJECT:
            rejected.append(content_diff)
            click.echo("")
        else:
            return

    for file, remediated_content in changes.items():
        file.write_text(remediated_content)
