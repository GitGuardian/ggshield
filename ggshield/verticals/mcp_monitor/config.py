"""
MCP configuration loading utilities.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


def load_json_file(path: Path) -> Union[Dict[str, Any], List[Any]]:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def save_json_file(path: Path, data: Union[Dict[str, Any], List[Any]]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=4))
    except OSError:
        pass


def load_mcp_config(workspace_roots: List[str]) -> Dict[str, Any]:
    for workspace in workspace_roots:
        workspace_mcp = Path(workspace) / ".cursor" / "mcp.json"
        if workspace_mcp.exists():
            config = load_json_file(workspace_mcp)
            if isinstance(config, dict):
                return config

    global_mcp = Path.home() / ".cursor" / "mcp.json"
    if global_mcp.exists():
        config = load_json_file(global_mcp)
        if isinstance(config, dict):
            return config

    return {}


def get_mcp_cache_dir() -> Path:
    cache_dir = Path.home() / ".cache" / "ggshield" / "mcp_monitor"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def get_mcp_output_dir() -> Path:
    output_dir = Path.home() / ".cache" / "ggshield" / "mcp_monitor" / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def extract_host_from_config(server_config: Optional[Dict[str, Any]]) -> Optional[str]:
    if not server_config:
        return None

    env_vars = server_config.get("env", {})

    if "CLICKHOUSE_HOST" in env_vars:
        return env_vars["CLICKHOUSE_HOST"]

    if "GITLAB_API_URL" in env_vars:
        url = env_vars["GITLAB_API_URL"]
        return url.replace("https://", "").replace("http://", "").split("/")[0]

    args = server_config.get("args", [])
    for arg in args:
        if isinstance(arg, str):
            if arg.startswith("https://"):
                return arg.replace("https://", "").split("/")[0]
            if arg.startswith("http://"):
                return arg.replace("http://", "").split("/")[0]

    return None


def get_mcp_remote_url(server_config: Dict[str, Any]) -> Optional[str]:
    args = server_config.get("args", [])
    for arg in args:
        if isinstance(arg, str) and (
            arg.startswith("http://") or arg.startswith("https://")
        ):
            return arg
    return None
