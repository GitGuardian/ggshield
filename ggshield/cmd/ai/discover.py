"""
MCP Discover command - Discovers MCP servers and optionally probes them
for tools, resources, and prompts.
"""

import json
from typing import Any, Dict, List, Optional

import click
from pygitguardian.models import AIDiscovery

from ggshield.cmd.utils.common_options import add_common_options
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core import ui
from ggshield.core.client import create_client_from_config
from ggshield.core.errors import APIKeyCheckError, UnknownInstanceError
from ggshield.core.text_utils import STYLE, format_text, pluralize
from ggshield.verticals.ai.agent_activity import (
    AgentActivityReport,
    collect_agent_activity,
)
from ggshield.verticals.ai.agents import AGENTS
from ggshield.verticals.ai.discovery import (
    discover_ai_configuration,
    save_discovery_cache,
    submit_ai_discovery,
)
from ggshield.verticals.ai.history import BackfillReport, backfill_mcp_history
from ggshield.verticals.ai.models import Scope


@click.command(name="discover")
@click.option(
    "--json",
    "use_json",
    is_flag=True,
    default=False,
    help="Output as JSON",
)
@click.option(
    "--history",
    "scan_history",
    is_flag=True,
    default=False,
    help="Also backfill historical MCP tool calls parsed from agent transcripts.",
)
@click.option(
    "--activity",
    "scan_activity",
    is_flag=True,
    default=False,
    help="[Experimental] Also backfill all agent activity events. Will later be merged with --history.",
)
@add_common_options()
@click.pass_context
def discover_cmd(
    ctx: click.Context,
    use_json: bool,
    scan_history: bool,
    scan_activity: bool,
    **kwargs: Any,
) -> None:
    """
    Discover MCP servers and their configuration.

    Parses configuration files from supported assistants.

    Examples:
      ggshield ai discover
      ggshield ai discover --json
      ggshield ai discover --history
    """

    config = discover_ai_configuration()

    ctx_obj = ContextObj.get(ctx)
    try:
        client = create_client_from_config(ctx_obj.config)
    except (APIKeyCheckError, UnknownInstanceError) as exc:
        ui.display_warning(
            f"Skipping upload of AI discovery to GitGuardian ({exc}). "
            "Authenticate with `ggshield auth login` to enable upload."
        )
        return

    backfill_report = BackfillReport()
    activity_report: Optional[AgentActivityReport] = None
    try:
        config = submit_ai_discovery(client, config)
        save_discovery_cache(config)
        if scan_history:
            backfill_report = backfill_mcp_history(client, config)
        if scan_activity:
            activity_report = collect_agent_activity(
                client, config.user, AGENTS.values()
            )
    except Exception as exc:
        if "missing the following scope:" in str(exc):
            scope = str(exc).split("missing the following scope:")[1].strip()
            reason = f'this command requires the {scope} scope. Run ggshield auth login --scopes "{scope}" to grant it.'
        else:
            reason = str(exc)
        ui.display_warning(f"Could not upload AI discovery to GitGuardian: {reason}")

    # Summarize after sending to GIM, so we can benefit from its fixes.
    summary = _summarize_discovery(config, backfill_report, activity_report)

    if use_json:
        click.echo(json.dumps(summary, indent=2))
    else:
        print_summary(summary)


def _summarize_discovery(
    config: AIDiscovery,
    report: BackfillReport,
    activity_report: Optional[AgentActivityReport] = None,
) -> Dict[str, Any]:
    """Summarize what we want to show of the discovery."""
    servers = []
    for server in config.servers:
        projects = set()
        agents = set()
        installed_globally = False
        for conf in server.configurations:
            agents.add(conf.agent)
            if conf.scope == Scope.USER:
                installed_globally = True
            elif conf.project:
                projects.add(conf.project)
        servers.append(
            {
                # If we don't have a display name, any configuration name
                # is probably less confusing than our deduplication key
                "name": server.display_name or server.configurations[0].name,
                "installed_globally": installed_globally,
                "projects": sorted(projects),
                "agents": sorted(AGENTS[name].display_name for name in agents),
            }
        )
    servers = sorted(servers, key=lambda x: x["name"])
    agents = sorted(
        (
            {
                "name": AGENTS[agent.name].display_name,
                "hooks_installed": agent.hooks_installed,
            }
            for agent in config.agents
        ),
        key=lambda x: x["name"],
    )
    summary: Dict[str, Any] = {
        "agents": agents,
        "servers": servers,
        "history": {
            "parsed": report.parsed,
            "ingested": report.ingested,
            "skipped": report.skipped,
        },
    }
    if activity_report is not None:
        summary["agent_activity"] = {
            "parsed": activity_report.parsed,
            "ingested": activity_report.ingested,
            "dropped": activity_report.dropped,
            "failed_batches": activity_report.failed_batches,
        }
    return summary


def print_summary(summary: Dict[str, Any]) -> None:
    """Print the summary of the discovery."""
    agents: List[Dict[str, Any]] = summary.get("agents", [])
    servers: List[Dict[str, Any]] = summary.get("servers", [])

    nb_servers = len(servers)
    nb_agents = len(agents)

    if nb_servers == 0:
        click.echo(format_text("No MCP servers discovered", STYLE["no_secret"]))
        return

    def _format_agent(agent: Dict[str, Any]) -> str:
        name = format_text(agent.get("name", "unknown"), STYLE["heading"])
        status = "hooks installed" if agent.get("hooks_installed") else "no hooks"
        return f"{name} ({status})"

    click.echo(
        f"\n{format_text('Agents discovered:', STYLE['key'])} "
        f"{', '.join(_format_agent(agent) for agent in agents) if agents else 'none'} "
        f"({nb_agents} {pluralize('agent', nb_agents)})"
    )
    click.echo(
        f"{format_text('MCP servers found:', STYLE['key'])} "
        f"{nb_servers} {pluralize('server', nb_servers)}\n"
    )

    for server in servers:
        name = server.get("name", "unknown")
        installed_globally = server.get("installed_globally", False)
        projects: List[str] = server.get("projects", [])
        server_agents: List[str] = server.get("agents", [])

        start = format_text(">", STYLE["detector_line_start"])
        server_name = format_text(name, STYLE["detector"])
        agents_names = ", ".join(
            format_text(agent, STYLE["heading"]) for agent in server_agents
        )
        click.echo(f"{start} {server_name} ({agents_names})")

        indent = "   "
        scope = "user" if installed_globally else "project"
        click.echo(f"{indent}{format_text('Scope:', STYLE['key'])} {scope}")
        if projects:
            click.echo(f"{indent}{format_text('Projects:', STYLE['key'])}")
            for j, project in enumerate(projects):
                connector = "└─" if j == len(projects) - 1 else "├─"
                click.echo(f"{indent}{connector} {project}")

    click.echo()

    history = summary.get("history")
    if history and history.get("parsed"):
        click.echo(f"{format_text('Backfilling MCP usage history…', STYLE['key'])}")
        click.echo(f"  • Parsed {history['parsed']:,} events")
        click.echo(
            f"  • Recorded {history['ingested']:,} events "
            f"({history.get('skipped', 0):,} skipped)"
        )

    agent_activity = summary.get("agent_activity")
    # Only surface the agent-activity block when there is something to report;
    # otherwise every `--history` run prints an all-zeros section.
    if agent_activity is not None and (
        agent_activity["parsed"] or agent_activity.get("failed_batches", 0)
    ):
        click.echo(f"{format_text('Collecting agent activity…', STYLE['key'])}")
        click.echo(f"  • Parsed {agent_activity['parsed']:,} activity events")
        click.echo(f"  • Recorded {agent_activity['ingested']:,} activity events ")
        if agent_activity.get("failed_batches", 0) > 0:
            label = format_text("Failed batches:", STYLE["detector_line_start"])
            click.echo(f"  • {label} {agent_activity['failed_batches']:,}")
        if agent_activity.get("dropped", 0) > 0:
            label = format_text("Dropped (unscannable):", STYLE["detector_line_start"])
            click.echo(f"  • {label} {agent_activity['dropped']:,}")
