"""
Plugin update command - updates installed plugins.
"""

import logging
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import click
import requests
from packaging import version as packaging_version

from ggshield.cmd.utils.common_options import add_common_options
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core import ui
from ggshield.core.client import create_client_from_config
from ggshield.core.config.enterprise_config import EnterpriseConfig
from ggshield.core.errors import ExitCode
from ggshield.core.plugin.client import (
    PluginAPIClient,
    PluginAPIError,
    PluginsNotEnabledError,
    PluginSourceType,
)
from ggshield.core.plugin.downloader import DownloadError, PluginDownloader
from ggshield.core.plugin.loader import PluginLoader, enable_installed_plugin
from ggshield.core.plugin.platform import get_platform_info
from ggshield.core.plugin.signature import SignatureVerificationMode
from ggshield.core.text_utils import pluralize


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _InstallationReport:
    """Args for one deferred ``report_installation`` call.

    Buffered during the update loop and fired after ``enterprise_config.save()``
    so a stalled ``/installed`` endpoint can't desync wheel-on-disk from
    the on-disk version record.
    """

    name: str
    version: str
    platform: str
    arch: str


def _is_newer_version(installed_version: str, candidate_version: str) -> bool:
    """Return True if candidate version is newer than installed version."""
    try:
        return packaging_version.parse(installed_version) < packaging_version.parse(
            candidate_version
        )
    except Exception as e:
        logger.warning(
            "Failed to parse plugin versions '%s' and '%s': %s",
            installed_version,
            candidate_version,
            e,
        )
        return False


@click.command()
@click.argument("plugin_name", required=False)
@click.option(
    "--all",
    "update_all",
    is_flag=True,
    help="Update all installed plugins",
)
@click.option(
    "--check",
    "check_only",
    is_flag=True,
    help="Check for updates without installing",
)
@click.option(
    "--allow-unsigned",
    "allow_unsigned",
    is_flag=True,
    help="Allow updating plugins without valid signatures (overrides strict mode)",
)
@add_common_options()
@click.pass_context
def update_cmd(
    ctx: click.Context,
    plugin_name: Optional[str],
    update_all: bool,
    check_only: bool,
    allow_unsigned: bool,
    **kwargs: Any,
) -> None:
    """
    Update installed plugins.

    Check for available updates:

        ggshield plugin update --check

    Update a specific plugin:

        ggshield plugin update tokenscanner

    Update all installed plugins:

        ggshield plugin update --all

    Note: Only plugins from GitGuardian API and GitHub releases can be auto-updated.
    Plugins installed from local files or GitHub artifacts cannot be auto-updated.
    """
    if not plugin_name and not update_all and not check_only:
        ui.display_error("Please specify a plugin name, use --all, or use --check")
        ui.display_info("Usage: ggshield plugin update <plugin_name>")
        ui.display_info("       ggshield plugin update --all")
        ui.display_info("       ggshield plugin update --check")
        ctx.exit(ExitCode.USAGE_ERROR)

    ctx_obj = ContextObj.get(ctx)
    config = ctx_obj.config

    # Signature verification is strict by default. The only override is the
    # explicit per-command --allow-unsigned flag.
    enterprise_config = EnterpriseConfig.load()
    signature_mode = (
        SignatureVerificationMode.WARN
        if allow_unsigned
        else SignatureVerificationMode.STRICT
    )
    loader = PluginLoader(enterprise_config)
    downloader = PluginDownloader()

    installed_plugins = {p.name: p for p in loader.discover_plugins() if p.is_installed}

    # Determine which plugins to check/update
    if update_all or check_only:
        plugins_to_process = list(installed_plugins.keys())
    else:
        if plugin_name not in installed_plugins:
            ui.display_error(f"Plugin '{plugin_name}' is not installed")
            ui.display_info("Use 'ggshield plugin list' to see installed plugins")
            ctx.exit(ExitCode.USAGE_ERROR)
        plugins_to_process = [plugin_name]

    if not plugins_to_process:
        ui.display_info("No plugins installed.")
        ui.display_info("Use 'ggshield plugin install' to install plugins.")
        return

    # Categorize plugins by source type
    gitguardian_plugins: List[str] = []
    github_release_plugins: List[str] = []
    non_updatable_plugins: List[Dict[str, Any]] = []

    for name in plugins_to_process:
        source = downloader.get_plugin_source(name)
        if source is None:
            # Legacy manifest or unknown source - try platform
            gitguardian_plugins.append(name)
        elif source.type == PluginSourceType.PLATFORM:
            gitguardian_plugins.append(name)
        elif source.type == PluginSourceType.GITHUB_RELEASE:
            github_release_plugins.append(name)
        else:
            # Local file, URL, or artifact - cannot auto-update
            non_updatable_plugins.append(
                {
                    "name": name,
                    "source_type": source.type,
                }
            )

    # Check GitGuardian API for updates
    updates_available: List[Dict[str, Any]] = []
    plugin_api_client: Optional[PluginAPIClient] = None
    # Tracks whether we asked the platform for catalog updates and got a
    # usable answer. Stays False when there were no platform plugins in
    # the batch OR when the catalog fetch failed and we degraded to
    # github-only checks. Drives the empty-result message at the bottom
    # so we don't claim "All updatable plugins are up to date" when half
    # the picture was actually missing.
    platform_checked = False

    if gitguardian_plugins:
        catalog_error: Optional[str] = None
        try:
            client = create_client_from_config(config)
            plugin_api_client = PluginAPIClient(client)
            catalog = plugin_api_client.get_available_plugins()
            available_plugins = {p.name: p for p in catalog.plugins if p.available}
            platform_checked = True

            for name in gitguardian_plugins:
                installed = installed_plugins.get(name)
                available = available_plugins.get(name)

                if not installed or not available:
                    continue

                installed_version = installed.version
                latest_version = available.latest_version

                if (
                    installed_version
                    and latest_version
                    and _is_newer_version(installed_version, latest_version)
                ):
                    updates_available.append(
                        {
                            "name": name,
                            "installed_version": installed_version,
                            "latest_version": latest_version,
                            "source_type": PluginSourceType.PLATFORM,
                        }
                    )

        except PluginsNotEnabledError:
            catalog_error = (
                "Plugin system is not available on this workspace. "
                "Contact your administrator."
            )
        except PluginAPIError as e:
            catalog_error = str(e)
        except Exception as e:
            catalog_error = f"Failed to connect to GitGuardian: {e}"

        if catalog_error is not None:
            # Degrade rather than abort when there's still other work to do:
            # GitHub-release plugins and the non-updatable footer don't depend
            # on the GitGuardian catalog, so a single failed fetch shouldn't
            # kill an otherwise valid ``update --all`` invocation. When the
            # platform fetch is the only thing we were asked to do (no
            # github_release plugins in the batch), surface as a hard error
            # so the exit code still reflects the failure.
            if github_release_plugins:
                ui.display_warning(
                    f"Skipping GitGuardian-hosted plugin updates: {catalog_error}"
                )
            else:
                ui.display_error(catalog_error)
                ctx.exit(ExitCode.UNEXPECTED_ERROR)
                return

    # Check GitHub releases for updates
    for name in github_release_plugins:
        source = downloader.get_plugin_source(name)
        if not source or not source.github_repo:
            continue

        installed = installed_plugins.get(name)
        if not installed or not installed.version:
            continue

        latest_release = _check_github_release_update(source.github_repo)
        if latest_release:
            latest_version = latest_release.get("tag_name", "").lstrip("v")
            if latest_version and _is_newer_version(installed.version, latest_version):
                # Find wheel asset in release
                wheel_url = _find_wheel_asset(latest_release)
                if wheel_url:
                    updates_available.append(
                        {
                            "name": name,
                            "installed_version": installed.version,
                            "latest_version": latest_version,
                            "source_type": PluginSourceType.GITHUB_RELEASE,
                            "download_url": wheel_url,
                            "github_repo": source.github_repo,
                        }
                    )

    # When the platform check was skipped (catalog fetch failed but we
    # still have github_release work to do), the "everything is up to
    # date" wording lies about half the picture. Surface that the
    # platform side wasn't actually checked so the user knows their
    # GitGuardian-hosted plugins are unverified, not confirmed-current.
    no_updates_msg = (
        "No updates found for checked plugins; "
        "GitGuardian-hosted plugins were skipped."
        if gitguardian_plugins and not platform_checked
        else "All updatable plugins are up to date."
    )

    # Check-only mode
    if check_only:
        if updates_available:
            ui.display_heading("Updates Available")
            for update in updates_available:
                source_label = (
                    "GitGuardian"
                    if update["source_type"] == PluginSourceType.PLATFORM
                    else "GitHub"
                )
                ui.display_info(
                    f"  {update['name']}: {update['installed_version']} -> "
                    f"{update['latest_version']} ({source_label})"
                )
            ui.display_info("")
            ui.display_info("Run 'ggshield plugin update --all' to update.")
        else:
            ui.display_info(no_updates_msg)

        _display_non_updatable_footer(non_updatable_plugins)
        return

    # Update mode
    if not updates_available:
        if plugin_name:
            # Check if it's non-updatable
            source = downloader.get_plugin_source(plugin_name)
            if source and source.type not in (
                PluginSourceType.PLATFORM,
                PluginSourceType.GITHUB_RELEASE,
            ):
                ui.display_error(
                    f"Plugin '{plugin_name}' was installed from "
                    f"{source.type.value.replace('_', ' ')} and cannot be "
                    f"auto-updated."
                )
                ui.display_info("Re-install the plugin manually to update.")
                ctx.exit(ExitCode.USAGE_ERROR)
            ui.display_info(f"Plugin '{plugin_name}' is already up to date.")
        elif update_all:
            ui.display_info(no_updates_msg)
            # Non-updatable plugins are still worth surfacing even when
            # everything else is current — the user asked about every
            # installed plugin, not just the auto-updatable ones.
            _display_non_updatable_footer(non_updatable_plugins)
        else:
            ui.display_info(no_updates_msg)
        return

    success_count = 0
    error_count = 0
    # Deferred best-effort report calls. ``report_installation`` is
    # synchronous over HTTP, and update.py historically invoked it
    # between the wheel install and the final ``enterprise_config.save()``
    # — a stalled ``/installed`` endpoint would block the command after
    # the wheel was already on disk but before the version was persisted.
    # Buffer the calls instead and fire them after ``save()`` so the
    # config is always durable before we attempt analytics.
    installation_reports: List[_InstallationReport] = []

    for update in updates_available:
        name = update["name"]
        latest_version = update["latest_version"]
        source_type = update["source_type"]

        ui.display_info(
            f"Updating {name}: {update['installed_version']} -> {latest_version}..."
        )

        try:
            if source_type == PluginSourceType.PLATFORM:
                assert plugin_api_client is not None
                platform_info = get_platform_info()
                with plugin_api_client.download_plugin(
                    name,
                    platform_info=platform_info,
                    version=latest_version,
                ) as (info, chunks):
                    bundle_bytes: Optional[bytes] = None
                    if info.signature_url:
                        try:
                            bundle_bytes = plugin_api_client.download_signature_bundle(
                                info.signature_url
                            )
                        except PluginAPIError as bundle_err:
                            # See install.py: STRICT propagates; WARN
                            # treats the bundle as unavailable rather
                            # than aborting an otherwise valid upgrade.
                            if signature_mode == SignatureVerificationMode.STRICT:
                                raise
                            ui.display_warning(
                                f"Could not fetch signature bundle for {name}: "
                                f"{bundle_err}. Continuing without verification "
                                f"(--allow-unsigned)."
                            )
                    wheel_path = downloader.download_and_install(
                        info,
                        chunks,
                        name,
                        signature_mode=signature_mode,
                        bundle_bytes=bundle_bytes,
                    )
                installation_reports.append(
                    _InstallationReport(
                        name=name,
                        version=info.version,
                        platform=platform_info.os,
                        arch=platform_info.arch,
                    )
                )

            elif source_type == PluginSourceType.GITHUB_RELEASE:
                download_url = update.get("download_url")
                github_repo = update.get("github_repo")
                if not download_url or not github_repo:
                    raise DownloadError(
                        "Missing GitHub release metadata for plugin update"
                    )

                _, _, wheel_path = downloader.download_from_github_release(
                    download_url, signature_mode=signature_mode
                )

            else:
                raise DownloadError(f"Unsupported plugin source type: {source_type}")

            # Mirror install.py: the loader keys enablement by the
            # wheel's entry-point name (when present), so update must
            # use the same key — otherwise the row written below falls
            # out of sync with discover_plugins and the plugin is
            # silently disabled after the upgrade. ``name`` here is
            # already the loader's canonical key, but a stale alias
            # under the wheel's distribution name from a pre-fix
            # install may still be on disk; ``enable_installed_plugin``
            # cleans that up and carries any ``auto_update: false``
            # forward to the canonical row.
            enable_installed_plugin(enterprise_config, name, latest_version, wheel_path)

            ui.display_info(f"  Updated {name} to v{latest_version}")
            success_count += 1

        except Exception as e:
            ui.display_error(f"  Failed to update {name}: {e}")
            error_count += 1

    # Save config FIRST so a hang inside the analytics reports below
    # can't desync the on-disk version from the wheel that's already on
    # disk. Each report is best-effort and bounded by HTTP_TIMEOUT_SECONDS
    # inside ``report_installation`` itself.
    enterprise_config.save()

    # ``installation_reports`` is only appended inside the PLATFORM branch
    # above, which itself runs after ``plugin_api_client`` has been set —
    # the buffer is non-empty IFF the client exists, so no None-guard needed.
    for report in installation_reports:
        assert plugin_api_client is not None  # invariant: see comment above
        plugin_api_client.report_installation(
            report.name,
            report.version,
            report.platform,
            report.arch,
        )

    # Summary
    if success_count > 0:
        ui.display_info("")
        ui.display_info(
            f"{success_count} {pluralize('plugin', success_count)} updated successfully."
        )

    if update_all:
        _display_non_updatable_footer(non_updatable_plugins)

    if error_count > 0:
        ctx.exit(ExitCode.UNEXPECTED_ERROR)


def _display_non_updatable_footer(
    non_updatable_plugins: List[Dict[str, Any]],
) -> None:
    """Render the shared 'Cannot Auto-Update' footer.

    Lists each non-updatable plugin with a humanised source label
    (matching ``plugin list``'s ``local_file`` → ``local file`` style)
    so the user gets the same vocabulary across commands.
    """
    if not non_updatable_plugins:
        return
    ui.display_info("")
    ui.display_heading("Cannot Auto-Update")
    for plugin in non_updatable_plugins:
        ui.display_info(
            f"  {plugin['name']}: installed from "
            f"{plugin['source_type'].value.replace('_', ' ')}"
        )
    ui.display_info("Re-install these plugins manually to update.")


def _check_github_release_update(github_repo: str) -> Optional[Dict[str, Any]]:
    """
    Check for the latest release of a GitHub repository.

    Args:
        github_repo: Repository in "owner/repo" format.

    Returns:
        Release data dict or None if check fails.
    """
    # Get GitHub token if available
    github_token = os.environ.get("GITHUB_TOKEN")

    headers: Dict[str, str] = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    try:
        response = requests.get(
            f"https://api.github.com/repos/{github_repo}/releases/latest",
            headers=headers,
            timeout=10,
        )
        if response.status_code == 200:
            return response.json()
    except requests.RequestException:
        pass

    return None


def _find_wheel_asset(release: Dict[str, Any]) -> Optional[str]:
    """
    Find a compatible wheel asset in a GitHub release.

    Prefers platform-specific wheels over pure-python wheels.

    Args:
        release: GitHub release data.

    Returns:
        Download URL for the wheel or None.
    """
    from ggshield.core.plugin.platform import get_wheel_platform_tags

    compatible_tags = get_wheel_platform_tags()
    assets = release.get("assets", [])

    fallback_url = None
    for asset in assets:
        name = asset.get("name", "")
        if not name.endswith(".whl"):
            continue
        url = asset.get("browser_download_url")
        # Pure-python wheels are always compatible
        if "py3-none-any" in name or "none-any" in name:
            fallback_url = url
            continue
        # Check platform-specific compatibility
        for tag in compatible_tags:
            if tag in name:
                return url
    return fallback_url
