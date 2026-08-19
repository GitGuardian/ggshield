import os
import time
from pathlib import Path
from typing import Any, List
from unittest.mock import MagicMock, patch

import pytest
from pygitguardian.models import AIDiscovery, Detail, MCPServer, UserInfo

from ggshield.core.errors import UnexpectedError
from ggshield.verticals.ai.discovery import (
    _merge_mcp_configurations,
    discover_ai_configuration,
    refresh_and_maybe_submit_discovery,
    submit_ai_discovery,
)
from ggshield.verticals.ai.models import MCPConfiguration, Scope, Transport


def _user(**kwargs: Any) -> UserInfo:
    defaults = dict(
        hostname="host", username="user", machine_id="mid", user_email="u@e.com"
    )
    return UserInfo.from_dict(defaults | kwargs)


def _cfg(
    name: str = "srv", agent: str = "cursor", scope: Scope = Scope.USER
) -> MCPConfiguration:
    return MCPConfiguration(
        name=name, agent=agent, scope=scope, transport=Transport.STDIO
    )


def _discovery(
    user: UserInfo = _user(),
    servers: List[MCPServer] = [],
    discovery_duration: float = 0.1,
) -> AIDiscovery:
    return AIDiscovery(
        user=user, servers=servers, discovery_duration=discovery_duration
    )


# ---------------------------------------------------------------------------
# _merge_mcp_configurations
# ---------------------------------------------------------------------------


class TestMergeMcpConfigurations:
    def test_different_names_produce_separate_servers(self):
        configs = [_cfg(name="a"), _cfg(name="b")]
        servers = _merge_mcp_configurations(configs)
        assert len(servers) == 2
        names = {s.name for s in servers}
        assert names == {"a", "b"}

    def test_same_name_merged_under_one_server(self):
        configs = [_cfg(name="x", agent="cursor"), _cfg(name="x", agent="claude-code")]
        servers = _merge_mcp_configurations(configs)
        assert len(servers) == 1
        assert len(servers[0].configurations) == 2

    def test_empty_list_returns_empty(self):
        assert _merge_mcp_configurations([]) == []


# ---------------------------------------------------------------------------
# discover_ai_configuration
# ---------------------------------------------------------------------------


class TestDiscoverAIConfiguration:
    @patch(
        "ggshield.verticals.ai.discovery.are_hooks_installed_globally",
        return_value=(False, None),
    )
    @patch("ggshield.verticals.ai.discovery.get_user_info", return_value=_user())
    @patch("ggshield.verticals.ai.discovery.AGENTS")
    def test_aggregates_agents(
        self,
        mock_agents: MagicMock,
        mock_user_info: MagicMock,
        mock_hooks: MagicMock,
        tmp_path: Path,
    ):
        agent1 = MagicMock()
        agent1.discover_project_directories.return_value = iter([tmp_path / "p1"])
        agent1.discover_mcp_configurations.return_value = [_cfg(name="s1")]
        agent1.discover_capabilities.return_value = False

        agent2 = MagicMock()
        agent2.discover_project_directories.return_value = iter([])
        agent2.discover_mcp_configurations.return_value = [_cfg(name="s2")]
        agent2.discover_capabilities.return_value = False

        mock_agents.values.return_value = [agent1, agent2]

        result = discover_ai_configuration()

        assert result.user == _user()
        assert len(result.servers) == 2
        assert result.discovery_duration > 0

    @patch("ggshield.verticals.ai.discovery.are_hooks_installed_globally")
    @patch("ggshield.verticals.ai.discovery.get_user_info", return_value=_user())
    @patch("ggshield.verticals.ai.discovery.AGENTS")
    def test_reports_present_agents_hook_status(
        self,
        mock_agents: MagicMock,
        mock_user_info: MagicMock,
        mock_hooks: MagicMock,
    ):
        # Present agent, hooks installed
        agent1 = MagicMock()
        agent1.name = "cursor"
        agent1.discover_project_directories.return_value = iter([])
        agent1.discover_mcp_configurations.return_value = []
        agent1.discover_capabilities.return_value = False
        agent1.is_present.return_value = True

        # Not present: must not appear in the agents list
        agent2 = MagicMock()
        agent2.name = "claude-code"
        agent2.discover_project_directories.return_value = iter([])
        agent2.discover_mcp_configurations.return_value = []
        agent2.discover_capabilities.return_value = False
        agent2.is_present.return_value = False

        mock_agents.values.return_value = [agent1, agent2]
        mock_hooks.side_effect = lambda name: {
            "cursor": (True, "ggshield secret scan ai-hook"),
        }.get(name, (False, None))

        result = discover_ai_configuration()

        assert [
            (a.name, a.hooks_installed, a.hooks_command) for a in result.agents
        ] == [("cursor", True, "ggshield secret scan ai-hook")]

    @patch(
        "ggshield.verticals.ai.discovery.are_hooks_installed_globally",
        return_value=(False, None),
    )
    @patch("ggshield.verticals.ai.discovery.get_user_info", return_value=_user())
    @patch("ggshield.verticals.ai.discovery.AGENTS")
    def test_ignores_the_configurations_of_absent_agents(
        self,
        mock_agents: MagicMock,
        mock_user_info: MagicMock,
        mock_hooks: MagicMock,
    ):
        present = MagicMock()
        present.name = "cursor"
        present.is_present.return_value = True
        present.discover_project_directories.return_value = iter([])
        present.discover_mcp_configurations.return_value = [_cfg(name="s1")]
        present.discover_capabilities.return_value = False

        # Absent agents also parse the configuration files they recognize, and
        # some of them report a hardcoded server. None of it must be reported.
        absent = MagicMock()
        absent.name = "copilot"
        absent.is_present.return_value = False
        absent.discover_project_directories.return_value = iter([])
        absent.discover_mcp_configurations.return_value = [
            _cfg(name="s1", agent="copilot"),
            _cfg(name="github-mcp-server", agent="copilot"),
        ]
        absent.discover_capabilities.return_value = False

        mock_agents.values.return_value = [present, absent]

        result = discover_ai_configuration()

        absent.discover_mcp_configurations.assert_not_called()
        assert [s.name for s in result.servers] == ["s1"]
        assert {
            configuration.agent
            for server in result.servers
            for configuration in server.configurations
        } == {"cursor"}

    @patch(
        "ggshield.verticals.ai.discovery.are_hooks_installed_globally",
        return_value=(False, None),
    )
    @patch("ggshield.verticals.ai.discovery.get_user_info", return_value=_user())
    @patch("ggshield.verticals.ai.discovery.AGENTS")
    def test_stops_capability_discovery_at_first_success(
        self,
        mock_agents: MagicMock,
        mock_user_info: MagicMock,
        mock_hooks: MagicMock,
    ):
        agent1 = MagicMock()
        agent1.discover_project_directories.return_value = iter([])
        agent1.discover_mcp_configurations.return_value = [_cfg(name="s")]
        agent1.discover_capabilities.return_value = True

        agent2 = MagicMock()
        agent2.discover_project_directories.return_value = iter([])
        agent2.discover_mcp_configurations.return_value = []
        agent2.discover_capabilities.return_value = False

        mock_agents.values.return_value = [agent1, agent2]

        discover_ai_configuration()

        agent1.discover_capabilities.assert_called_once()
        agent2.discover_capabilities.assert_not_called()


# ---------------------------------------------------------------------------
# submit_ai_discovery
# ---------------------------------------------------------------------------


class TestSubmitAIDiscovery:
    def test_successful_response(self):
        discovery = _discovery()
        client = MagicMock()
        client.send_ai_discovery.return_value = discovery

        result = submit_ai_discovery(client, discovery)
        assert result.user == discovery.user

    def test_non_200_raises(self):
        discovery = _discovery()
        client = MagicMock()
        client.send_ai_discovery.return_value = Detail(
            status_code=500, detail="Internal Server Error"
        )

        with pytest.raises(UnexpectedError):
            submit_ai_discovery(client, discovery)


# ---------------------------------------------------------------------------
# refresh_and_maybe_submit_discovery
# ---------------------------------------------------------------------------


class TestRefreshAndMaybeSubmitDiscovery:
    @pytest.fixture(autouse=True)
    def cache_ttl(self):
        """Expired TTL by default, so tests exercise the filesystem discovery path.

        Yields the two TTL mocks so a test can make the cache fresh instead.
        """
        with (
            patch(
                "ggshield.verticals.ai.discovery.is_discovery_cache_fresh",
                return_value=False,
            ) as m_fresh,
            patch(
                "ggshield.verticals.ai.discovery.touch_discovery_cache",
            ) as m_touch,
        ):
            yield m_fresh, m_touch

    def _patch_all(self):
        return (
            patch(
                "ggshield.verticals.ai.discovery.load_discovery_cache",
            ),
            patch(
                "ggshield.verticals.ai.discovery.discover_ai_configuration",
            ),
            patch(
                "ggshield.verticals.ai.discovery.submit_ai_discovery",
            ),
            patch(
                "ggshield.verticals.ai.discovery.save_discovery_cache",
            ),
        )

    def test_no_cache_submits_and_saves(self):
        p_load, p_discover, p_submit, p_save = self._patch_all()
        with (
            p_load as m_load,
            p_discover as m_discover,
            p_submit as m_submit,
            p_save as m_save,
        ):
            m_load.return_value = None
            new_disc = _discovery()
            m_discover.return_value = new_disc
            submitted = _discovery(discovery_duration=0.5)
            m_submit.return_value = submitted

            result = refresh_and_maybe_submit_discovery(MagicMock())

            m_submit.assert_called_once()
            m_save.assert_called_once_with(submitted)
            assert result == submitted

    def test_unchanged_returns_cache_without_submission(self):
        cached = _discovery()
        p_load, p_discover, p_submit, p_save = self._patch_all()
        with (
            p_load as m_load,
            p_discover as m_discover,
            p_submit as m_submit,
            p_save as m_save,
        ):
            m_load.return_value = cached
            m_discover.return_value = cached  # identical discovery

            result = refresh_and_maybe_submit_discovery(MagicMock())

            m_submit.assert_not_called()
            m_save.assert_not_called()
            assert result == cached

    def test_changed_submits_and_saves(self):
        cached = _discovery(user=_user(hostname="old"))
        new_disc = _discovery(user=_user(hostname="new"))
        p_load, p_discover, p_submit, p_save = self._patch_all()
        with (
            p_load as m_load,
            p_discover as m_discover,
            p_submit as m_submit,
            p_save as m_save,
        ):
            m_load.return_value = cached
            m_discover.return_value = new_disc
            m_submit.return_value = new_disc

            refresh_and_maybe_submit_discovery(MagicMock())

            m_submit.assert_called_once()
            m_save.assert_called_once()

    def test_api_error_swallowed(self):
        p_load, p_discover, p_submit, p_save = self._patch_all()
        with (
            p_load as m_load,
            p_discover as m_discover,
            p_submit as m_submit,
            p_save as m_save,
        ):
            m_load.return_value = None
            new_disc = _discovery()
            m_discover.return_value = new_disc
            m_submit.side_effect = RuntimeError("network")

            result = refresh_and_maybe_submit_discovery(MagicMock())

            assert result == new_disc
            m_save.assert_not_called()

    def test_fresh_cache_skips_the_filesystem_walk(self, cache_ttl):
        """Within the TTL, the cached discovery is returned without re-walking."""
        m_fresh, _ = cache_ttl
        m_fresh.return_value = True
        cached = _discovery()
        p_load, p_discover, p_submit, p_save = self._patch_all()
        with (
            p_load as m_load,
            p_discover as m_discover,
            p_submit as m_submit,
            p_save as m_save,
        ):
            m_load.return_value = cached

            result = refresh_and_maybe_submit_discovery(MagicMock())

            m_discover.assert_not_called()
            m_submit.assert_not_called()
            m_save.assert_not_called()
            assert result == cached

    def test_fresh_but_unreadable_cache_still_walks(self, cache_ttl):
        """A recent but corrupt cache file must not short-circuit discovery."""
        m_fresh, _ = cache_ttl
        m_fresh.return_value = True
        p_load, p_discover, p_submit, p_save = self._patch_all()
        with (
            p_load as m_load,
            p_discover as m_discover,
            p_submit as m_submit,
            p_save as m_save,
        ):
            m_load.return_value = None  # unparseable cache
            m_discover.return_value = _discovery()
            m_submit.return_value = _discovery()

            refresh_and_maybe_submit_discovery(MagicMock())

            m_discover.assert_called_once()
            m_submit.assert_called_once()
            m_save.assert_called_once()

    def test_expired_ttl_walks_again_and_resets_the_ttl(self, cache_ttl):
        """Past the TTL we re-walk; if nothing changed we reset the TTL instead of
        re-walking on every subsequent call."""
        _, m_touch = cache_ttl
        cached = _discovery()
        p_load, p_discover, p_submit, p_save = self._patch_all()
        with (
            p_load as m_load,
            p_discover as m_discover,
            p_submit as m_submit,
            p_save as m_save,
        ):
            m_load.return_value = cached
            m_discover.return_value = cached

            result = refresh_and_maybe_submit_discovery(MagicMock())

            m_discover.assert_called_once()
            m_touch.assert_called_once()
            m_submit.assert_not_called()
            m_save.assert_not_called()
            assert result == cached

    def test_expired_ttl_with_changed_configuration_still_submits(self, cache_ttl):
        """The TTL must not swallow a real configuration change."""
        _, m_touch = cache_ttl
        cached = _discovery(user=_user(hostname="old"))
        new_disc = _discovery(user=_user(hostname="new"))
        p_load, p_discover, p_submit, p_save = self._patch_all()
        with (
            p_load as m_load,
            p_discover as m_discover,
            p_submit as m_submit,
            p_save as m_save,
        ):
            m_load.return_value = cached
            m_discover.return_value = new_disc
            m_submit.return_value = new_disc

            refresh_and_maybe_submit_discovery(MagicMock())

            m_submit.assert_called_once()
            m_save.assert_called_once()
            # save_discovery_cache already refreshes the file mtime.
            m_touch.assert_not_called()

    def test_reuses_machine_id_from_cache(self):
        cached = _discovery(user=_user(machine_id="cached-id"))
        p_load, p_discover = self._patch_all()[:2]
        with (
            p_load as m_load,
            p_discover as m_discover,
        ):
            m_load.return_value = cached
            m_discover.return_value = cached

            refresh_and_maybe_submit_discovery(MagicMock())

            _, kwargs = m_discover.call_args
            assert kwargs.get("machine_id") == "cached-id"


# ---------------------------------------------------------------------------
# refresh_and_maybe_submit_discovery, against the real on-disk cache
# ---------------------------------------------------------------------------


class TestRefreshAgainstRealCache:
    """The tests above mock the cache away, so they cannot see whether a
    discovery that really went through it still compares equal."""

    @staticmethod
    def _age_cache(tmp_path: Path) -> None:
        """Backdate the cache file, so that a freshness short-circuit around the
        walk cannot be what keeps the submission from happening."""
        cache_file = tmp_path / "ai_discovery.json"
        mtime = time.time() - 24 * 3600
        os.utime(cache_file, (mtime, mtime))

    def test_submits_once_then_stays_quiet(self, tmp_path: Path):
        discovery = AIDiscovery(
            user=_user(),
            servers=_merge_mcp_configurations(
                [
                    MCPConfiguration(
                        name="srv",
                        agent="cursor",
                        scope=Scope.USER,
                        transport=Transport.STDIO,
                        command="run",
                        display_name="Pretty Server",
                    )
                ]
            ),
            discovery_duration=0.1,
        )
        with (
            patch("ggshield.verticals.ai.cache.get_cache_dir", return_value=tmp_path),
            patch(
                "ggshield.verticals.ai.discovery.discover_ai_configuration",
                return_value=discovery,
            ),
            patch(
                "ggshield.verticals.ai.discovery.submit_ai_discovery",
                # The API answers with its own, plain pygitguardian objects.
                side_effect=lambda client, sent: AIDiscovery.from_dict(sent.to_dict()),
            ) as m_submit,
        ):
            refresh_and_maybe_submit_discovery(MagicMock())
            assert m_submit.call_count == 1, "cold cache must submit"

            for _ in range(2):
                self._age_cache(tmp_path)
                refresh_and_maybe_submit_discovery(MagicMock())
            assert m_submit.call_count == 1, "unchanged configuration must not submit"
