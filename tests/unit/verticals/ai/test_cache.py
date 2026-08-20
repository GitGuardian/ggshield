import json
import os
import stat
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import patch
from uuid import UUID

import pytest
from pygitguardian.models import (
    AgentInfo,
    AIDiscovery,
    MCPConfiguration,
    MCPPromptInfo,
    MCPResourceInfo,
    MCPToolInfo,
    UserInfo,
)

from ggshield.core.config.user_config import SecretConfig
from ggshield.verticals.ai.cache import (
    DISCOVERY_CACHE_TTL_SECONDS,
    VERDICT_CACHE_MAX_ENTRIES,
    VERDICT_CACHE_TTL_SECONDS,
    _server_has_capabilities_unknown_to,
    _verdict_cache_path,
    has_changed_from,
    has_clean_verdict,
    is_discovery_cache_fresh,
    load_discovery_cache,
    save_discovery_cache,
    store_clean_verdict,
    touch_discovery_cache,
    verdict_key,
)
from ggshield.verticals.ai.discovery import _merge_mcp_configurations
from ggshield.verticals.ai.models import MCPConfiguration as LocalMCPConfiguration
from ggshield.verticals.ai.models import MCPServer, Scope, Transport
from tests.conftest import skipwindows


def _user(**kwargs: Any) -> UserInfo:
    defaults = dict(
        hostname="host", username="user", machine_id="mid", user_email="u@e.com"
    )
    return UserInfo(**(defaults | kwargs))


def _server(
    name: str = "srv",
    tools: Optional[List[MCPToolInfo]] = None,
    resources: Optional[List[MCPResourceInfo]] = None,
    prompts: Optional[List[MCPPromptInfo]] = None,
    configurations: Optional[List[MCPConfiguration]] = None,
) -> MCPServer:
    return MCPServer(
        name=name,
        tools=tools or [],
        resources=resources or [],
        prompts=prompts or [],
        configurations=configurations or [],
    )


def _cfg(
    name: str = "srv",
    agent: str = "cursor",
    scope: Scope = Scope.USER,
    project: Optional[str] = None,
) -> MCPConfiguration:
    return MCPConfiguration(
        name=name,
        agent=agent,
        scope=scope,
        transport=Transport.STDIO,
        project=project,
    )


# ---------------------------------------------------------------------------
# MCPServer.has_capabilities_unknown_to
# ---------------------------------------------------------------------------


class TestMCPServerHasCapabilitiesUnknownTo:
    @pytest.mark.parametrize(
        "self_kwargs, other_kwargs, expected",
        [
            pytest.param(
                {"tools": [MCPToolInfo(name="t1")]},
                {"tools": [MCPToolInfo(name="t1")]},
                False,
                id="same_tools",
            ),
            pytest.param(
                {"tools": [MCPToolInfo(name="t1"), MCPToolInfo(name="t2")]},
                {"tools": [MCPToolInfo(name="t1")]},
                True,
                id="extra_tool",
            ),
            pytest.param(
                {"resources": [MCPResourceInfo(uri="r1"), MCPResourceInfo(uri="r2")]},
                {"resources": [MCPResourceInfo(uri="r1")]},
                True,
                id="extra_resource",
            ),
            pytest.param(
                {"prompts": [MCPPromptInfo(name="p1"), MCPPromptInfo(name="p2")]},
                {"prompts": [MCPPromptInfo(name="p1")]},
                True,
                id="extra_prompt",
            ),
            pytest.param(
                {"tools": [MCPToolInfo(name="t1")]},
                {"tools": [MCPToolInfo(name="t1"), MCPToolInfo(name="t2")]},
                False,
                id="subset_of_other",
            ),
            pytest.param({}, {}, False, id="both_empty"),
        ],
    )
    def test_has_capabilities_unknown_to(
        self, self_kwargs: Dict[str, Any], other_kwargs: Dict[str, Any], expected: bool
    ):
        assert (
            _server_has_capabilities_unknown_to(
                _server(**self_kwargs), _server(**other_kwargs)
            )
            is expected
        )


# ---------------------------------------------------------------------------
# AIDiscovery.has_changed_from
# ---------------------------------------------------------------------------


class TestAIDiscoveryHasChangedFrom:
    def test_identical_returns_false(self):
        cfg = _cfg()
        a = AIDiscovery(
            user=_user(),
            servers=[_server(configurations=[cfg])],
            discovery_duration=0.1,
        )
        b = AIDiscovery(
            user=_user(),
            servers=[_server(configurations=[cfg])],
            discovery_duration=0.2,
        )
        assert has_changed_from(a, b) is False

    def test_different_user_returns_true(self):
        cfg = _cfg()
        a = AIDiscovery(
            user=_user(hostname="a"),
            servers=[_server(configurations=[cfg])],
            discovery_duration=0.1,
        )
        b = AIDiscovery(
            user=_user(hostname="b"),
            servers=[_server(configurations=[cfg])],
            discovery_duration=0.1,
        )
        assert has_changed_from(a, b) is True

    def test_different_configuration_keys_returns_true(self):
        a = AIDiscovery(
            user=_user(),
            servers=[_server(configurations=[_cfg(name="x")])],
            discovery_duration=0.1,
        )
        b = AIDiscovery(
            user=_user(),
            servers=[_server(configurations=[_cfg(name="y")])],
            discovery_duration=0.1,
        )
        assert has_changed_from(a, b) is True

    def test_new_capabilities_unknown_to_all_candidates_returns_true(self):
        cfg = _cfg()
        a = AIDiscovery(
            user=_user(),
            servers=[
                _server(
                    configurations=[cfg],
                    tools=[MCPToolInfo(name="new_tool")],
                )
            ],
            discovery_duration=0.1,
        )
        b = AIDiscovery(
            user=_user(),
            servers=[_server(configurations=[cfg])],
            discovery_duration=0.1,
        )
        assert has_changed_from(a, b) is True

    def test_capabilities_known_to_one_candidate_returns_false(self):
        cfg = _cfg()
        tool = MCPToolInfo(name="known")
        a = AIDiscovery(
            user=_user(),
            servers=[_server(configurations=[cfg], tools=[tool])],
            discovery_duration=0.1,
        )
        b = AIDiscovery(
            user=_user(),
            servers=[_server(configurations=[cfg], tools=[tool])],
            discovery_duration=0.1,
        )
        assert has_changed_from(a, b) is False

    def test_empty_servers_returns_false(self):
        a = AIDiscovery(user=_user(), servers=[], discovery_duration=0.1)
        b = AIDiscovery(user=_user(), servers=[], discovery_duration=0.1)
        assert has_changed_from(a, b) is False

    def test_changed_hook_installation_returns_true(self):
        cfg = _cfg()
        a = AIDiscovery(
            user=_user(),
            servers=[_server(configurations=[cfg])],
            agents=[AgentInfo(name="cursor", hooks_installed=True)],
            discovery_duration=0.1,
        )
        b = AIDiscovery(
            user=_user(),
            servers=[_server(configurations=[cfg])],
            agents=[AgentInfo(name="cursor", hooks_installed=False)],
            discovery_duration=0.1,
        )
        assert has_changed_from(a, b) is True

    def test_same_hook_installation_returns_false(self):
        cfg = _cfg()
        agents = [AgentInfo(name="cursor", hooks_installed=True)]
        a = AIDiscovery(
            user=_user(),
            servers=[_server(configurations=[cfg])],
            agents=agents,
            discovery_duration=0.1,
        )
        b = AIDiscovery(
            user=_user(),
            servers=[_server(configurations=[cfg])],
            agents=list(agents),
            discovery_duration=0.2,
        )
        assert has_changed_from(a, b) is False


# ---------------------------------------------------------------------------
# Change detection against a discovery that really went through the cache
# ---------------------------------------------------------------------------


def _local_cfg(
    name: str = "srv",
    agent: str = "cursor",
    scope: Scope = Scope.USER,
    project: Optional[str] = None,
    command: Optional[str] = "run",
    args: Optional[List[str]] = None,
    display_name: Optional[str] = "Pretty Server",
) -> LocalMCPConfiguration:
    """A configuration exactly as `discover_ai_configuration` builds it."""
    return LocalMCPConfiguration(
        name=name,
        agent=agent,
        scope=scope,
        transport=Transport.STDIO,
        project=project,
        command=command,
        args=args or [],
        display_name=display_name,
    )


def _local_discovery(
    configurations: List[LocalMCPConfiguration],
    user: Optional[UserInfo] = None,
    agents: Optional[List[AgentInfo]] = None,
) -> AIDiscovery:
    return AIDiscovery(
        user=user or _user(),
        servers=_merge_mcp_configurations(configurations),
        agents=(
            agents
            if agents is not None
            else [AgentInfo(name="cursor", hooks_installed=True)]
        ),
        discovery_duration=0.1,
    )


def _through_cache(discovery: AIDiscovery, tmp_path: Path) -> AIDiscovery:
    with patch("ggshield.verticals.ai.cache.get_cache_dir", return_value=tmp_path):
        save_discovery_cache(discovery)
        loaded = load_discovery_cache()
    assert loaded is not None
    return loaded


class TestHasChangedFromThroughCache:
    """A freshly walked discovery holds `ggshield` MCPConfiguration instances, a
    cached one holds `pygitguardian` ones. Change detection must see through that."""

    def test_same_configuration_is_not_a_change(self, tmp_path: Path):
        discovery = _local_discovery([_local_cfg()])
        assert has_changed_from(discovery, _through_cache(discovery, tmp_path)) is False

    def test_added_server_is_a_change(self, tmp_path: Path):
        cached = _through_cache(_local_discovery([_local_cfg(name="a")]), tmp_path)
        current = _local_discovery([_local_cfg(name="a"), _local_cfg(name="b")])
        assert has_changed_from(current, cached) is True

    def test_removed_server_is_a_change(self, tmp_path: Path):
        cached = _through_cache(
            _local_discovery([_local_cfg(name="a"), _local_cfg(name="b")]), tmp_path
        )
        current = _local_discovery([_local_cfg(name="a")])
        assert has_changed_from(current, cached) is True

    def test_changed_configuration_content_is_a_change(self, tmp_path: Path):
        cached = _through_cache(
            _local_discovery([_local_cfg(command="old", args=["--x"])]), tmp_path
        )
        current = _local_discovery([_local_cfg(command="new", args=["--x"])])
        assert has_changed_from(current, cached) is True

    def test_changed_user_is_a_change(self, tmp_path: Path):
        cached = _through_cache(
            _local_discovery([_local_cfg()], user=_user(hostname="old")), tmp_path
        )
        current = _local_discovery([_local_cfg()], user=_user(hostname="new"))
        assert has_changed_from(current, cached) is True

    def test_changed_agents_is_a_change(self, tmp_path: Path):
        cached = _through_cache(
            _local_discovery(
                [_local_cfg()],
                agents=[AgentInfo(name="cursor", hooks_installed=False)],
            ),
            tmp_path,
        )
        current = _local_discovery(
            [_local_cfg()], agents=[AgentInfo(name="cursor", hooks_installed=True)]
        )
        assert has_changed_from(current, cached) is True

    def test_display_name_only_change_is_not_a_change(self, tmp_path: Path):
        """`display_name` is local, so it cannot round trip and must not submit."""
        cached = _through_cache(
            _local_discovery([_local_cfg(display_name="Old")]), tmp_path
        )
        current = _local_discovery([_local_cfg(display_name="New")])
        assert has_changed_from(current, cached) is False


# ---------------------------------------------------------------------------
# load / save discovery cache
# ---------------------------------------------------------------------------


class TestLoadSaveDiscoveryCache:
    def test_round_trip(self, tmp_path: Path):
        discovery = AIDiscovery(user=_user(), servers=[], discovery_duration=0.1)
        with patch("ggshield.verticals.ai.cache.get_cache_dir", return_value=tmp_path):
            save_discovery_cache(discovery)
            loaded = load_discovery_cache()
        assert loaded is not None
        assert loaded.user == discovery.user

    def test_load_returns_none_when_missing(self, tmp_path: Path):
        with patch("ggshield.verticals.ai.cache.get_cache_dir", return_value=tmp_path):
            assert load_discovery_cache() is None

    def test_load_returns_none_on_valid_json_bad_schema(self, tmp_path: Path):
        """Valid JSON that doesn't match AIDiscovery schema."""
        cache_file = tmp_path / "ai_discovery.json"
        cache_file.write_text('{"foo": "bar"}')
        with patch("ggshield.verticals.ai.cache.get_cache_dir", return_value=tmp_path):
            assert load_discovery_cache() is None

    def test_load_returns_none_on_invalid_json(self, tmp_path: Path):
        """Valid JSON that doesn't match AIDiscovery schema."""
        cache_file = tmp_path / "ai_discovery.json"
        cache_file.write_text("not json")
        with patch("ggshield.verticals.ai.cache.get_cache_dir", return_value=tmp_path):
            assert load_discovery_cache() is None

    def test_load_returns_none_on_oserror(self, tmp_path: Path):
        with patch("ggshield.verticals.ai.cache.get_cache_dir", return_value=tmp_path):
            cache_file = tmp_path / "ai_discovery.json"
            cache_file.mkdir()  # directory instead of file triggers OSError
            assert load_discovery_cache() is None


class TestVerdictKey:
    """The key must cover everything the API's answer depends on."""

    ARGS = ("https://api.example.com", "token", SecretConfig(), "file.py", "content")

    @staticmethod
    def _key(**config_kwargs: Any) -> str:
        return verdict_key(
            "https://api.example.com",
            "token",
            SecretConfig(**config_kwargs),
            "file.py",
            "content",
        )

    # Index 2 is the config, covered by its own tests below.
    @pytest.mark.parametrize("index", [0, 1, 3, 4])
    def test_every_part_changes_the_key(self, index: int):
        """GIVEN two keys differing in one part only THEN they differ."""
        other = list(self.ARGS)
        other[index] += "-x"
        assert verdict_key(*self.ARGS) != verdict_key(*other)

    def test_parts_cannot_be_shifted_across_the_separator(self):
        """A longer instance must not be able to impersonate another key."""
        config = SecretConfig()
        assert verdict_key("a", "b", config, "c", "d") != verdict_key(
            "a\0b", "c", config, "d", ""
        )

    def test_unencodable_content_still_yields_distinct_keys(self):
        """Lone surrogates (reachable from a JSON payload) must not collide."""
        config = SecretConfig()
        assert verdict_key("i", "k", config, "f", "\ud800") != verdict_key(
            "i", "k", config, "f", "\ud801"
        )

    def test_same_config_yields_the_same_key(self):
        """Two equivalent configs must still hit, otherwise the cache is dead."""
        assert self._key() == self._key()

    @pytest.mark.parametrize(
        "config_kwargs",
        [
            # Rewrites the filename we send.
            {"filename_only": True},
            # Changes which policy breaks land in `secrets`.
            {"all_secrets": True},
            # Switches the endpoint to scan_and_create_incidents.
            {"source_uuid": UUID("11111111-1111-1111-1111-111111111111")},
        ],
    )
    def test_request_shaping_settings_change_the_key(self, config_kwargs: Any):
        """A setting that changes the request, or how we read the answer, must not
        serve a verdict recorded under its other value."""
        assert self._key() != self._key(**config_kwargs)

    @pytest.mark.parametrize(
        "config_kwargs",
        [
            # Presentation only.
            {"show_secrets": True},
            # A verdict that depended on it is never stored in the first place,
            # see AIHookScanner._scan_content.
            {"ignore_known_secrets": True},
        ],
    )
    def test_unrelated_settings_do_not_change_the_key(self, config_kwargs: Any):
        """Settings that cannot make a verdict stale must not cost a cache miss."""
        assert self._key() == self._key(**config_kwargs)


class TestVerdictCache:
    """Unit tests for the AI hook clean-verdict cache. Keys are opaque strings
    here; what goes into them is TestVerdictKey's business.

    The autouse do_not_use_real_user_dirs fixture already points get_cache_dir()
    at a per-test temporary directory.
    """

    def test_store_then_hit(self):
        """GIVEN a stored clean verdict WHEN the same content is looked up THEN it hits."""
        store_clean_verdict("some content")
        assert has_clean_verdict("some content") is True

    def test_miss_on_different_content(self):
        """GIVEN a stored verdict WHEN other content is looked up THEN it misses."""
        store_clean_verdict("some content")
        assert has_clean_verdict("other content") is False

    def test_miss_on_empty_cache(self):
        """GIVEN no cache file WHEN content is looked up THEN it misses."""
        assert not _verdict_cache_path().exists()
        assert has_clean_verdict("some content") is False

    def test_miss_once_expired(self):
        """GIVEN a verdict older than the TTL WHEN looked up THEN it misses."""
        store_clean_verdict("some content")
        with patch(
            "ggshield.verticals.ai.cache.time.time",
            return_value=time.time() + VERDICT_CACHE_TTL_SECONDS + 1,
        ):
            assert has_clean_verdict("some content") is False

    def test_miss_on_timestamp_in_the_future(self):
        """A forged far-future timestamp must not become a never-expiring hit."""
        self._write_cache({"some content": time.time() + 10_000})
        assert has_clean_verdict("some content") is False

    def test_miss_on_corrupted_json(self):
        """GIVEN a cache file that is not valid JSON WHEN read THEN it is treated as empty."""
        self._write_cache_text("{not json")
        assert has_clean_verdict("some content") is False

    def test_miss_on_json_that_is_not_an_object(self):
        """A JSON array where a mapping is expected is treated as empty."""
        self._write_cache_text('["nope"]')
        assert has_clean_verdict("some content") is False

    @skipwindows
    def test_poisoned_world_writable_cache_is_ignored(self):
        """A cache anyone can write is a bypass oracle: refuse to read it."""
        store_clean_verdict("some content")
        assert has_clean_verdict("some content") is True
        _verdict_cache_path().chmod(0o666)
        assert has_clean_verdict("some content") is False

    @skipwindows
    def test_group_writable_cache_is_ignored(self):
        """Same for a group-writable cache."""
        store_clean_verdict("some content")
        _verdict_cache_path().chmod(0o660)
        assert has_clean_verdict("some content") is False

    @skipwindows
    def test_cache_owned_by_another_user_is_ignored(self):
        """0600 is only trustworthy if we are the owner: a file somebody else
        dropped in a writable cache dir must not be believed."""
        store_clean_verdict("some content")
        with patch("ggshield.verticals.ai.cache.os.getuid", return_value=-1):
            assert has_clean_verdict("some content") is False

    @skipwindows
    def test_stored_cache_file_is_private(self):
        """The cache file must be created 0600."""
        store_clean_verdict("some content")
        assert stat.S_IMODE(_verdict_cache_path().stat().st_mode) == 0o600

    @skipwindows
    def test_writing_repairs_a_loose_permission_cache_file(self):
        """A file we refuse to read must not disable the cache for good."""
        store_clean_verdict("some content")
        _verdict_cache_path().chmod(0o666)
        store_clean_verdict("other content")
        assert stat.S_IMODE(_verdict_cache_path().stat().st_mode) == 0o600
        assert has_clean_verdict("other content") is True
        # The verdicts of the untrusted file were dropped, not carried over.
        assert has_clean_verdict("some content") is False

    @skipwindows
    def test_symlinked_cache_is_ignored(self):
        """A symlink at the cache path is not a cache file we wrote."""
        path = _verdict_cache_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        target = path.parent / "elsewhere.json"
        target.write_text(json.dumps({"some content": time.time()}))
        path.symlink_to(target)
        assert has_clean_verdict("some content") is False

    def test_entry_count_is_bounded(self):
        """GIVEN more verdicts than the cap WHEN stored THEN only the newest are kept."""
        for i in range(VERDICT_CACHE_MAX_ENTRIES + 10):
            store_clean_verdict(f"content {i}")
        stored = json.loads(_verdict_cache_path().read_text())
        assert len(stored) == VERDICT_CACHE_MAX_ENTRIES
        assert has_clean_verdict(f"content {VERDICT_CACHE_MAX_ENTRIES + 9}") is True

    def test_expired_entries_are_dropped_on_write(self):
        """Storing a verdict purges entries that have expired."""
        store_clean_verdict("old content")
        with patch(
            "ggshield.verticals.ai.cache.time.time",
            return_value=time.time() + VERDICT_CACHE_TTL_SECONDS + 1,
        ):
            store_clean_verdict("new content")
        assert list(json.loads(_verdict_cache_path().read_text())) == ["new content"]

    def test_store_never_raises_when_the_cache_dir_is_unusable(self):
        """A cache failure must never propagate: the hook would rather scan."""
        with patch(
            "ggshield.verticals.ai.cache.get_cache_dir",
            return_value=Path(__file__) / "not-a-dir",
        ):
            store_clean_verdict("some content")
            assert has_clean_verdict("some content") is False

    @staticmethod
    def _write_cache(payload: Dict[str, float]) -> None:
        TestVerdictCache._write_cache_text(json.dumps(payload))

    @staticmethod
    def _write_cache_text(text: str) -> None:
        path = _verdict_cache_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        # Keep the file trustworthy so these tests exercise the content checks
        # and not the permission check.
        path.chmod(0o600)


class TestDiscoveryCacheTTL:
    def _age(self, tmp_path: Path, seconds: float) -> Path:
        cache_file = tmp_path / "ai_discovery.json"
        cache_file.write_text("{}")
        mtime = time.time() - seconds
        os.utime(cache_file, (mtime, mtime))
        return cache_file

    def test_not_fresh_when_missing(self, tmp_path: Path):
        with patch("ggshield.verticals.ai.cache.get_cache_dir", return_value=tmp_path):
            assert is_discovery_cache_fresh() is False

    def test_fresh_within_ttl(self, tmp_path: Path):
        self._age(tmp_path, DISCOVERY_CACHE_TTL_SECONDS / 2)
        with patch("ggshield.verticals.ai.cache.get_cache_dir", return_value=tmp_path):
            assert is_discovery_cache_fresh() is True

    def test_stale_past_ttl(self, tmp_path: Path):
        self._age(tmp_path, DISCOVERY_CACHE_TTL_SECONDS + 1)
        with patch("ggshield.verticals.ai.cache.get_cache_dir", return_value=tmp_path):
            assert is_discovery_cache_fresh() is False

    def test_stale_when_mtime_is_in_the_future(self, tmp_path: Path):
        """A clock jump must not pin the cache as fresh forever."""
        self._age(tmp_path, -DISCOVERY_CACHE_TTL_SECONDS)
        with patch("ggshield.verticals.ai.cache.get_cache_dir", return_value=tmp_path):
            assert is_discovery_cache_fresh() is False

    def test_fresh_when_mtime_is_barely_in_the_future(self, tmp_path: Path):
        """A just-touched file can read slightly ahead of time.time(): the two come
        from different clock sources. Small skew is fresh, not a clock jump."""
        self._age(tmp_path, -1)
        with patch("ggshield.verticals.ai.cache.get_cache_dir", return_value=tmp_path):
            assert is_discovery_cache_fresh() is True

    def test_touch_makes_a_stale_cache_fresh_again(self, tmp_path: Path):
        cache_file = self._age(tmp_path, DISCOVERY_CACHE_TTL_SECONDS + 1)
        content = cache_file.read_text()
        with patch("ggshield.verticals.ai.cache.get_cache_dir", return_value=tmp_path):
            touch_discovery_cache()
            assert is_discovery_cache_fresh() is True
        assert cache_file.read_text() == content
