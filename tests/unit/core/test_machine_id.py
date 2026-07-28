import os
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ggshield.core.machine_id import (
    _get_hostname,
    _get_linux_system_id,
    _get_machine_id,
    _get_macos_system_id,
    _get_username,
    _get_windows_system_id,
    _is_trusted_cache_owner,
    _normalize_uuid,
    _parse_wmic_uuid,
    _read_first_nonempty_line,
    _read_trusted_cache_line,
    _windows_binary,
    _write_machine_id_cache,
)


@pytest.fixture(autouse=True)
def clear_machine_id_caches():
    """Reset the lru_cache on cached helpers so each test sees its own mocks."""
    _get_username.cache_clear()
    _get_machine_id.cache_clear()
    yield


# ---------------------------------------------------------------------------
# _get_hostname
# ---------------------------------------------------------------------------


class TestGetHostname:
    @patch("ggshield.core.machine_id.sys")
    @patch("ggshield.core.machine_id.socket.gethostname", return_value="linuxbox")
    def test_linux_returns_gethostname(
        self, _mock_host: MagicMock, mock_sys: MagicMock
    ):
        mock_sys.platform = "linux"
        assert _get_hostname() == "linuxbox"

    @patch("ggshield.core.machine_id.sys")
    @patch("ggshield.core.machine_id.os.environ", {"COMPUTERNAME": "WINBOX"})
    def test_windows_prefers_computername(self, mock_sys: MagicMock):
        mock_sys.platform = "win32"
        assert _get_hostname() == "WINBOX"

    @patch("ggshield.core.machine_id.sys")
    @patch("ggshield.core.machine_id.socket.gethostname", side_effect=OSError)
    def test_oserror_returns_unknown(self, _mock_host: MagicMock, mock_sys: MagicMock):
        mock_sys.platform = "linux"
        assert _get_hostname() == "unknown"


# ---------------------------------------------------------------------------
# _get_username
# ---------------------------------------------------------------------------


class TestGetUsername:
    @patch("ggshield.core.machine_id.getpass.getuser", return_value="alice")
    def test_returns_getuser(self, _mock: MagicMock):
        assert _get_username() == "alice"

    @patch("ggshield.core.machine_id.os.getlogin", return_value="bob")
    @patch("ggshield.core.machine_id.getpass.getuser", side_effect=Exception)
    def test_falls_back_to_getlogin(self, *_mocks: MagicMock):
        assert _get_username() == "bob"

    @patch("ggshield.core.machine_id.os.getlogin", side_effect=Exception)
    @patch("ggshield.core.machine_id.getpass.getuser", side_effect=Exception)
    def test_returns_unknown_when_both_fail(self, *_mocks: MagicMock):
        assert _get_username() == "unknown"


# ---------------------------------------------------------------------------
# _get_machine_id
# ---------------------------------------------------------------------------


class TestGetMachineId:
    @patch("ggshield.core.machine_id.platform.system", return_value="Linux")
    @patch("ggshield.core.machine_id._get_linux_system_id", return_value=None)
    def test_uses_shared_cache_when_no_system_id(
        self, _mock_linux: MagicMock, _mock_platform: MagicMock, tmp_path: Path
    ):
        # No derivable hardware id → fall back to the shared ~/.ggshield cache
        # that both ggshield and satori read/write.
        ggshield_dir = tmp_path / ".ggshield"
        ggshield_dir.mkdir()
        cache = ggshield_dir / "machine_id"
        cache.write_text("cached-uuid\n")
        os.chmod(cache, 0o600)  # owner-only, so the trust gate accepts it
        with patch("ggshield.core.machine_id.get_user_home_dir", return_value=tmp_path):
            assert _get_machine_id() == "cached-uuid"

    @pytest.mark.skipif(os.name != "posix", reason="POSIX permission model")
    @patch("ggshield.core.machine_id.platform.system", return_value="Linux")
    @patch("ggshield.core.machine_id._get_linux_system_id", return_value=None)
    @patch("ggshield.core.machine_id.uuid.uuid4")
    def test_world_writable_cache_is_not_trusted(
        self,
        mock_uuid4: MagicMock,
        _mock_linux: MagicMock,
        _mock_platform: MagicMock,
        tmp_path: Path,
    ):
        # A world-writable cache could be pre-seeded by a local attacker → ignore
        # it and mint a fresh id instead of adopting the planted value.
        fixed_uuid = uuid.UUID("99999999-9999-9999-9999-999999999999")
        mock_uuid4.return_value = fixed_uuid
        ggshield_dir = tmp_path / ".ggshield"
        ggshield_dir.mkdir()
        cache = ggshield_dir / "machine_id"
        cache.write_text("attacker-planted-uuid\n")
        os.chmod(cache, 0o666)
        with patch("ggshield.core.machine_id.get_user_home_dir", return_value=tmp_path):
            assert _get_machine_id() == str(fixed_uuid)

    @patch("ggshield.core.machine_id.platform.system", return_value="Linux")
    @patch(
        "ggshield.core.machine_id._get_linux_system_id",
        return_value="linux-machine-id",
    )
    def test_system_id_takes_precedence_over_cache(
        self, _mock_linux: MagicMock, _mock_platform: MagicMock, tmp_path: Path
    ):
        # A stale cached fallback must never shadow a derivable hardware id.
        ggshield_dir = tmp_path / ".ggshield"
        ggshield_dir.mkdir()
        (ggshield_dir / "machine_id").write_text("stale-cached\n")
        with patch("ggshield.core.machine_id.get_user_home_dir", return_value=tmp_path):
            assert _get_machine_id() == "linux-machine-id"

    def test_dead_satori_shim_is_not_consulted(self, tmp_path: Path):
        # The legacy ~/.satori reconciliation shim is removed: a value there must
        # neither win over nor substitute for the real derivation.
        satori_dir = tmp_path / ".satori"
        satori_dir.mkdir()
        (satori_dir / "machine_id").write_text("satori-legacy\n")
        with patch(
            "ggshield.core.machine_id.get_user_home_dir", return_value=tmp_path
        ), patch(
            "ggshield.core.machine_id.platform.system", return_value="Linux"
        ), patch(
            "ggshield.core.machine_id._get_linux_system_id",
            return_value="linux-machine-id",
        ):
            assert _get_machine_id() == "linux-machine-id"

    @patch("ggshield.core.machine_id.platform.system", return_value="Linux")
    @patch(
        "ggshield.core.machine_id._get_linux_system_id",
        return_value="linux-machine-id",
    )
    def test_linux_reads_system_id(
        self, _mock_linux: MagicMock, _mock_platform: MagicMock, tmp_path: Path
    ):
        with patch("ggshield.core.machine_id.get_user_home_dir", return_value=tmp_path):
            assert _get_machine_id() == "linux-machine-id"

    @patch("ggshield.core.machine_id.platform.system", return_value="Darwin")
    @patch(
        "ggshield.core.machine_id._get_macos_system_id",
        return_value="mac-uuid-123",
    )
    def test_macos_parses_ioreg(
        self, _mock_mac: MagicMock, _mock_platform: MagicMock, tmp_path: Path
    ):
        with patch("ggshield.core.machine_id.get_user_home_dir", return_value=tmp_path):
            assert _get_machine_id() == "mac-uuid-123"

    @patch("ggshield.core.machine_id.platform.system", return_value="Linux")
    @patch("ggshield.core.machine_id._get_linux_system_id", return_value=None)
    @patch("ggshield.core.machine_id.uuid.uuid4")
    def test_generates_uuid_when_all_fail(
        self,
        mock_uuid4: MagicMock,
        _mock_linux: MagicMock,
        _mock_platform: MagicMock,
        tmp_path: Path,
    ):
        fixed_uuid = uuid.UUID("12345678-1234-5678-1234-567812345678")
        mock_uuid4.return_value = fixed_uuid
        with patch("ggshield.core.machine_id.get_user_home_dir", return_value=tmp_path):
            result = _get_machine_id()
        assert result == str(fixed_uuid)
        assert (tmp_path / ".ggshield" / "machine_id").read_text().strip() == str(
            fixed_uuid
        )

    @patch("ggshield.core.machine_id.platform.system", return_value="Linux")
    @patch("ggshield.core.machine_id._get_linux_system_id", return_value=None)
    @patch("ggshield.core.machine_id.uuid.uuid4")
    def test_persistence_failure_still_returns_uuid(
        self,
        mock_uuid4: MagicMock,
        _mock_linux: MagicMock,
        _mock_platform: MagicMock,
        tmp_path: Path,
    ):
        fixed_uuid = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        mock_uuid4.return_value = fixed_uuid
        # Make .ggshield a file so mkdir fails
        (tmp_path / ".ggshield").write_text("block")
        with patch("ggshield.core.machine_id.get_user_home_dir", return_value=tmp_path):
            result = _get_machine_id()
        assert result == str(fixed_uuid)


# ---------------------------------------------------------------------------
# _normalize_uuid
# ---------------------------------------------------------------------------


CANONICAL = "4c4c4544-0044-4810-8057-b5c04f4a5331"


class TestNormalizeUuid:
    @pytest.mark.parametrize(
        "value",
        [
            pytest.param("4C4C4544-0044-4810-8057-B5C04F4A5331", id="uppercase"),
            pytest.param("{4C4C4544-0044-4810-8057-B5C04F4A5331}", id="braced"),
            pytest.param("4C4C4544004448108057B5C04F4A5331", id="undashed"),
            pytest.param("urn:uuid:4C4C4544-0044-4810-8057-B5C04F4A5331", id="urn"),
            pytest.param("  4c4c4544-0044-4810-8057-b5c04f4a5331  ", id="padded"),
        ],
    )
    def test_canonicalizes_accepted_forms(self, value: str):
        assert _normalize_uuid(value) == CANONICAL

    @pytest.mark.parametrize(
        "value",
        [
            # Python's uuid.UUID accepts all of these via lax int(x, 16); the
            # machine-identity contract requires exactly 32 hex digits so satori
            # (strict Rust parser) and ggshield derive the same id — or both
            # fall back — on the same input.
            pytest.param("0x" + "a" * 30, id="hex_prefix"),
            pytest.param("+" + "a" * 31, id="plus_sign"),
            pytest.param("a_" + "a" * 30, id="underscore"),
            pytest.param("{ " + "a" * 31 + "}", id="brace_padded_whitespace"),
            pytest.param("４" + "a" * 31, id="fullwidth_digit"),
            pytest.param("", id="empty"),
            pytest.param("not-a-uuid", id="garbage"),
            pytest.param("4c4c4544", id="too_short"),
            pytest.param("4c4c4544-0044-4810-8057-b5c04f4a5331aa", id="too_long"),
        ],
    )
    def test_rejects_non_strict_forms(self, value: str):
        assert _normalize_uuid(value) is None

    @pytest.mark.parametrize(
        "value",
        [
            # Placeholder SMBIOS UUIDs reported by unconfigured/cloned firmware
            # identify an image, not a machine: adopting one collapses every
            # such endpoint in an account onto a single machine_id row.
            pytest.param("00000000-0000-0000-0000-000000000000", id="all_zeros"),
            pytest.param("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF", id="all_fs_upper"),
            pytest.param("ffffffff-ffff-ffff-ffff-ffffffffffff", id="all_fs_lower"),
            pytest.param("0" * 32, id="all_zeros_undashed"),
            pytest.param("03000200-0400-0500-0006-000700080009", id="ami_default"),
            # The rest of osquery's placeholder blocklist (see osquery
            # core/system.cpp kPlaceholderHardwareUUIDList and issue #8887).
            pytest.param("03020100-0504-0706-0809-0a0b0c0d0e0f", id="scrambled"),
            pytest.param("10000000-0000-8000-0040-000000000000", id="one_zeros"),
            pytest.param("FEFEFEFE-FEFE-FEFE-FEFE-FEFEFEFEFEFE", id="fefe_windows"),
        ],
    )
    def test_rejects_sentinel_uuids(self, value: str):
        assert _normalize_uuid(value) is None


# ---------------------------------------------------------------------------
# _parse_wmic_uuid
# ---------------------------------------------------------------------------


class TestParseWmicUuid:
    @pytest.mark.parametrize(
        "stdout, expected",
        [
            pytest.param(
                "UUID\n4C4C4544-0044-4810-8057-B5C04F4A5331\n",
                "4c4c4544-0044-4810-8057-b5c04f4a5331",
                id="valid_uuid",
            ),
            pytest.param("UUID\n", None, id="header_only"),
            pytest.param("UUID\nnot-a-uuid\n", None, id="invalid_line"),
            pytest.param("", None, id="empty_string"),
            pytest.param("UUID\n0x" + "a" * 30 + "\n", None, id="lax_hex_rejected"),
            pytest.param(
                "UUID\n03000200-0400-0500-0006-000700080009\n",
                None,
                id="sentinel_rejected",
            ),
            pytest.param(
                "UUID\n00000000-0000-0000-0000-000000000000\n"
                "4C4C4544-0044-4810-8057-B5C04F4A5331\n",
                "4c4c4544-0044-4810-8057-b5c04f4a5331",
                id="sentinel_skipped_next_line_wins",
            ),
        ],
    )
    def test_parse_wmic_uuid(self, stdout: str, expected: str):
        assert _parse_wmic_uuid(stdout) == expected


# ---------------------------------------------------------------------------
# _read_first_nonempty_line
# ---------------------------------------------------------------------------


class TestReadFirstNonemptyLine:
    def test_returns_first_nonempty_line(self, tmp_path: Path):
        f = tmp_path / "data.txt"
        f.write_text("\n  \nhello\nworld\n")
        assert _read_first_nonempty_line(f) == "hello"

    def test_returns_none_for_all_blank_lines(self, tmp_path: Path):
        f = tmp_path / "blank.txt"
        f.write_text("  \n\n  \n")
        assert _read_first_nonempty_line(f) is None

    def test_returns_none_on_oserror(self, tmp_path: Path):
        assert _read_first_nonempty_line(tmp_path / "nonexistent.txt") is None


# ---------------------------------------------------------------------------
# _get_linux_system_id
# ---------------------------------------------------------------------------


class TestGetLinuxSystemId:
    @patch(
        "ggshield.core.machine_id._read_first_nonempty_line",
        side_effect=[None, "dmi-uuid", "ignored"],
    )
    def test_returns_first_successful_candidate(self, _mock: MagicMock):
        assert _get_linux_system_id() == "dmi-uuid"

    @patch(
        "ggshield.core.machine_id._read_first_nonempty_line",
        return_value=None,
    )
    def test_returns_none_when_all_fail(self, _mock: MagicMock):
        assert _get_linux_system_id() is None


# ---------------------------------------------------------------------------
# _get_macos_system_id
# ---------------------------------------------------------------------------


class TestGetMacosSystemId:
    @patch("ggshield.core.machine_id.subprocess.run")
    def test_returns_uuid_from_ioreg(self, mock_run: MagicMock):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='  "IOPlatformUUID" = "ABCD-1234-EF56"\n',
        )
        assert _get_macos_system_id() == "ABCD-1234-EF56"

    @patch("ggshield.core.machine_id.subprocess.run")
    def test_returns_none_on_nonzero_returncode(self, mock_run: MagicMock):
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        assert _get_macos_system_id() is None

    @patch("ggshield.core.machine_id.subprocess.run")
    def test_returns_none_when_regex_does_not_match(self, mock_run: MagicMock):
        mock_run.return_value = MagicMock(returncode=0, stdout="no uuid here\n")
        assert _get_macos_system_id() is None

    @patch(
        "ggshield.core.machine_id.subprocess.run",
        side_effect=OSError("ioreg not found"),
    )
    def test_returns_none_on_oserror(self, _mock: MagicMock):
        assert _get_macos_system_id() is None


# ---------------------------------------------------------------------------
# _get_windows_system_id
# ---------------------------------------------------------------------------


class TestGetWindowsSystemId:
    @patch("ggshield.core.machine_id.subprocess.run")
    def test_returns_uuid_from_wmic(self, mock_run: MagicMock):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="UUID\n4C4C4544-0044-4810-8057-B5C04F4A5331\n",
        )
        assert _get_windows_system_id() == "4c4c4544-0044-4810-8057-b5c04f4a5331"

    @patch("ggshield.core.machine_id.subprocess.run")
    def test_falls_back_to_powershell(self, mock_run: MagicMock):
        wmic_result = MagicMock(returncode=1, stdout="")
        ps_result = MagicMock(
            returncode=0,
            stdout="4C4C4544-0044-4810-8057-B5C04F4A5331\n",
        )
        mock_run.side_effect = [wmic_result, ps_result]
        assert _get_windows_system_id() == "4c4c4544-0044-4810-8057-b5c04f4a5331"

    @patch("ggshield.core.machine_id.subprocess.run")
    def test_powershell_invalid_uuid_returns_none(self, mock_run: MagicMock):
        wmic_result = MagicMock(returncode=1, stdout="")
        ps_result = MagicMock(returncode=0, stdout="not-a-uuid\n")
        mock_run.side_effect = [wmic_result, ps_result]
        assert _get_windows_system_id() is None

    @patch("ggshield.core.machine_id.subprocess.run")
    def test_powershell_sentinel_uuid_returns_none(self, mock_run: MagicMock):
        # A placeholder SMBIOS UUID is not a machine identity: fall through to
        # the shared cache instead of adopting it.
        wmic_result = MagicMock(returncode=1, stdout="")
        ps_result = MagicMock(
            returncode=0, stdout="FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF\n"
        )
        mock_run.side_effect = [wmic_result, ps_result]
        assert _get_windows_system_id() is None

    @patch(
        "ggshield.core.machine_id.subprocess.run",
        side_effect=OSError("cmd not found"),
    )
    def test_returns_none_when_all_commands_fail(self, _mock: MagicMock):
        assert _get_windows_system_id() is None

    @patch("ggshield.core.machine_id.subprocess.run")
    def test_invokes_absolute_binary_path_with_timeout(self, mock_run: MagicMock):
        # Binaries must be resolved to absolute %SystemRoot% paths (not bare
        # names that CreateProcess would resolve via the CWD), and bounded by a
        # timeout so a hung WMI service can't block forever.
        mock_run.return_value = MagicMock(
            returncode=0, stdout="UUID\n4C4C4544-0044-4810-8057-B5C04F4A5331\n"
        )
        with patch.dict(os.environ, {"SystemRoot": r"C:\Windows"}):
            assert _get_windows_system_id() == "4c4c4544-0044-4810-8057-b5c04f4a5331"
        argv = mock_run.call_args.args[0]
        assert argv[0].endswith("WMIC.exe") and argv[0] != "wmic"
        assert "wbem" in argv[0]
        assert mock_run.call_args.kwargs["timeout"] > 0


# ---------------------------------------------------------------------------
# _get_machine_id (additional branches)
# ---------------------------------------------------------------------------


class TestGetMachineIdExtraBranches:
    @patch("ggshield.core.machine_id.platform.system", return_value="Windows")
    @patch("ggshield.core.machine_id.sys")
    @patch(
        "ggshield.core.machine_id._get_windows_system_id",
        return_value="win-uuid-456",
    )
    def test_windows_branch(
        self,
        _mock_win: MagicMock,
        mock_sys: MagicMock,
        _mock_platform: MagicMock,
        tmp_path: Path,
    ):
        mock_sys.platform = "win32"
        with patch("ggshield.core.machine_id.get_user_home_dir", return_value=tmp_path):
            assert _get_machine_id() == "win-uuid-456"

    def test_cache_probe_oserror_is_handled(self, tmp_path: Path):
        # An OSError while probing the shared cache must not crash — fall through
        # to minting a fresh id.
        fixed_uuid = uuid.UUID("11111111-2222-3333-4444-555555555555")
        with patch(
            "ggshield.core.machine_id.get_user_home_dir", return_value=tmp_path
        ), patch.object(Path, "stat", side_effect=OSError("permission denied")), patch(
            "ggshield.core.machine_id.platform.system", return_value="Linux"
        ), patch(
            "ggshield.core.machine_id._get_linux_system_id", return_value=None
        ), patch(
            "ggshield.core.machine_id.uuid.uuid4", return_value=fixed_uuid
        ):
            assert _get_machine_id() == str(fixed_uuid)


# ---------------------------------------------------------------------------
# _windows_binary
# ---------------------------------------------------------------------------


class TestWindowsBinary:
    def test_builds_absolute_path_from_systemroot(self):
        with patch.dict(os.environ, {"SystemRoot": r"C:\Windows"}):
            path = _windows_binary("System32", "wbem", "WMIC.exe")
        assert path.endswith("WMIC.exe")
        assert "System32" in path

    def test_defaults_when_systemroot_unset(self):
        env = {k: v for k, v in os.environ.items() if k != "SystemRoot"}
        with patch.dict(os.environ, env, clear=True):
            path = _windows_binary("System32", "wbem", "WMIC.exe")
        assert "Windows" in path and path.endswith("WMIC.exe")


# ---------------------------------------------------------------------------
# _read_trusted_cache_line
# ---------------------------------------------------------------------------


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission model")
class TestReadTrustedCacheLine:
    def test_owner_only_file_is_read(self, tmp_path: Path):
        f = tmp_path / "machine_id"
        f.write_text("cached-id\n")
        os.chmod(f, 0o600)
        assert _read_trusted_cache_line(f) == "cached-id"

    @pytest.mark.parametrize("mode", [0o666, 0o660, 0o620])
    def test_group_or_world_writable_file_is_rejected(self, tmp_path: Path, mode: int):
        f = tmp_path / "machine_id"
        f.write_text("cached-id\n")
        os.chmod(f, mode)
        assert _read_trusted_cache_line(f) is None

    def test_missing_file_is_rejected(self, tmp_path: Path):
        assert _read_trusted_cache_line(tmp_path / "nope") is None

    def test_owner_acceptance_rules(self):
        # Identity is client-asserted end to end (the server stores whatever
        # machine_id a client reports), so an own-files-only rule buys no
        # integrity. The real requirement is that no OTHER unprivileged user
        # can plant the file: trusted owners are the current user, root, and
        # the owner of the home the cache lives in — so sudo -E runs and
        # plain user runs adopt each other's id instead of diverging.
        assert _is_trusted_cache_owner(file_uid=1000, euid=1000, home_uid=1000)
        assert _is_trusted_cache_owner(file_uid=0, euid=1000, home_uid=1000)
        assert _is_trusted_cache_owner(file_uid=1000, euid=0, home_uid=1000)
        assert not _is_trusted_cache_owner(file_uid=1001, euid=1000, home_uid=1000)
        assert not _is_trusted_cache_owner(file_uid=1001, euid=0, home_uid=1000)
        assert not _is_trusted_cache_owner(file_uid=1001, euid=1000, home_uid=None)

    def test_symlink_is_rejected_even_to_trusted_target(self, tmp_path: Path):
        # stat()-then-open() by path follows symlinks: under sudo -E a planted
        # link to a root-owned file would pass an ownership check and leak that
        # file's first line as the machine_id. The gate must open the real file
        # only (O_NOFOLLOW) and validate the very descriptor it reads.
        target = tmp_path / "target"
        target.write_text("via-symlink\n")
        os.chmod(target, 0o600)
        link = tmp_path / "machine_id"
        link.symlink_to(target)
        assert _read_trusted_cache_line(link) is None

    def test_fifo_is_rejected_without_blocking(self, tmp_path: Path):
        # A FIFO passes naive mode/uid checks but blocks a plain open() forever.
        fifo = tmp_path / "machine_id"
        os.mkfifo(fifo, 0o600)
        assert _read_trusted_cache_line(fifo) is None

    def test_blank_file_yields_none(self, tmp_path: Path):
        f = tmp_path / "machine_id"
        f.write_text("\n  \n")
        os.chmod(f, 0o600)
        assert _read_trusted_cache_line(f) is None

    def test_unreadable_home_dir_rejects_unowned_file(self, tmp_path: Path):
        # If the home directory can't be stat'ed, the home-owner rule can't
        # vouch for the file: only self- or root-owned files remain trusted.
        f = tmp_path / "machine_id"
        f.write_text("cached-id\n")
        os.chmod(f, 0o600)
        with patch(
            "ggshield.core.machine_id.os.stat", side_effect=OSError("denied")
        ), patch("ggshield.core.machine_id.os.geteuid", return_value=os.geteuid() + 1):
            assert _read_trusted_cache_line(f) is None

    def test_read_oserror_yields_none(self, tmp_path: Path):
        f = tmp_path / "machine_id"
        f.write_text("cached-id\n")
        os.chmod(f, 0o600)
        with patch("ggshield.core.machine_id.os.read", side_effect=OSError("io error")):
            assert _read_trusted_cache_line(f) is None


# ---------------------------------------------------------------------------
# Cache write hardening
# ---------------------------------------------------------------------------


@pytest.fixture
def umask_002():
    old = os.umask(0o002)
    yield
    os.umask(old)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission model")
@patch("ggshield.core.machine_id.platform.system", return_value="Linux")
@patch("ggshield.core.machine_id._get_linux_system_id", return_value=None)
class TestCacheWriteHardening:
    def test_cache_written_0600_and_stable_under_umask_002(
        self,
        _mock_linux: MagicMock,
        _mock_platform: MagicMock,
        tmp_path: Path,
        umask_002: None,
    ):
        # Under umask 002 (RHEL/Fedora user-private-group default) a
        # umask-derived write is group-writable, which the trust gate itself
        # rejects on the next run — the id would churn forever on the very
        # machines the fallback cache exists for.
        with patch("ggshield.core.machine_id.get_user_home_dir", return_value=tmp_path):
            first = _get_machine_id()
            _get_machine_id.cache_clear()
            second = _get_machine_id()
        assert first == second
        cache = tmp_path / ".ggshield" / "machine_id"
        assert (cache.stat().st_mode & 0o777) == 0o644

    def test_rejected_self_owned_cache_is_replaced_with_0600(
        self, _mock_linux: MagicMock, _mock_platform: MagicMock, tmp_path: Path
    ):
        # A loose-permission file we own is untrusted (content may have been
        # tampered with) but must be securely replaced, not overwritten in
        # place — truncation preserves the bad mode and the churn loop.
        ggshield_dir = tmp_path / ".ggshield"
        ggshield_dir.mkdir()
        cache = ggshield_dir / "machine_id"
        cache.write_text("attacker-planted\n")
        os.chmod(cache, 0o666)
        with patch("ggshield.core.machine_id.get_user_home_dir", return_value=tmp_path):
            first = _get_machine_id()
            _get_machine_id.cache_clear()
            second = _get_machine_id()
        assert first != "attacker-planted"
        assert first == second
        assert (cache.stat().st_mode & 0o777) == 0o644
        assert cache.read_text().strip() == first

    def test_privileged_run_adopts_home_owners_cache_without_writing(
        self, _mock_linux: MagicMock, _mock_platform: MagicMock, tmp_path: Path
    ):
        # Under sudo -E the cache belongs to the invoking user: root adopts
        # the user's id (same machine, same identity) and never rewrites the
        # user's file.
        ggshield_dir = tmp_path / ".ggshield"
        ggshield_dir.mkdir()
        cache = ggshield_dir / "machine_id"
        cache.write_text("users-own-id\n")
        os.chmod(cache, 0o600)
        with patch(
            "ggshield.core.machine_id.get_user_home_dir", return_value=tmp_path
        ), patch("ggshield.core.machine_id.os.geteuid", return_value=0):
            result = _get_machine_id()
        assert result == "users-own-id"
        assert cache.read_text() == "users-own-id\n"
        assert (cache.stat().st_mode & 0o777) == 0o600

    def test_write_never_touches_a_foreign_owned_file(
        self, _mock_linux: MagicMock, _mock_platform: MagicMock, tmp_path: Path
    ):
        # The write side stays strict even though the read side adopts: a run
        # under another euid must not unlink or rewrite this user's file.
        ggshield_dir = tmp_path / ".ggshield"
        ggshield_dir.mkdir()
        cache = ggshield_dir / "machine_id"
        cache.write_text("users-own-id\n")
        os.chmod(cache, 0o600)
        with patch(
            "ggshield.core.machine_id.os.geteuid", return_value=os.geteuid() + 1
        ):
            _write_machine_id_cache(cache, "intruder-id")
        assert cache.read_text() == "users-own-id\n"
        assert (cache.stat().st_mode & 0o777) == 0o600

    def test_symlinked_cache_is_replaced_without_touching_target(
        self, _mock_linux: MagicMock, _mock_platform: MagicMock, tmp_path: Path
    ):
        # Writing through a planted symlink redirects the write to the target
        # (the write-half symlink attack). Remove the link itself and create a
        # real file; the target must stay untouched.
        target = tmp_path / "target"
        target.write_text("via-symlink\n")
        os.chmod(target, 0o600)
        ggshield_dir = tmp_path / ".ggshield"
        ggshield_dir.mkdir()
        cache = ggshield_dir / "machine_id"
        cache.symlink_to(target)
        with patch("ggshield.core.machine_id.get_user_home_dir", return_value=tmp_path):
            result = _get_machine_id()
        assert result != "via-symlink"
        assert target.read_text() == "via-symlink\n"
        assert not cache.is_symlink()
        assert cache.read_text().strip() == result
