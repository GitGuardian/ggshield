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
    _parse_wmic_uuid,
    _read_first_nonempty_line,
)


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
    def test_returns_satori_cached_id(self, tmp_path: Path):
        satori_dir = tmp_path / ".satori"
        satori_dir.mkdir()
        (satori_dir / "machine_id").write_text("cached-uuid\n")
        with patch("ggshield.core.machine_id.get_user_home_dir", return_value=tmp_path):
            assert _get_machine_id() == "cached-uuid"

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
        assert (tmp_path / ".satori" / "machine_id").read_text().strip() == str(
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
        # Make .satori a file so mkdir fails
        (tmp_path / ".satori").write_text("block")
        with patch("ggshield.core.machine_id.get_user_home_dir", return_value=tmp_path):
            result = _get_machine_id()
        assert result == str(fixed_uuid)


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

    @patch(
        "ggshield.core.machine_id.subprocess.run",
        side_effect=OSError("cmd not found"),
    )
    def test_returns_none_when_all_commands_fail(self, _mock: MagicMock):
        assert _get_windows_system_id() is None


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

    def test_satori_oserror_is_handled(self, tmp_path: Path):
        with patch(
            "ggshield.core.machine_id.get_user_home_dir", return_value=tmp_path
        ), patch.object(
            Path, "is_file", side_effect=OSError("permission denied")
        ), patch(
            "ggshield.core.machine_id.platform.system", return_value="Linux"
        ), patch(
            "ggshield.core.machine_id._get_linux_system_id",
            return_value="fallback-id",
        ):
            assert _get_machine_id() == "fallback-id"
