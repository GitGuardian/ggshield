import configparser
import sys
from pathlib import Path

import pytest

from ggshield.verticals.honeytoken.aws_profile import (
    ForceRefusal,
    PlacementError,
    RemoveOutcome,
    WriteOutcome,
    aws_path,
    remove_aws_profile,
    resolve_placement,
    write_aws_profile,
)
from ggshield.verticals.honeytoken.endpoint_deployments import (
    DeploymentMethod,
    HoneytokenCreds,
    PlacementConfig,
)


def _creds(access_id: str, secret: str) -> HoneytokenCreds:
    return HoneytokenCreds(access_token_id=access_id, secret_key=secret)


def _section(path: Path, name: str) -> dict:
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(path)
    return dict(parser[name])


# --- aws_path / resolve_placement -------------------------------------------------


def test_aws_path_composes_under_dot_aws():
    assert aws_path(Path("/home/alice"), "credentials") == Path(
        "/home/alice/.aws/credentials"
    )
    assert aws_path(Path("/home/alice"), "credentials.back") == Path(
        "/home/alice/.aws/credentials.back"
    )


@pytest.mark.parametrize("bad", ["", ".", "..", "a/b", "a\\b"])
def test_aws_path_rejects_traversal_and_separators(bad):
    with pytest.raises(PlacementError):
        aws_path(Path("/home/alice"), bad)


def test_resolve_placement_credentials_has_no_prefix():
    path, section = resolve_placement(
        DeploymentMethod.AWS_CREDENTIALS,
        PlacementConfig(filename="credentials", profile_name="gg"),
        Path("/home/alice"),
    )
    assert path == Path("/home/alice/.aws/credentials")
    assert section == "gg"


def test_resolve_placement_config_profile_has_prefix():
    path, section = resolve_placement(
        DeploymentMethod.AWS_CONFIG_PROFILE,
        PlacementConfig(filename="config", profile_name="gg"),
        Path("/home/alice"),
    )
    assert path == Path("/home/alice/.aws/config")
    assert section == "profile gg"


def test_resolve_placement_unknown_method_raises():
    with pytest.raises(PlacementError):
        resolve_placement(
            DeploymentMethod.UNKNOWN,
            PlacementConfig(filename="x", profile_name="y"),
            Path("/home/alice"),
        )


# --- write_aws_profile ------------------------------------------------------------


def test_write_creates_when_absent(tmp_path):
    path = tmp_path / "credentials"
    outcome = write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)
    assert outcome is WriteOutcome.WROTE
    assert _section(path, "gg") == {
        "aws_access_key_id": "K1",
        "aws_secret_access_key": "S1",
    }


def test_write_is_idempotent_for_same_key(tmp_path):
    path = tmp_path / "credentials"
    write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)
    assert (
        write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)
        is WriteOutcome.ALREADY_CURRENT
    )


def test_write_refuses_drifted_secret_without_force(tmp_path):
    path = tmp_path / "credentials"
    write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)
    with pytest.raises(ForceRefusal):
        write_aws_profile(path, "gg", _creds("K1", "S2"), force=False)


def test_write_repairs_drifted_secret_with_force(tmp_path):
    path = tmp_path / "credentials"
    write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)
    assert (
        write_aws_profile(path, "gg", _creds("K1", "S2"), force=True)
        is WriteOutcome.WROTE
    )
    assert _section(path, "gg")["aws_secret_access_key"] == "S2"


def test_write_refuses_foreign_collision_without_force(tmp_path):
    path = tmp_path / "credentials"
    write_aws_profile(path, "gg", _creds("OTHER", "X"), force=False)
    with pytest.raises(ForceRefusal):
        write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)


def test_write_preserves_other_profiles(tmp_path):
    path = tmp_path / "credentials"
    parser = configparser.ConfigParser(interpolation=None)
    parser["default"] = {"aws_access_key_id": "USER", "aws_secret_access_key": "MINE"}
    with open(path, "w") as handle:
        parser.write(handle)

    write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)
    assert _section(path, "default") == {
        "aws_access_key_id": "USER",
        "aws_secret_access_key": "MINE",
    }
    assert _section(path, "gg")["aws_access_key_id"] == "K1"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file mode bits")
def test_write_sets_restrictive_permissions(tmp_path):
    path = tmp_path / "credentials"
    write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)
    assert (path.stat().st_mode & 0o777) == 0o600


# --- remove_aws_profile -----------------------------------------------------------


def test_remove_absent_file(tmp_path):
    assert (
        remove_aws_profile(tmp_path / "credentials", "gg", None)
        is RemoveOutcome.ALREADY_ABSENT
    )


def test_remove_absent_profile(tmp_path):
    path = tmp_path / "credentials"
    write_aws_profile(path, "other", _creds("K1", "S1"), force=False)
    assert remove_aws_profile(path, "gg", None) is RemoveOutcome.ALREADY_ABSENT


def test_remove_keeps_other_profiles(tmp_path):
    path = tmp_path / "credentials"
    write_aws_profile(path, "default", _creds("USER", "MINE"), force=False)
    write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)
    assert remove_aws_profile(path, "gg", None) is RemoveOutcome.REMOVED
    assert path.exists()
    assert _section(path, "default")["aws_access_key_id"] == "USER"


def test_remove_deletes_now_empty_file(tmp_path):
    path = tmp_path / "credentials"
    write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)
    assert remove_aws_profile(path, "gg", None) is RemoveOutcome.REMOVED
    assert not path.exists()


def test_remove_when_key_matches(tmp_path):
    path = tmp_path / "credentials"
    write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)
    assert remove_aws_profile(path, "gg", "K1") is RemoveOutcome.REMOVED
    assert not path.exists()


def test_write_on_malformed_file_raises_placement_error(tmp_path):
    path = tmp_path / "credentials"
    path.write_text("[\nnot an ini file at all")
    with pytest.raises(PlacementError):
        write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)


def test_remove_on_malformed_file_raises_placement_error(tmp_path):
    path = tmp_path / "credentials"
    path.write_text("garbage = without [ header")
    with pytest.raises(PlacementError):
        remove_aws_profile(path, "gg", None)


def test_remove_keeps_foreign_key(tmp_path):
    path = tmp_path / "credentials"
    write_aws_profile(path, "gg", _creds("OTHER", "X"), force=False)
    assert remove_aws_profile(path, "gg", "K1") is RemoveOutcome.FOREIGN_KEPT
    # Section left untouched.
    assert _section(path, "gg")["aws_access_key_id"] == "OTHER"
