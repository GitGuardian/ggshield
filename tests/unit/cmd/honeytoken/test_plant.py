import configparser
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import pytest
from click.testing import CliRunner

from ggshield.__main__ import cli
from ggshield.core.errors import ExitCode
from tests.unit.conftest import assert_invoke_exited_with, assert_invoke_ok
from tests.unit.request_mock import ExpectedRequest, RequestMock, create_json_response


ENDPOINT = "/v1/honeytokens/endpoint-deployments"


def _deployment(
    action: str,
    *,
    dep_id: str = "dep-1",
    method: str = "aws_credentials",
    filename: str = "credentials",
    profile: str = "prod-backup",
    token: Optional[Tuple[str, str]] = None,
) -> Dict[str, Any]:
    deployment: Dict[str, Any] = {
        "id": dep_id,
        "action": action,
        "method": method,
        "config": {"filename": filename, "profile_name": profile},
    }
    if token is not None:
        deployment["token"] = {"access_token_id": token[0], "secret_key": token[1]}
    return deployment


def _install_mock(monkeypatch) -> RequestMock:
    mock = RequestMock()
    monkeypatch.setattr("ggshield.core.client.Session.request", mock)
    return mock


def _section(path: Path, name: str) -> dict:
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(path)
    return dict(parser[name])


def test_help(cli_fs_runner: CliRunner) -> None:
    result = cli_fs_runner.invoke(cli, ["honeytoken", "plant", "--help"])
    assert_invoke_ok(result)
    assert "plant" in result.output.lower()


def test_list_targets_no_api_call(cli_fs_runner: CliRunner) -> None:
    result = cli_fs_runner.invoke(
        cli, ["honeytoken", "plant", "--user-dir", "home", "--list-targets"]
    )
    assert_invoke_ok(result)
    assert "Would plant for 1 user(s)" in result.output


def test_plant_writes_profile(cli_fs_runner: CliRunner, monkeypatch) -> None:
    mock = _install_mock(monkeypatch)
    mock.add_POST(
        ENDPOINT,
        create_json_response(
            {"deployments": [_deployment("write", token=("AKIAEXAMPLE", "s3cr3t"))]}
        ),
    )
    mock.add_request(
        ExpectedRequest("PATCH", f"{ENDPOINT}/dep-1", create_json_response({}, 200))
    )

    result = cli_fs_runner.invoke(
        cli, ["honeytoken", "plant", "--type", "aws", "--user-dir", "home"]
    )

    assert_invoke_ok(result)
    mock.assert_all_requests_happened()
    assert _section(Path("home/.aws/credentials"), "prod-backup") == {
        "aws_access_key_id": "AKIAEXAMPLE",
        "aws_secret_access_key": "s3cr3t",
    }


def test_plant_is_idempotent(cli_fs_runner: CliRunner, monkeypatch) -> None:
    # Pre-existing profile with the same creds → AlreadyCurrent → confirmed planted.
    aws_dir = Path("home/.aws")
    aws_dir.mkdir(parents=True)
    parser = configparser.ConfigParser(interpolation=None)
    parser["prod-backup"] = {
        "aws_access_key_id": "AKIAEXAMPLE",
        "aws_secret_access_key": "s3cr3t",
    }
    with open(aws_dir / "credentials", "w") as handle:
        parser.write(handle)

    mock = _install_mock(monkeypatch)
    mock.add_POST(
        ENDPOINT,
        create_json_response(
            {"deployments": [_deployment("write", token=("AKIAEXAMPLE", "s3cr3t"))]}
        ),
    )
    mock.add_request(
        ExpectedRequest("PATCH", f"{ENDPOINT}/dep-1", create_json_response({}, 200))
    )

    result = cli_fs_runner.invoke(cli, ["honeytoken", "plant", "--user-dir", "home"])
    assert_invoke_ok(result)
    assert "0 written, 1 skipped" in result.output


def test_remove_only_uses_get_and_removes_revoked(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    # On-disk profile holds the revoked key → verify-before-remove deletes it.
    aws_dir = Path("home/.aws")
    aws_dir.mkdir(parents=True)
    parser = configparser.ConfigParser(interpolation=None)
    parser["prod-backup"] = {
        "aws_access_key_id": "REVOKED",
        "aws_secret_access_key": "old",
    }
    with open(aws_dir / "credentials", "w") as handle:
        parser.write(handle)

    mock = _install_mock(monkeypatch)
    # GET (read-only cleanup) returns a delete carrying the revoked key.
    mock.add_GET(
        ENDPOINT,
        create_json_response(
            {"deployments": [_deployment("delete", token=("REVOKED", "old"))]}
        ),
    )
    mock.add_request(
        ExpectedRequest("PATCH", f"{ENDPOINT}/dep-1", create_json_response({}, 200))
    )

    result = cli_fs_runner.invoke(
        cli, ["honeytoken", "plant", "--remove-only", "--user-dir", "home"]
    )

    assert_invoke_ok(result)
    mock.assert_all_requests_happened()
    assert not (aws_dir / "credentials").exists()
    assert "1 removed" in result.output


def test_remove_only_reapplies_ownership_when_file_survives(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    # A delete that leaves OTHER profiles rewrites the file (temp + os.replace). As root
    # that leaves it root-owned 0600, locking the user out — ownership/perms must be
    # re-applied. Here we record the call to prove the re-apply happens.
    aws_dir = Path("home/.aws")
    aws_dir.mkdir(parents=True)
    parser = configparser.ConfigParser(interpolation=None)
    parser["prod-backup"] = {
        "aws_access_key_id": "REVOKED",
        "aws_secret_access_key": "old",
    }
    parser["default"] = {
        "aws_access_key_id": "USER_OWN",
        "aws_secret_access_key": "mine",
    }
    with open(aws_dir / "credentials", "w") as handle:
        parser.write(handle)

    reapplied: list = []
    monkeypatch.setattr(
        "ggshield.cmd.honeytoken.plant.apply_perms_and_owner",
        lambda path, target, running_as_root: reapplied.append(Path(path)),
    )

    mock = _install_mock(monkeypatch)
    mock.add_GET(
        ENDPOINT,
        create_json_response(
            {"deployments": [_deployment("delete", token=("REVOKED", "old"))]}
        ),
    )
    mock.add_request(
        ExpectedRequest("PATCH", f"{ENDPOINT}/dep-1", create_json_response({}, 200))
    )

    result = cli_fs_runner.invoke(
        cli, ["honeytoken", "plant", "--remove-only", "--user-dir", "home"]
    )

    assert_invoke_ok(result)
    # The file survived (the foreign 'default' profile remains) and was re-permed.
    assert (aws_dir / "credentials").exists()
    assert Path("home/.aws/credentials") in reapplied
    # The user's own profile is intact.
    assert (
        _section(aws_dir / "credentials", "default")["aws_access_key_id"] == "USER_OWN"
    )


def test_remove_only_skips_reapply_when_file_deleted(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    # When ours was the only profile, the file is unlinked — there's nothing left to
    # re-perm, so apply_perms_and_owner must NOT run.
    aws_dir = Path("home/.aws")
    aws_dir.mkdir(parents=True)
    parser = configparser.ConfigParser(interpolation=None)
    parser["prod-backup"] = {
        "aws_access_key_id": "REVOKED",
        "aws_secret_access_key": "old",
    }
    with open(aws_dir / "credentials", "w") as handle:
        parser.write(handle)

    reapplied: list = []
    monkeypatch.setattr(
        "ggshield.cmd.honeytoken.plant.apply_perms_and_owner",
        lambda *a, **k: reapplied.append(a),
    )

    mock = _install_mock(monkeypatch)
    mock.add_GET(
        ENDPOINT,
        create_json_response(
            {"deployments": [_deployment("delete", token=("REVOKED", "old"))]}
        ),
    )
    mock.add_request(
        ExpectedRequest("PATCH", f"{ENDPOINT}/dep-1", create_json_response({}, 200))
    )

    result = cli_fs_runner.invoke(
        cli, ["honeytoken", "plant", "--remove-only", "--user-dir", "home"]
    )

    assert_invoke_ok(result)
    assert not (aws_dir / "credentials").exists()
    assert reapplied == []


def test_malformed_credentials_file_fails_cleanly(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    # A garbage ~/.aws/credentials must not crash with a traceback: the deployment is
    # reported failed and the run exits non-zero with a clean message.
    aws_dir = Path("home/.aws")
    aws_dir.mkdir(parents=True)
    (aws_dir / "credentials").write_text("[\nthis is not a valid ini file")

    mock = _install_mock(monkeypatch)
    mock.add_POST(
        ENDPOINT,
        create_json_response(
            {"deployments": [_deployment("write", token=("AKIAEXAMPLE", "s3cr3t"))]}
        ),
    )
    mock.add_request(
        ExpectedRequest("PATCH", f"{ENDPOINT}/dep-1", create_json_response({}, 200))
    )

    result = cli_fs_runner.invoke(cli, ["honeytoken", "plant", "--user-dir", "home"])

    assert_invoke_exited_with(result, ExitCode.UNEXPECTED_ERROR)
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "could not parse" in result.output


@pytest.mark.skipif(sys.platform == "win32", reason="passwd lookup is POSIX")
def test_unknown_user_is_usage_error(cli_fs_runner: CliRunner) -> None:
    result = cli_fs_runner.invoke(
        cli, ["honeytoken", "plant", "--user", "ghost-nonexistent-xyz"]
    )
    assert_invoke_exited_with(result, ExitCode.USAGE_ERROR)
    assert "could not resolve home directory" in result.output


def test_write_entry_missing_credentials_fails(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    mock = _install_mock(monkeypatch)
    mock.add_POST(
        ENDPOINT,
        create_json_response({"deployments": [_deployment("write", token=None)]}),
    )
    mock.add_request(
        ExpectedRequest("PATCH", f"{ENDPOINT}/dep-1", create_json_response({}, 200))
    )
    result = cli_fs_runner.invoke(cli, ["honeytoken", "plant", "--user-dir", "home"])
    assert_invoke_exited_with(result, ExitCode.UNEXPECTED_ERROR)
    assert "missing credentials" in result.output


def test_confirm_failure_is_logged_not_fatal(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    # The profile is written; the confirm PATCH fails → logged, run still succeeds.
    mock = _install_mock(monkeypatch)
    mock.add_POST(
        ENDPOINT,
        create_json_response(
            {"deployments": [_deployment("write", token=("AKIAEXAMPLE", "s3cr3t"))]}
        ),
    )
    mock.add_request(
        ExpectedRequest(
            "PATCH", f"{ENDPOINT}/dep-1", create_json_response({"detail": "boom"}, 500)
        )
    )
    result = cli_fs_runner.invoke(cli, ["honeytoken", "plant", "--user-dir", "home"])
    assert_invoke_ok(result)
    assert "could not confirm" in result.output
    assert Path("home/.aws/credentials").exists()


def test_target_resolution_failure_is_clean(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    # e.g. pwd.getpwall() blowing up during a root fan-out: no traceback.
    def _boom(*_a, **_k):
        raise RuntimeError("pwd exploded")

    monkeypatch.setattr("ggshield.cmd.honeytoken.plant.resolve_targets", _boom)
    result = cli_fs_runner.invoke(cli, ["honeytoken", "plant"])
    assert_invoke_exited_with(result, ExitCode.UNEXPECTED_ERROR)
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "could not resolve planting targets" in result.output


def test_unexpected_per_target_error_does_not_crash(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    # Last-resort net: an unexpected failure for a target is reported, not raised.
    def _boom(*_a, **_k):
        raise RuntimeError("boom")

    monkeypatch.setattr("ggshield.cmd.honeytoken.plant._reconcile_for_user", _boom)
    result = cli_fs_runner.invoke(cli, ["honeytoken", "plant", "--user-dir", "home"])
    assert_invoke_exited_with(result, ExitCode.UNEXPECTED_ERROR)
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "unexpected error" in result.output


def test_api_auth_error_exits_authentication(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    # A 403 from the reconcile POST → AUTHENTICATION_ERROR, reported cleanly, no write.
    mock = _install_mock(monkeypatch)
    mock.add_POST(ENDPOINT, create_json_response({"detail": "forbidden"}, 403))
    result = cli_fs_runner.invoke(cli, ["honeytoken", "plant", "--user-dir", "home"])
    assert_invoke_exited_with(result, ExitCode.AUTHENTICATION_ERROR)
    assert not Path("home/.aws/credentials").exists()


def test_remove_only_foreign_profile_is_kept(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    # The on-disk profile holds a DIFFERENT key than the revoked token → verify-before-
    # remove leaves it untouched (never clobber a foreign profile).
    aws_dir = Path("home/.aws")
    aws_dir.mkdir(parents=True)
    parser = configparser.ConfigParser(interpolation=None)
    parser["prod-backup"] = {
        "aws_access_key_id": "SOMEONE_ELSE",
        "aws_secret_access_key": "x",
    }
    with open(aws_dir / "credentials", "w") as handle:
        parser.write(handle)

    mock = _install_mock(monkeypatch)
    mock.add_GET(
        ENDPOINT,
        create_json_response(
            {"deployments": [_deployment("delete", token=("REVOKED", "old"))]}
        ),
    )
    mock.add_request(
        ExpectedRequest("PATCH", f"{ENDPOINT}/dep-1", create_json_response({}, 200))
    )

    result = cli_fs_runner.invoke(
        cli, ["honeytoken", "plant", "--remove-only", "--user-dir", "home"]
    )

    assert_invoke_ok(result)
    assert "left untouched" in result.output
    # The foreign profile is preserved verbatim.
    assert (
        _section(aws_dir / "credentials", "prod-backup")["aws_access_key_id"]
        == "SOMEONE_ELSE"
    )


def test_remove_only_delete_failure_is_reported(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    # A malformed ~/.aws during the delete pass is reported per-deployment (FAILED), not
    # a crash; the run exits non-zero with a clean message.
    aws_dir = Path("home/.aws")
    aws_dir.mkdir(parents=True)
    (aws_dir / "credentials").write_text("[\nthis is not a valid ini file")

    mock = _install_mock(monkeypatch)
    mock.add_GET(
        ENDPOINT,
        create_json_response(
            {"deployments": [_deployment("delete", token=("REVOKED", "old"))]}
        ),
    )
    mock.add_request(
        ExpectedRequest("PATCH", f"{ENDPOINT}/dep-1", create_json_response({}, 200))
    )

    result = cli_fs_runner.invoke(
        cli, ["honeytoken", "plant", "--remove-only", "--user-dir", "home"]
    )

    assert_invoke_exited_with(result, ExitCode.UNEXPECTED_ERROR)
    assert "could not parse" in result.output


def test_unknown_action_is_ignored(cli_fs_runner: CliRunner, monkeypatch) -> None:
    # A forward-compat action a newer backend introduced is logged, not fatal.
    mock = _install_mock(monkeypatch)
    mock.add_POST(
        ENDPOINT, create_json_response({"deployments": [_deployment("freeze")]})
    )
    result = cli_fs_runner.invoke(cli, ["honeytoken", "plant", "--user-dir", "home"])
    assert_invoke_ok(result)
    assert "ignoring unknown action" in result.output


def test_foreign_profile_without_force_fails(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    # On-disk profile holds a different key; a write without --force must refuse.
    aws_dir = Path("home/.aws")
    aws_dir.mkdir(parents=True)
    parser = configparser.ConfigParser(interpolation=None)
    parser["prod-backup"] = {
        "aws_access_key_id": "USER_OWN",
        "aws_secret_access_key": "mine",
    }
    with open(aws_dir / "credentials", "w") as handle:
        parser.write(handle)

    mock = _install_mock(monkeypatch)
    mock.add_POST(
        ENDPOINT,
        create_json_response(
            {"deployments": [_deployment("write", token=("AKIAEXAMPLE", "s3cr3t"))]}
        ),
    )
    mock.add_request(
        ExpectedRequest("PATCH", f"{ENDPOINT}/dep-1", create_json_response({}, 200))
    )

    result = cli_fs_runner.invoke(cli, ["honeytoken", "plant", "--user-dir", "home"])

    assert_invoke_exited_with(result, ExitCode.UNEXPECTED_ERROR)
    # The user's own profile is left untouched.
    assert (
        _section(Path("home/.aws/credentials"), "prod-backup")["aws_access_key_id"]
        == "USER_OWN"
    )
