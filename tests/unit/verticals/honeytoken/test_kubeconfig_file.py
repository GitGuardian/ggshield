from pathlib import Path

import pytest
import yaml

from ggshield.verticals.honeytoken.aws_profile import (
    PlacementError,
    RemoveOutcome,
    WriteOutcome,
)
from ggshield.verticals.honeytoken.endpoint_deployments import KubeconfigToken
from ggshield.verticals.honeytoken.kubeconfig_file import (
    ForceRefusal,
    kube_path,
    remove_kubeconfig,
    write_kubeconfig,
)


_USER = "kubernetes-admin"


def _kubeconfig(subdomain: str, bearer: str) -> str:
    context = f"{_USER}@{subdomain}"
    return yaml.safe_dump(
        {
            "apiVersion": "v1",
            "kind": "Config",
            "clusters": [
                {
                    "name": subdomain,
                    "cluster": {"server": f"https://{subdomain}.orionfleet.io"},
                }
            ],
            "users": [{"name": _USER, "user": {"token": bearer}}],
            "contexts": [
                {"name": context, "context": {"cluster": subdomain, "user": _USER}}
            ],
            "current-context": context,
        },
        sort_keys=False,
    )


def _token(subdomain: str, bearer: str) -> KubeconfigToken:
    return KubeconfigToken(
        kubeconfig=_kubeconfig(subdomain, bearer),
        context_name=f"{_USER}@{subdomain}",
    )


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _names(doc: dict, key: str) -> set:
    return {item["name"] for item in doc.get(key, [])}


# --- kube_path --------------------------------------------------------------------


def test_kube_path_composes_under_dot_kube():
    assert kube_path(Path("/home/alice"), "config") == Path("/home/alice/.kube/config")


@pytest.mark.parametrize("bad", ["", ".", "..", "a/b", "a\\b"])
def test_kube_path_rejects_traversal_and_separators(bad):
    with pytest.raises(PlacementError):
        kube_path(Path("/home/alice"), bad)


# --- write ------------------------------------------------------------------------


def test_write_creates_kubeconfig_with_our_context(tmp_path):
    path = tmp_path / ".kube" / "config"

    outcome = write_kubeconfig(path, _token("abc123", "s3cret"), force=False)

    assert outcome is WriteOutcome.WROTE
    doc = _load(path)
    assert _names(doc, "contexts") == {"kubernetes-admin@abc123"}
    assert doc["users"][0]["user"]["token"] == "s3cret"
    assert doc["current-context"] == "kubernetes-admin@abc123"


def test_write_is_idempotent(tmp_path):
    path = tmp_path / ".kube" / "config"
    token = _token("abc123", "s3cret")
    write_kubeconfig(path, token, force=False)

    outcome = write_kubeconfig(path, token, force=False)

    assert outcome is WriteOutcome.ALREADY_CURRENT


def test_write_preserves_existing_real_entries(tmp_path):
    path = tmp_path / ".kube" / "config"
    path.parent.mkdir(parents=True)
    path.write_text(
        yaml.safe_dump(
            {
                "apiVersion": "v1",
                "kind": "Config",
                "clusters": [{"name": "prod", "cluster": {"server": "https://real"}}],
                "users": [{"name": "alice", "user": {"token": "real-tok"}}],
                "contexts": [
                    {
                        "name": "alice@prod",
                        "context": {"cluster": "prod", "user": "alice"},
                    }
                ],
                "current-context": "alice@prod",
            }
        ),
        encoding="utf-8",
    )

    write_kubeconfig(path, _token("abc123", "s3cret"), force=False)

    doc = _load(path)
    assert _names(doc, "contexts") == {"alice@prod", "kubernetes-admin@abc123"}
    assert _names(doc, "clusters") == {"prod", "abc123"}
    # The user's own current-context is not hijacked.
    assert doc["current-context"] == "alice@prod"


def test_write_refuses_to_clobber_a_foreign_entry_without_force(tmp_path):
    path = tmp_path / ".kube" / "config"
    path.parent.mkdir(parents=True)
    # A real kubernetes-admin user already exists with a different token.
    path.write_text(
        yaml.safe_dump(
            {
                "apiVersion": "v1",
                "kind": "Config",
                "clusters": [],
                "users": [{"name": _USER, "user": {"token": "real-admin-token"}}],
                "contexts": [],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ForceRefusal):
        write_kubeconfig(path, _token("abc123", "s3cret"), force=False)


def test_write_force_overwrites_a_foreign_entry(tmp_path):
    path = tmp_path / ".kube" / "config"
    path.parent.mkdir(parents=True)
    path.write_text(
        yaml.safe_dump(
            {
                "apiVersion": "v1",
                "kind": "Config",
                "clusters": [],
                "users": [{"name": _USER, "user": {"token": "real-admin-token"}}],
                "contexts": [],
            }
        ),
        encoding="utf-8",
    )

    outcome = write_kubeconfig(path, _token("abc123", "s3cret"), force=True)

    assert outcome is WriteOutcome.WROTE
    doc = _load(path)
    assert doc["users"][0]["user"]["token"] == "s3cret"


# --- remove -----------------------------------------------------------------------


def test_remove_deletes_the_file_when_only_ours(tmp_path):
    path = tmp_path / ".kube" / "config"
    token = _token("abc123", "s3cret")
    write_kubeconfig(path, token, force=False)

    outcome = remove_kubeconfig(path, token)

    assert outcome is RemoveOutcome.REMOVED
    assert not path.exists()


def test_remove_absent_context_is_already_absent(tmp_path):
    path = tmp_path / ".kube" / "config"

    outcome = remove_kubeconfig(path, _token("abc123", "s3cret"))

    assert outcome is RemoveOutcome.ALREADY_ABSENT


def test_remove_keeps_a_foreign_token(tmp_path):
    path = tmp_path / ".kube" / "config"
    write_kubeconfig(path, _token("abc123", "planted"), force=False)
    # Someone rotated our context's token out of band.
    doc = _load(path)
    doc["users"][0]["user"]["token"] = "rotated-by-someone-else"
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")

    outcome = remove_kubeconfig(path, _token("abc123", "planted"))

    assert outcome is RemoveOutcome.FOREIGN_KEPT
    assert path.exists()


def test_remove_keeps_a_user_still_referenced_by_a_real_context(tmp_path):
    path = tmp_path / ".kube" / "config"
    write_kubeconfig(path, _token("abc123", "planted"), force=False)
    # A real context reuses the same kubernetes-admin user (shared name).
    doc = _load(path)
    doc["contexts"].append(
        {"name": "real@abc123", "context": {"cluster": "abc123", "user": _USER}}
    )
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")

    outcome = remove_kubeconfig(path, _token("abc123", "planted"))

    assert outcome is RemoveOutcome.REMOVED
    doc = _load(path)
    # Our context is gone, but the shared user (still referenced) is kept.
    assert _names(doc, "contexts") == {"real@abc123"}
    assert _USER in _names(doc, "users")
