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
    # We never claim current-context — hijacking the active context would make the user's
    # next bare `kubectl` trip our own decoy (self-trip).
    assert "current-context" not in doc


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


# --- regression: kubectl's canonical empty config (null lists / empty current) -----


def test_write_into_kubectl_empty_null_lists(tmp_path):
    # kubectl serialises empty lists as `null` and current-context as "".
    path = tmp_path / ".kube" / "config"
    path.parent.mkdir(parents=True)
    path.write_text(
        yaml.safe_dump(
            {
                "apiVersion": "v1",
                "kind": "Config",
                "clusters": None,
                "users": None,
                "contexts": None,
                "current-context": "",
            }
        ),
        encoding="utf-8",
    )

    outcome = write_kubeconfig(path, _token("abc123", "s3cret"), force=False)

    assert outcome is WriteOutcome.WROTE
    doc = _load(path)
    assert _names(doc, "contexts") == {"kubernetes-admin@abc123"}
    # An empty current-context is not hijacked (no self-trip).
    assert not doc.get("current-context")


def test_remove_on_kubectl_empty_null_lists_is_already_absent(tmp_path):
    path = tmp_path / ".kube" / "config"
    path.parent.mkdir(parents=True)
    path.write_text(
        yaml.safe_dump({"apiVersion": "v1", "kind": "Config", "contexts": None}),
        encoding="utf-8",
    )

    outcome = remove_kubeconfig(path, _token("abc123", "s3cret"))

    assert outcome is RemoveOutcome.ALREADY_ABSENT


def test_write_rejects_non_list_clusters(tmp_path):
    path = tmp_path / ".kube" / "config"
    path.parent.mkdir(parents=True)
    path.write_text(
        yaml.safe_dump({"apiVersion": "v1", "kind": "Config", "clusters": "oops"}),
        encoding="utf-8",
    )

    with pytest.raises(PlacementError):
        write_kubeconfig(path, _token("abc123", "s3cret"), force=False)


@pytest.mark.parametrize("op", ["write", "remove"])
def test_malformed_yaml_raises_placement_error(tmp_path, op):
    path = tmp_path / ".kube" / "config"
    path.parent.mkdir(parents=True)
    path.write_text("clusters: [unclosed", encoding="utf-8")
    token = _token("abc123", "s3cret")

    with pytest.raises(PlacementError):
        if op == "write":
            write_kubeconfig(path, token, force=False)
        else:
            remove_kubeconfig(path, token)


def test_write_does_not_claim_current_context_on_a_fresh_file(tmp_path):
    path = tmp_path / ".kube" / "config"

    write_kubeconfig(path, _token("abc123", "s3cret"), force=False)

    assert "current-context" not in _load(path)


# --- remove leaves a foreign context that only shares our name ---------------------


def test_remove_keeps_a_context_sharing_our_name_but_not_ours(tmp_path):
    path = tmp_path / ".kube" / "config"
    path.parent.mkdir(parents=True)
    # A real context named exactly like ours, pointing at a different cluster/user.
    path.write_text(
        yaml.safe_dump(
            {
                "apiVersion": "v1",
                "kind": "Config",
                "clusters": [{"name": "real", "cluster": {"server": "https://real"}}],
                "users": [{"name": "real-user", "user": {"token": "real"}}],
                "contexts": [
                    {
                        "name": "kubernetes-admin@abc123",
                        "context": {"cluster": "real", "user": "real-user"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    outcome = remove_kubeconfig(path, _token("abc123", "planted"))

    assert outcome is RemoveOutcome.FOREIGN_KEPT
    doc = _load(path)
    assert _names(doc, "contexts") == {"kubernetes-admin@abc123"}
    assert _names(doc, "users") == {"real-user"}


def test_remove_tolerates_a_non_dict_context(tmp_path):
    path = tmp_path / ".kube" / "config"
    path.parent.mkdir(parents=True)
    path.write_text(
        yaml.safe_dump(
            {
                "apiVersion": "v1",
                "kind": "Config",
                "contexts": [{"name": "kubernetes-admin@abc123", "context": "oops"}],
            }
        ),
        encoding="utf-8",
    )

    # A non-dict context sharing our name is not ours → FOREIGN_KEPT, no crash.
    outcome = remove_kubeconfig(path, _token("abc123", "s3cret"))

    assert outcome is RemoveOutcome.FOREIGN_KEPT


# --- --force must not destroy a real credential referenced by a foreign context ----


def test_force_refuses_a_user_referenced_by_a_real_context(tmp_path):
    path = tmp_path / ".kube" / "config"
    path.parent.mkdir(parents=True)
    # Our user name collides with a real user that a real context still references.
    path.write_text(
        yaml.safe_dump(
            {
                "apiVersion": "v1",
                "kind": "Config",
                "clusters": [{"name": "prod", "cluster": {"server": "https://real"}}],
                "users": [{"name": _USER, "user": {"token": "real-admin-token"}}],
                "contexts": [
                    {"name": "real@prod", "context": {"cluster": "prod", "user": _USER}}
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(PlacementError):
        write_kubeconfig(path, _token("abc123", "s3cret"), force=True)

    # The real credential is left intact.
    assert _load(path)["users"][0]["user"]["token"] == "real-admin-token"
