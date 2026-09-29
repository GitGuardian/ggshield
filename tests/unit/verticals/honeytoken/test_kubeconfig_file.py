import os
import warnings
from pathlib import Path

import pytest
import yaml

from ggshield.verticals.honeytoken import secure_file as secure_file_mod
from ggshield.verticals.honeytoken.endpoint_deployments import KubeconfigToken
from ggshield.verticals.honeytoken.kubeconfig_file import (
    ForceRefusal,
    kube_path,
    remove_kubeconfig,
    write_kubeconfig,
)
from ggshield.verticals.honeytoken.placement import (
    PlacementError,
    RemoveOutcome,
    WriteOutcome,
)
from ggshield.verticals.honeytoken.secure_file import FD_HARDENED


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
    # A fresh file gets our context as current-context, like any real kubeconfig.
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
    # No other context and an empty current-context: effectively a fresh file → claimed.
    assert doc["current-context"] == "kubernetes-admin@abc123"


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


def test_write_does_not_claim_current_context_next_to_a_real_context(tmp_path):
    # A real context without an active one: the owner unset it on purpose, and claiming
    # it would make their next bare `kubectl` trip our own decoy.
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
            }
        ),
        encoding="utf-8",
    )

    write_kubeconfig(path, _token("abc123", "s3cret"), force=False)

    assert "current-context" not in _load(path)


def test_remove_drops_the_current_context_we_claimed(tmp_path):
    # The owner's own top-level key keeps the file alive after our entries are gone; the
    # current-context we set must not survive as a dangling pointer.
    path = tmp_path / ".kube" / "config"
    path.parent.mkdir(parents=True)
    path.write_text(
        yaml.safe_dump({"apiVersion": "v1", "kind": "Config", "preferences": {"x": 1}}),
        encoding="utf-8",
    )
    token = _token("abc123", "s3cret")
    write_kubeconfig(path, token, force=False)
    assert _load(path)["current-context"] == "kubernetes-admin@abc123"

    assert remove_kubeconfig(path, token) is RemoveOutcome.REMOVED

    doc = _load(path)
    assert "current-context" not in doc
    assert doc["preferences"] == {"x": 1}


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


# --- review round 2: secret hygiene, duplicates, realistic files ---------------------


def _scoped_kubeconfig(subdomain: str, bearer: str) -> str:
    """The production shape: user scoped to the cluster (``kubernetes-admin-<sub>``)."""
    user = f"kubernetes-admin-{subdomain}"
    context = f"{user}@{subdomain}"
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
            "users": [{"name": user, "user": {"token": bearer}}],
            "contexts": [
                {"name": context, "context": {"cluster": subdomain, "user": user}}
            ],
        },
        sort_keys=False,
    )


def _scoped_token(subdomain: str, bearer: str) -> KubeconfigToken:
    return KubeconfigToken(
        _scoped_kubeconfig(subdomain, bearer),
        f"kubernetes-admin-{subdomain}@{subdomain}",
    )


def test_scoped_user_name_round_trips(tmp_path):
    path = tmp_path / ".kube" / "config"
    token = _scoped_token("e284abc", "s3cret")

    assert write_kubeconfig(path, token, force=False) is WriteOutcome.WROTE
    assert write_kubeconfig(path, token, force=False) is WriteOutcome.ALREADY_CURRENT
    doc = _load(path)
    assert _names(doc, "users") == {"kubernetes-admin-e284abc"}
    assert remove_kubeconfig(path, token) is RemoveOutcome.REMOVED
    assert not path.exists()


@pytest.mark.parametrize("where", ["on_disk", "generated"])
def test_parse_error_never_leaks_the_bearer(tmp_path, where):
    # The parser's error message embeds the offending source line; a kubeconfig's broken line
    # is typically the `token:` one, so the message must be built from position only.
    real_bearer = "REAL-USER-PROD-BEARER-MUST-NOT-LEAK"
    broken = f"users:\n- name: me\n  user:\n    token: {real_bearer}: oops\n"
    path = tmp_path / ".kube" / "config"
    if where == "on_disk":
        path.parent.mkdir(parents=True)
        path.write_text(broken, encoding="utf-8")
        token = _token("abc123", "s3cret")
    else:
        token = KubeconfigToken(broken, "whatever")

    with pytest.raises(PlacementError) as excinfo:
        write_kubeconfig(path, token, force=False)

    message = str(excinfo.value)
    assert real_bearer not in message
    assert "line 4" in message


def test_remove_drops_every_duplicate_of_our_context(tmp_path):
    # A hand-edited file can hold two copies of our context; both must go, and the
    # cluster/user (with the live bearer) must not survive through the duplicate.
    path = tmp_path / ".kube" / "config"
    token = _token("abc123", "s3cret")
    write_kubeconfig(path, token, force=False)
    doc = _load(path)
    doc["contexts"].append(dict(doc["contexts"][0]))
    doc["clusters"].append({"name": "real", "cluster": {"server": "https://real"}})
    doc["users"].append({"name": "real-user", "user": {"token": "real"}})
    doc["contexts"].append(
        {"name": "real", "context": {"cluster": "real", "user": "real-user"}}
    )
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")

    outcome = remove_kubeconfig(path, token)

    assert outcome is RemoveOutcome.REMOVED
    after = _load(path)
    assert _names(after, "contexts") == {"real"}
    assert _names(after, "clusters") == {"real"}
    assert _names(after, "users") == {"real-user"}
    assert "s3cret" not in path.read_text(encoding="utf-8")


def test_remove_keeps_a_foreign_context_sharing_our_name_next_to_ours(tmp_path):
    path = tmp_path / ".kube" / "config"
    token = _token("abc123", "s3cret")
    write_kubeconfig(path, token, force=False)
    doc = _load(path)
    doc["clusters"].append({"name": "other", "cluster": {"server": "https://other"}})
    doc["users"].append({"name": "other-user", "user": {"token": "other"}})
    # Same name as ours, but pointing at a real cluster/user → not ours, must stay.
    doc["contexts"].append(
        {
            "name": "kubernetes-admin@abc123",
            "context": {"cluster": "other", "user": "other-user"},
        }
    )
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")

    outcome = remove_kubeconfig(path, token)

    assert outcome is RemoveOutcome.REMOVED
    after = _load(path)
    assert [ctx["context"]["cluster"] for ctx in after["contexts"]] == ["other"]
    assert _names(after, "clusters") == {"other"}
    assert _names(after, "users") == {"other-user"}


def test_write_dedupes_a_stale_duplicate_of_our_user(tmp_path):
    # Two same-named users (one stale) → one entry left, carrying the current bearer.
    path = tmp_path / ".kube" / "config"
    write_kubeconfig(path, _token("abc123", "old"), force=False)
    doc = _load(path)
    doc["users"].append(dict(doc["users"][0]))
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")

    outcome = write_kubeconfig(path, _token("abc123", "new"), force=True)

    assert outcome is WriteOutcome.WROTE
    after = _load(path)
    assert [u["user"]["token"] for u in after["users"]] == ["new"]
    assert "old" not in path.read_text(encoding="utf-8")


def test_realistic_kubectl_file_is_preserved_and_idempotent(tmp_path):
    # An EKS-style kubectl-generated file: exec auth, big CA blob, preferences,
    # extensions, namespace, current-context — everything must survive in content and
    # the second plant must be a no-op.
    path = tmp_path / ".kube" / "config"
    path.parent.mkdir(parents=True)
    arn = "arn:aws:eks:eu-west-1:123456789012:cluster/prod"
    real = {
        "apiVersion": "v1",
        "kind": "Config",
        "preferences": {"colors": True},
        "current-context": arn,
        "clusters": [
            {
                "name": arn,
                "cluster": {
                    "server": "https://ABCDEF.gr7.eu-west-1.eks.amazonaws.com",
                    "certificate-authority-data": "A" * 1800,
                    "extensions": [{"name": "client.authentication.k8s.io/exec"}],
                },
            }
        ],
        "users": [
            {
                "name": arn,
                "user": {
                    "exec": {
                        "apiVersion": "client.authentication.k8s.io/v1beta1",
                        "command": "aws",
                        "args": ["eks", "get-token", "--cluster-name", "prod"],
                        "env": None,
                    }
                },
            }
        ],
        "contexts": [
            {
                "name": arn,
                "context": {"cluster": arn, "user": arn, "namespace": "payments"},
            }
        ],
    }
    path.write_text(yaml.safe_dump(real, sort_keys=False), encoding="utf-8")
    token = _scoped_token("abc123", "s3cret")

    assert write_kubeconfig(path, token, force=False) is WriteOutcome.WROTE
    assert write_kubeconfig(path, token, force=False) is WriteOutcome.ALREADY_CURRENT

    after = _load(path)
    for key in ("clusters", "users", "contexts"):
        assert after[key][0] == real[key][0]
    assert after["preferences"] == {"colors": True}
    assert after["current-context"] == arn
    assert remove_kubeconfig(path, token) is RemoveOutcome.REMOVED
    restored = _load(path)
    for key in ("clusters", "users", "contexts"):
        assert restored[key] == real[key]


@pytest.mark.parametrize(
    "real_credential",
    [
        {"exec": {"command": "aws", "args": ["eks", "get-token"]}},
        {"client-certificate": "/home/me/real.crt", "client-key": "/home/me/real.key"},
    ],
    ids=["exec-plugin", "client-certificate"],
)
def test_remove_keeps_a_user_that_carries_no_token_of_ours(tmp_path, real_credential):
    # The entry under our name now authenticates without a bearer. We cannot prove it is
    # ours, so it is somebody's real credential — removing it would delete it, and the
    # whole file with it once nothing else remains.
    path = tmp_path / ".kube" / "config"
    token = _token("abc123", "s3cret")
    write_kubeconfig(path, token, force=False)
    doc = _load(path)
    doc["users"][0]["user"] = real_credential
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")

    assert remove_kubeconfig(path, token) is RemoveOutcome.FOREIGN_KEPT

    assert path.exists()
    assert _load(path)["users"][0]["user"] == real_credential


# --- round-trip fidelity: the user's file is theirs, we only add/remove our entries -----


_ANNOTATED = """\
# ~/.kube/config — managed by hand, do not reformat
apiVersion: v1
kind: Config
preferences: {}
current-context: prod   # keep prod as default!
clusters:
- name: prod  # the real one
  cluster:
    server: 'https://prod.example.com:6443'
    certificate-authority-data: QUJD
users:
- name: me
  user:
    token: "real-token"   # rotated monthly
contexts:
- name: prod
  context: {cluster: prod, user: me, namespace: payments}
"""


def test_write_preserves_comments_quotes_and_key_order(tmp_path):
    path = tmp_path / ".kube" / "config"
    path.parent.mkdir(parents=True)
    path.write_text(_ANNOTATED, encoding="utf-8")

    assert write_kubeconfig(path, _token("abc123", "s3cret"), force=False) is (
        WriteOutcome.WROTE
    )

    text = path.read_text(encoding="utf-8")
    # Every comment the user wrote is still there, where they wrote it.
    assert text.startswith("# ~/.kube/config — managed by hand, do not reformat\n")
    assert "current-context: prod   # keep prod as default!" in text
    assert "- name: prod  # the real one" in text
    assert 'token: "real-token"   # rotated monthly' in text
    # Quoting style, flow mapping and top-level key order are untouched.
    assert "server: 'https://prod.example.com:6443'" in text
    assert "context: {cluster: prod, user: me, namespace: payments}" in text
    top_level = [
        line.split(":")[0] for line in text.splitlines() if line and line[0].isalpha()
    ]
    assert top_level == [
        "apiVersion",
        "kind",
        "preferences",
        "current-context",
        "clusters",
        "users",
        "contexts",
    ]
    # And our entries were merged in, once.
    doc = _load(path)
    assert _names(doc, "contexts") == {"prod", "kubernetes-admin@abc123"}


def test_remove_restores_the_annotated_file_verbatim(tmp_path):
    path = tmp_path / ".kube" / "config"
    path.parent.mkdir(parents=True)
    path.write_text(_ANNOTATED, encoding="utf-8")
    token = _token("abc123", "s3cret")
    write_kubeconfig(path, token, force=False)

    assert remove_kubeconfig(path, token) is RemoveOutcome.REMOVED

    assert path.read_text(encoding="utf-8") == _ANNOTATED


def test_idempotent_rewrite_does_not_touch_the_file_at_all(tmp_path):
    path = tmp_path / ".kube" / "config"
    path.parent.mkdir(parents=True)
    path.write_text(_ANNOTATED, encoding="utf-8")
    token = _token("abc123", "s3cret")
    write_kubeconfig(path, token, force=False)
    before = path.read_text(encoding="utf-8")

    assert write_kubeconfig(path, token, force=False) is WriteOutcome.ALREADY_CURRENT

    assert path.read_text(encoding="utf-8") == before


def test_long_scalars_are_not_folded(tmp_path):
    # A 1800-char certificate-authority-data must stay on one line: a line-wrapped
    # scalar is valid YAML but a visible change to the user's file.
    path = tmp_path / ".kube" / "config"
    path.parent.mkdir(parents=True)
    blob = "Q" * 1800
    path.write_text(
        "apiVersion: v1\nkind: Config\nclusters:\n- name: prod\n  cluster:\n"
        f"    server: https://prod\n    certificate-authority-data: {blob}\n"
        "users: []\ncontexts: []\n",
        encoding="utf-8",
    )

    write_kubeconfig(path, _token("abc123", "s3cret"), force=False)

    assert f"certificate-authority-data: {blob}\n" in path.read_text(encoding="utf-8")


def test_multi_document_file_is_rejected_clearly(tmp_path):
    path = tmp_path / ".kube" / "config"
    path.parent.mkdir(parents=True)
    path.write_text("apiVersion: v1\n---\napiVersion: v1\n", encoding="utf-8")

    with pytest.raises(PlacementError, match="ComposerError at line 2"):
        write_kubeconfig(path, _token("abc123", "s3cret"), force=False)


# --- batch C: file kept when the user's own top-level keys remain, real-principal message


def test_remove_keeps_a_file_that_still_holds_the_users_preferences(tmp_path):
    # kubectl writes `preferences:` blocks; a file holding only that plus our entries
    # must survive our removal (we never delete what is theirs).
    path = tmp_path / ".kube" / "config"
    path.parent.mkdir(parents=True)
    path.write_text(
        "apiVersion: v1\nkind: Config\npreferences:\n  colors: true\n", encoding="utf-8"
    )
    token = _token("abc123", "s3cret")
    write_kubeconfig(path, token, force=False)

    assert remove_kubeconfig(path, token) is RemoveOutcome.REMOVED

    assert path.exists()
    doc = _load(path)
    assert doc["preferences"] == {"colors": True}
    assert not doc.get("contexts") and not doc.get("users") and not doc.get("clusters")


def test_remove_deletes_a_file_that_is_only_an_empty_shell(tmp_path):
    # `preferences: {}` and empty lists carry nothing of the user's → the shell goes.
    path = tmp_path / ".kube" / "config"
    path.parent.mkdir(parents=True)
    path.write_text("apiVersion: v1\nkind: Config\npreferences: {}\n", encoding="utf-8")
    token = _token("abc123", "s3cret")
    write_kubeconfig(path, token, force=False)

    assert remove_kubeconfig(path, token) is RemoveOutcome.REMOVED
    assert not path.exists()


def test_real_principal_collision_message_does_not_blame_force(tmp_path):
    # Without --force the refusal must not read as if the user had passed it.
    path = tmp_path / ".kube" / "config"
    path.parent.mkdir(parents=True)
    path.write_text(
        yaml.safe_dump(
            {
                "apiVersion": "v1",
                "kind": "Config",
                "clusters": [{"name": "abc123", "cluster": {"server": "https://real"}}],
                "users": [{"name": "real-user", "user": {"token": "real"}}],
                "contexts": [
                    {
                        "name": "real",
                        "context": {"cluster": "abc123", "user": "real-user"},
                    }
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    with pytest.raises(PlacementError) as excinfo:
        write_kubeconfig(path, _token("abc123", "s3cret"), force=False)

    message = str(excinfo.value)
    assert "real cluster still used by another context" in message
    assert "even with --force" not in message


# --- batch D: duplicate-key leak, comments-only remainder, non-regular files ------------


@pytest.mark.parametrize("where", ["on_disk", "generated"])
def test_duplicate_key_error_never_leaks_the_value(tmp_path, where):
    # ruamel's DuplicateKeyError.problem quotes the duplicated VALUE — for a repeated
    # `token:` key that is the user's real bearer. Only the error class + position may go
    # into our message.
    real_bearer = "REAL-PROD-BEARER-MUST-NOT-LEAK"
    doubled = (
        "users:\n- name: prod-admin\n  user:\n"
        f"    token: {real_bearer}\n    token: {real_bearer}\n"
    )
    path = tmp_path / ".kube" / "config"
    if where == "on_disk":
        path.parent.mkdir(parents=True)
        path.write_text(doubled, encoding="utf-8")
        token = _token("abc123", "s3cret")
    else:
        token = KubeconfigToken(doubled, "whatever")

    with pytest.raises(PlacementError) as excinfo:
        write_kubeconfig(path, token, force=False)

    message = str(excinfo.value)
    assert real_bearer not in message
    assert "DuplicateKeyError at line 5" in message


def test_remove_keeps_a_file_whose_only_remainder_is_the_users_comments(tmp_path):
    path = tmp_path / ".kube" / "config"
    path.parent.mkdir(parents=True)
    annotated = "# === my curated kube config ===\n# do not delete\napiVersion: v1\nkind: Config\n"
    path.write_text(annotated, encoding="utf-8")
    token = _token("abc123", "s3cret")
    write_kubeconfig(path, token, force=False)

    assert remove_kubeconfig(path, token) is RemoveOutcome.REMOVED

    # The file survives with the user's comments in place; only the (now empty) list
    # keys the merge normalised remain alongside the shell.
    assert path.exists()
    text = path.read_text(encoding="utf-8")
    assert text.startswith(annotated)
    assert "s3cret" not in text and "abc123" not in text


def test_directory_in_place_of_the_kubeconfig_is_a_placement_error(tmp_path):
    path = tmp_path / ".kube" / "config"
    path.mkdir(parents=True)

    with pytest.raises(PlacementError, match="not a regular file"):
        write_kubeconfig(path, _token("abc123", "s3cret"), force=False)
    with pytest.raises(PlacementError, match="not a regular file"):
        remove_kubeconfig(path, _token("abc123", "s3cret"))


# --- review round 3: parser output never reaches the operator -------------------------


@pytest.mark.parametrize("where", ["on_disk", "generated"])
def test_a_bad_yaml_tag_never_leaks_the_token_value(tmp_path, where):
    # `token: !!int <bearer>` fails inside ruamel's constructor as a plain ValueError
    # ("invalid literal for int() ... '<bearer>'"), which is not a YAMLError and so used
    # to travel all the way to stderr with the value in it.
    real_bearer = "REAL-PROD-BEARER-MUST-NOT-LEAK"
    tagged = (
        "apiVersion: v1\nkind: Config\n"
        f"users:\n- name: prod-admin\n  user:\n    token: !!int {real_bearer}\n"
    )
    path = tmp_path / ".kube" / "config"
    if where == "on_disk":
        path.parent.mkdir(parents=True)
        path.write_text(tagged, encoding="utf-8")
        token = _token("abc123", "s3cret")
    else:
        token = KubeconfigToken(tagged, "whatever")

    with pytest.raises(PlacementError) as excinfo:
        write_kubeconfig(path, token, force=False)

    message = str(excinfo.value)
    assert real_bearer not in message
    assert "not a valid kubeconfig/YAML file (ValueError)" in message


def test_a_reused_anchor_does_not_print_the_token_line_as_a_warning(tmp_path):
    # ruamel reports a duplicate anchor through `warnings.warn`, quoting both source
    # lines. That text bypasses our error wording entirely, so the load must run muted.
    real_bearer = "REAL-PROD-BEARER-MUST-NOT-LEAK"
    anchored = (
        "apiVersion: v1\nkind: Config\nclusters: []\ncontexts: []\n"
        "users:\n"
        f"- name: one\n  user:\n    token: &tok {real_bearer}\n"
        f"- name: two\n  user:\n    token: &tok {real_bearer}\n"
    )
    path = tmp_path / ".kube" / "config"
    path.parent.mkdir(parents=True)
    path.write_text(anchored, encoding="utf-8")

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        write_kubeconfig(path, _token("abc123", "s3cret"), force=False)

    assert [str(item.message) for item in caught] == []


@pytest.mark.skipif(not FD_HARDENED, reason="needs dir fds / O_NOFOLLOW")
def test_a_hardlinked_kubeconfig_is_refused(tmp_path):
    # ~/.kube/config planted as a hardlink to a file the user cannot read: the root
    # fan-out must not read it, merge it and hand the copy back to them.
    secret = tmp_path / "not-theirs"
    secret.write_text("apiVersion: v1\nkind: Config\nstolen: yes\n", encoding="utf-8")
    path = tmp_path / ".kube" / "config"
    path.parent.mkdir(parents=True)
    os.link(secret, path)

    with pytest.raises(PlacementError, match="hard links"):
        write_kubeconfig(path, _token("abc123", "s3cret"), force=False)
    assert path.read_text(encoding="utf-8") == secret.read_text(encoding="utf-8")


def test_write_dedupes_even_when_the_first_copy_is_already_current(tmp_path):
    # Two entries share our user name: the first is current, the second still carries an
    # old bearer. `_find` only sees the first, so the ALREADY_CURRENT shortcut used to
    # report "planted" and leave the stale bearer on disk.
    path = tmp_path / ".kube" / "config"
    path.parent.mkdir(parents=True)
    token = _token("abc123", "current-bearer")
    write_kubeconfig(path, token, force=False)

    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    doc["users"].append({"name": _USER, "user": {"token": "stale-bearer"}})
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")

    assert write_kubeconfig(path, token, force=False) is WriteOutcome.WROTE

    text = path.read_text(encoding="utf-8")
    assert "stale-bearer" not in text
    assert text.count("current-bearer") == 1


def test_remove_drops_our_user_when_the_context_was_deleted_by_hand(tmp_path):
    # The CLI's `config delete-context` removes the context alone; the cluster and the
    # user — with our bearer — stay behind. Reporting ALREADY_ABSENT there would leave
    # the revoked decoy readable for good.
    path = tmp_path / ".kube" / "config"
    path.parent.mkdir(parents=True)
    token = _token("abc123", "s3cret")
    write_kubeconfig(path, token, force=False)

    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    doc["contexts"] = []
    doc.pop("current-context", None)
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    assert "s3cret" in path.read_text(encoding="utf-8")

    assert remove_kubeconfig(path, token) is RemoveOutcome.REMOVED
    assert not path.exists() or "s3cret" not in path.read_text(encoding="utf-8")


def test_remove_leaves_an_orphan_user_another_context_still_binds(tmp_path):
    # Without a context of ours we have nothing but the name to go on, so a user some
    # other context still references is not ours to delete.
    path = tmp_path / ".kube" / "config"
    path.parent.mkdir(parents=True)
    token = _token("abc123", "s3cret")
    write_kubeconfig(path, token, force=False)

    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    doc["contexts"] = [
        {"name": "theirs", "context": {"cluster": "real", "user": _USER}}
    ]
    doc.pop("current-context", None)
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")

    assert remove_kubeconfig(path, token) is RemoveOutcome.ALREADY_ABSENT


@pytest.mark.skipif(not FD_HARDENED, reason="patches the fd backend's os.unlink")
def test_remove_reports_a_failed_unlink_instead_of_claiming_success(
    tmp_path, monkeypatch
):
    # An unlink refused by the filesystem must not be passed off as removed: the server
    # would retire the delete with the decoy still on disk. The path backend gets the
    # same guarantee from its own test in test_secure_file.
    path = tmp_path / ".kube" / "config"
    path.parent.mkdir(parents=True)
    token = _token("abc123", "s3cret")
    write_kubeconfig(path, token, force=False)

    def _refuse(*args, **kwargs):
        raise PermissionError("EROFS")

    monkeypatch.setattr(secure_file_mod.os, "unlink", _refuse)

    with pytest.raises(PlacementError, match="could not remove"):
        remove_kubeconfig(path, token)


# --- generated-payload guards and empty-document handling ----------------------------


def test_remove_on_an_empty_kube_dir_is_already_absent(tmp_path):
    path = tmp_path / ".kube" / "config"
    path.parent.mkdir(parents=True)  # the dir exists, the file does not

    assert remove_kubeconfig(path, _token("abc123", "s3cret")) is (
        RemoveOutcome.ALREADY_ABSENT
    )


def test_generated_payload_without_the_named_context_is_rejected(tmp_path):
    token = KubeconfigToken(
        _kubeconfig("abc123", "s3cret"), context_name="not-in-there"
    )

    with pytest.raises(PlacementError, match="no context named"):
        write_kubeconfig(tmp_path / ".kube" / "config", token, force=False)


def test_generated_payload_with_an_unnamed_cluster_is_rejected(tmp_path):
    body = yaml.safe_dump(
        {
            "apiVersion": "v1",
            "kind": "Config",
            "clusters": [],
            "users": [],
            "contexts": [{"name": "ctx", "context": {"cluster": None, "user": _USER}}],
        }
    )

    with pytest.raises(PlacementError, match="unnamed context, cluster, or user"):
        write_kubeconfig(
            tmp_path / ".kube" / "config",
            KubeconfigToken(body, context_name="ctx"),
            force=False,
        )


def test_generated_payload_missing_its_cluster_entry_is_rejected(tmp_path):
    body = yaml.safe_dump(
        {
            "apiVersion": "v1",
            "kind": "Config",
            "clusters": [],
            "users": [{"name": _USER, "user": {"token": "s3cret"}}],
            "contexts": [
                {"name": "ctx", "context": {"cluster": "abc123", "user": _USER}}
            ],
        }
    )

    with pytest.raises(PlacementError, match="missing its cluster or user entry"):
        write_kubeconfig(
            tmp_path / ".kube" / "config",
            KubeconfigToken(body, context_name="ctx"),
            force=False,
        )


def test_a_document_that_parses_to_nothing_is_treated_as_an_empty_file(tmp_path):
    # `---` on its own is valid YAML for "no document"; kubectl treats it as empty.
    path = tmp_path / ".kube" / "config"
    path.parent.mkdir(parents=True)
    path.write_text("---\n", encoding="utf-8")

    assert write_kubeconfig(path, _token("abc123", "s3cret"), force=False) is (
        WriteOutcome.WROTE
    )


def test_a_document_that_is_not_a_mapping_is_rejected(tmp_path):
    path = tmp_path / ".kube" / "config"
    path.parent.mkdir(parents=True)
    path.write_text("just a bare string\n", encoding="utf-8")

    with pytest.raises(PlacementError, match="not a mapping"):
        write_kubeconfig(path, _token("abc123", "s3cret"), force=False)
