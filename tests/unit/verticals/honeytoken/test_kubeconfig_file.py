from pathlib import Path

import pytest
import yaml

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
    # PyYAML's error message embeds the offending source line; a kubeconfig's broken line
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


def test_remove_proceeds_when_on_disk_user_carries_no_token(tmp_path):
    # Our user entry was hand-edited to exec auth (no `token:`): nothing to verify the
    # bearer against, so the context is still ours by cluster+user and is removed.
    path = tmp_path / ".kube" / "config"
    token = _token("abc123", "s3cret")
    write_kubeconfig(path, token, force=False)
    doc = _load(path)
    doc["users"][0]["user"] = {"exec": {"command": "aws"}}
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")

    assert remove_kubeconfig(path, token) is RemoveOutcome.REMOVED
    assert not path.exists()


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

    with pytest.raises(PlacementError, match="another document at line 2"):
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
