"""
On-disk placement of kubeconfig honeytokens for ``ggshield honeytoken plant``.

GIM sends the full rendered kubeconfig (exactly one cluster + user + context) and its
context name; the client merges those three named entries into ``~/.kube/<filename>``,
**preserving any real entries the user already has**, and removes them on ``delete``.

Merge/remove is by entry *name*, orphan-aware, and verify-before-remove:

- write: upsert our cluster/user/context. If any of those names already exists with
  different content (e.g. a real ``kubernetes-admin`` user), refuse without ``--force``
  rather than clobber it. All three already present and identical → no-op.
- remove: drop our context; drop the cluster/user it referenced only if no *other*
  context still uses them; and only if the on-disk user still carries *our* bearer
  (a rotated/foreign token is left untouched).

Reuses the shared no-follow, fd-anchored I/O (``secure_file``) so the root fan-out gets
the same TOCTOU hardening as the AWS placement. ``WriteOutcome``/``RemoveOutcome`` and
``PlacementError`` are the shared placement vocabulary (defined alongside the AWS
backend); ``ForceRefusal`` is kubeconfig-specific (its own message).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from ggshield.verticals.honeytoken import secure_file
from ggshield.verticals.honeytoken.aws_profile import (
    PlacementError,
    RemoveOutcome,
    WriteOutcome,
)
from ggshield.verticals.honeytoken.endpoint_deployments import (
    DeploymentMethod,
    KubeconfigToken,
)
from ggshield.verticals.honeytoken.secure_file import SecureFileError


SUPPORTED_METHODS = (DeploymentMethod.KUBECONFIG,)

_LIST_KEYS = ("clusters", "users", "contexts")


class ForceRefusal(Exception):
    """One of our named entries already exists with different content; refusing to
    overwrite without ``--force``. Carried so the caller can classify it."""

    def __init__(self, name: str, path: Path) -> None:
        super().__init__(
            f"kubeconfig entry [{name}] in {path} already exists with different content "
            "(a real or foreign cluster/user/context reusing our name) — refusing to "
            "overwrite without --force"
        )
        self.name = name
        self.path = path


class _Identity:
    """The three named entries (and bearer) our generated kubeconfig contributes."""

    def __init__(self, token: KubeconfigToken) -> None:
        doc = _load_doc(token.kubeconfig, Path("<generated kubeconfig>"))
        contexts = _named_list(doc, "contexts")
        ctx = _find(contexts, token.context_name) or (contexts[0] if contexts else None)
        if ctx is None:
            raise PlacementError("generated kubeconfig has no context")
        inner = ctx.get("context") or {}
        context_name = ctx.get("name")
        cluster_name = inner.get("cluster")
        user_name = inner.get("user")
        if not (
            isinstance(context_name, str)
            and isinstance(cluster_name, str)
            and isinstance(user_name, str)
        ):
            raise PlacementError(
                "generated kubeconfig has an unnamed context, cluster, or user"
            )
        self.context_name: str = context_name
        self.cluster_name: str = cluster_name
        self.user_name: str = user_name
        cluster = _find(_named_list(doc, "clusters"), self.cluster_name)
        user = _find(_named_list(doc, "users"), self.user_name)
        if cluster is None or user is None:
            raise PlacementError(
                "generated kubeconfig is missing its cluster or user entry"
            )
        self.cluster_entry = cluster
        self.user_entry = user
        self.context_entry = ctx
        self.bearer: Optional[str] = (user.get("user") or {}).get("token")


def kube_path(home: Path, filename: str) -> Path:
    """Compose ``<home>/.kube/<filename>``, re-asserting the backend's safe-charset rule
    (defense in depth: this may run as root) so the path stays directly inside ``.kube``.
    """
    if filename in ("", ".", "..") or "/" in filename or "\\" in filename:
        raise PlacementError(f"invalid honeytoken filename {filename!r}")
    return home / ".kube" / filename


# --- YAML parsing helpers ---------------------------------------------------------


def _load_doc(text: Optional[str], where: Path) -> Dict[str, Any]:
    if not text or not text.strip():
        return {}
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PlacementError(
            f"could not parse {where}: not a valid kubeconfig/YAML file ({exc})"
        )
    if doc is None:
        return {}
    if not isinstance(doc, dict):
        raise PlacementError(f"could not parse {where}: kubeconfig is not a mapping")
    return doc


def _dump(doc: Dict[str, Any]) -> str:
    return yaml.safe_dump(doc, sort_keys=False, default_flow_style=False)


def _named_list(doc: Dict[str, Any], key: str) -> List[Dict[str, Any]]:
    items = doc.get(key) or []
    if not isinstance(items, list):
        raise PlacementError(f"kubeconfig {key!r} is not a list")
    return items


def _find(items: List[Dict[str, Any]], name: Optional[str]) -> Optional[Dict[str, Any]]:
    for item in items:
        if isinstance(item, dict) and item.get("name") == name:
            return item
    return None


def _upsert(items: List[Dict[str, Any]], entry: Dict[str, Any]) -> None:
    for index, item in enumerate(items):
        if isinstance(item, dict) and item.get("name") == entry.get("name"):
            items[index] = entry
            return
    items.append(entry)


# --- decisions (shared by both I/O backends) --------------------------------------


def _decide_write(
    doc: Dict[str, Any], ident: _Identity, force: bool, path: Path
) -> WriteOutcome:
    """Mutate ``doc`` to hold our three entries and return the outcome.

    - all three present and identical → ``ALREADY_CURRENT``
    - any of our names present with different content → refuse unless ``force``
    - else upsert; claim ``current-context`` only when the file had none (low-disruption)
    """
    doc.setdefault("apiVersion", "v1")
    doc.setdefault("kind", "Config")
    for key in _LIST_KEYS:
        doc.setdefault(key, [])

    existing = {
        "clusters": (_find(doc["clusters"], ident.cluster_name), ident.cluster_entry),
        "users": (_find(doc["users"], ident.user_name), ident.user_entry),
        "contexts": (_find(doc["contexts"], ident.context_name), ident.context_entry),
    }
    if all(found is not None for found, _ in existing.values()) and all(
        found == ours for found, ours in existing.values()
    ):
        return WriteOutcome.ALREADY_CURRENT
    if any(found is not None and found != ours for found, ours in existing.values()):
        if not force:
            raise ForceRefusal(ident.context_name, path)

    _upsert(doc["clusters"], ident.cluster_entry)
    _upsert(doc["users"], ident.user_entry)
    _upsert(doc["contexts"], ident.context_entry)
    if not doc.get("current-context"):
        doc["current-context"] = ident.context_name
    return WriteOutcome.WROTE


def _decide_remove(doc: Dict[str, Any], ident: _Identity) -> RemoveOutcome:
    """Drop our context (and any now-orphaned cluster/user) if the on-disk user still
    carries our bearer. Returns the outcome; ``REMOVED`` means the caller must persist.
    """
    contexts = _named_list(doc, "contexts")
    if _find(contexts, ident.context_name) is None:
        return RemoveOutcome.ALREADY_ABSENT

    existing_user = _find(_named_list(doc, "users"), ident.user_name)
    on_disk_bearer = (
        (existing_user.get("user") or {}).get("token") if existing_user else None
    )
    if (
        ident.bearer is not None
        and on_disk_bearer is not None
        and on_disk_bearer != ident.bearer
    ):
        return RemoveOutcome.FOREIGN_KEPT

    doc["contexts"] = [
        ctx
        for ctx in contexts
        if not (isinstance(ctx, dict) and ctx.get("name") == ident.context_name)
    ]
    # Drop the cluster/user only if no remaining context still references them (a real
    # context may legitimately share the name, e.g. the common `kubernetes-admin` user).
    still_used_clusters = {
        (ctx.get("context") or {}).get("cluster")
        for ctx in doc["contexts"]
        if isinstance(ctx, dict)
    }
    still_used_users = {
        (ctx.get("context") or {}).get("user")
        for ctx in doc["contexts"]
        if isinstance(ctx, dict)
    }
    if ident.cluster_name not in still_used_clusters:
        doc["clusters"] = [
            c
            for c in _named_list(doc, "clusters")
            if not (isinstance(c, dict) and c.get("name") == ident.cluster_name)
        ]
    if ident.user_name not in still_used_users:
        doc["users"] = [
            u
            for u in _named_list(doc, "users")
            if not (isinstance(u, dict) and u.get("name") == ident.user_name)
        ]
    if doc.get("current-context") == ident.context_name:
        doc.pop("current-context", None)
    return RemoveOutcome.REMOVED


def _is_empty(doc: Dict[str, Any]) -> bool:
    """No clusters, users, or contexts left — the file is nothing but an empty shell."""
    return not any(doc.get(key) for key in _LIST_KEYS)


# --- public API -------------------------------------------------------------------


def write_kubeconfig(path: Path, token: KubeconfigToken, force: bool) -> WriteOutcome:
    """Merge our cluster/user/context into ``path``, preserving the user's real entries.

    Rotation is handled upstream by processing ``delete`` before ``write``, so a content
    mismatch only trips on a genuine collision the operator should review.
    """
    ident = _Identity(token)
    try:
        secure_file.require_safe_backend()
        if secure_file.FD_HARDENED:
            dir_fd = secure_file.open_dir_fd(path.parent, create=True)
            try:
                doc = _load_doc(secure_file.read_via_fd(dir_fd, path.name), path)
                outcome = _decide_write(doc, ident, force, path)
                if outcome is WriteOutcome.WROTE:
                    secure_file.atomic_write_via_fd(dir_fd, path.name, _dump(doc))
                return outcome
            finally:
                os.close(dir_fd)

        secure_file.reject_symlinked_target(path)
        doc = _load_doc(secure_file.read_path(path), path)
        outcome = _decide_write(doc, ident, force, path)
        if outcome is WriteOutcome.WROTE:
            secure_file.atomic_write_path(path, _dump(doc))
        return outcome
    except SecureFileError as exc:
        raise PlacementError(str(exc))


def remove_kubeconfig(path: Path, token: KubeconfigToken) -> RemoveOutcome:
    """Remove our context (and orphaned cluster/user) from ``path``, leaving real entries
    intact. Delete the file only when nothing at all is left."""
    ident = _Identity(token)
    try:
        secure_file.require_safe_backend()
        if secure_file.FD_HARDENED:
            try:
                dir_fd = secure_file.open_dir_fd(path.parent, create=False)
            except FileNotFoundError:
                return RemoveOutcome.ALREADY_ABSENT
            try:
                text = secure_file.read_via_fd(dir_fd, path.name)
                if text is None:
                    return RemoveOutcome.ALREADY_ABSENT
                doc = _load_doc(text, path)
                outcome = _decide_remove(doc, ident)
                if outcome is not RemoveOutcome.REMOVED:
                    return outcome
                if _is_empty(doc):
                    secure_file.unlink_via_fd(dir_fd, path.name)
                else:
                    secure_file.atomic_write_via_fd(dir_fd, path.name, _dump(doc))
                return outcome
            finally:
                os.close(dir_fd)

        secure_file.reject_symlinked_target(path)
        text = secure_file.read_path(path)
        if text is None:
            return RemoveOutcome.ALREADY_ABSENT
        doc = _load_doc(text, path)
        outcome = _decide_remove(doc, ident)
        if outcome is not RemoveOutcome.REMOVED:
            return outcome
        if _is_empty(doc):
            secure_file.unlink_path(path)
        else:
            secure_file.atomic_write_path(path, _dump(doc))
        return outcome
    except SecureFileError as exc:
        raise PlacementError(str(exc))
