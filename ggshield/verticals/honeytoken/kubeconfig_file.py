"""
On-disk placement of kubeconfig honeytokens for ``ggshield honeytoken plant``.

GIM sends the full rendered kubeconfig (exactly one cluster + user + context) and its
context name; the client merges those three named entries into ``~/.kube/<filename>``,
**preserving any real entries the user already has**, and removes them on ``delete``.

Merge/remove is by entry *name*, orphan-aware, and verify-before-remove:

- write: upsert our cluster/user/context. If any of those names already exists with
  different content, refuse without ``--force`` rather than clobber it; a cluster/user
  that a *foreign* context still references is refused even with ``--force`` (it is a
  real principal). We never claim ``current-context`` — hijacking the active context
  would trip the decoy on the owner's own ``kubectl``. All three identical → no-op.
- remove: drop our context only when it is actually ours (same cluster+user) and the
  on-disk user still carries *our* bearer (a rotated/foreign token is left untouched);
  then drop the cluster/user it referenced only if no *other* context still uses them.

The file is edited round-trip (``ruamel.yaml``): the user's comments, quoting, flow
style and key order survive, exactly as ``configupdater`` does for ``~/.aws`` — we only
ever add or drop our own entries.

Reuses the shared no-follow, fd-anchored I/O (``secure_file``) so the root fan-out gets
the same TOCTOU hardening as the AWS placement, and the shared outcome/error
vocabulary (``placement``); ``ForceRefusal`` here only words the message for kubeconfig.
"""

from __future__ import annotations

import io
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from ggshield.verticals.honeytoken import secure_file
from ggshield.verticals.honeytoken.endpoint_deployments import KubeconfigToken
from ggshield.verticals.honeytoken.placement import ForceRefusal as _ForceRefusal
from ggshield.verticals.honeytoken.placement import (
    PlacementError,
    RemoveOutcome,
    WriteOutcome,
)
from ggshield.verticals.honeytoken.secure_file import SecureFileError


_LIST_KEYS = ("clusters", "users", "contexts")


class ForceRefusal(_ForceRefusal):
    """One of our named entries already exists with different content."""

    def __init__(self, name: str, path: Path) -> None:
        super().__init__(
            f"kubeconfig entry [{name}] in {path} already exists with different content "
            "(a real or foreign cluster/user/context reusing our name) — refusing to "
            "overwrite without --force",
            name=name,
            path=path,
        )


class _Identity:
    """The three named entries (and bearer) our generated kubeconfig contributes."""

    def __init__(self, token: KubeconfigToken) -> None:
        doc = _load_doc(token.kubeconfig, Path("<generated kubeconfig>"))
        contexts = _named_list(doc, "contexts")
        ctx = _find(contexts, token.context_name)
        if ctx is None:
            raise PlacementError(
                f"generated kubeconfig has no context named {token.context_name!r}"
            )
        inner = _mapping(ctx.get("context"))
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
        self.bearer: Optional[str] = _mapping(user.get("user")).get("token")


def kube_path(home: Path, filename: str) -> Path:
    """Compose ``<home>/.kube/<filename>``, re-asserting the backend's safe-charset rule
    (defense in depth: this may run as root) so the path stays directly inside ``.kube``.
    """
    if filename in ("", ".", "..") or "/" in filename or "\\" in filename:
        raise PlacementError(f"invalid honeytoken filename {filename!r}")
    return home / ".kube" / filename


# --- YAML parsing helpers ---------------------------------------------------------


def _yaml() -> YAML:
    """A round-trip loader/dumper tuned to leave the user's file alone: quotes kept, no
    folding of long scalars (CA blobs, tokens), kubectl's flush-left list indentation.
    """
    rt = YAML(typ="rt")
    rt.preserve_quotes = True
    rt.width = 1 << 20
    rt.indent(mapping=2, sequence=2, offset=0)
    return rt


def _load_doc(text: Optional[str], where: Path) -> Dict[str, Any]:
    if not text or not text.strip():
        return {}
    try:
        doc = _yaml().load(text)
    except YAMLError as exc:
        # Never interpolate the exception itself: PyYAML's message embeds the offending
        # source line, and in a kubeconfig that is typically a ``token:`` line — a user's
        # real bearer would end up on stderr / in the fleet agent's logs.
        raise PlacementError(
            f"could not parse {where}: not a valid kubeconfig/YAML file "
            f"({_yaml_error_location(exc)})"
        )
    if doc is None:
        return {}
    if not isinstance(doc, dict):
        raise PlacementError(f"could not parse {where}: kubeconfig is not a mapping")
    return doc


def _yaml_error_location(exc: YAMLError) -> str:
    """The parser's problem statement and position only — nothing copied from the file."""
    problem = getattr(exc, "problem", None) or "parse error"
    mark = getattr(exc, "problem_mark", None)
    if mark is None:
        return str(problem)
    return f"{problem} at line {mark.line + 1}, column {mark.column + 1}"


def _dump(doc: Dict[str, Any]) -> str:
    stream = io.StringIO()
    _yaml().dump(doc, stream)
    return stream.getvalue()


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


def _mapping(value: Any) -> Dict[str, Any]:
    """A nested sub-mapping, tolerating a malformed file where it is ``None`` or a scalar
    (kubectl always writes dicts, but a hand-edited config may not)."""
    return value if isinstance(value, dict) else {}


def _same_name(item: Any, name: Optional[str]) -> bool:
    return isinstance(item, dict) and item.get("name") == name


def _remove_where(items: List[Any], unwanted: Callable[[Any], bool]) -> None:
    """Delete matching items in place, by index, so the round-trip list keeps the
    comments attached to the entries that stay (rebuilding the list would drop them)."""
    for index in range(len(items) - 1, -1, -1):
        if unwanted(items[index]):
            del items[index]


def _upsert(items: List[Dict[str, Any]], entry: Dict[str, Any]) -> None:
    """Replace the first same-named entry in place (keeps the file order) and drop any
    later duplicate: kubectl resolves names by first match, so extra copies are dead
    weight — and a stale copy of *our* user would keep an old bearer alive on disk."""
    name = entry.get("name")
    first = next((i for i, item in enumerate(items) if _same_name(item, name)), None)
    if first is None:
        items.append(entry)
        return
    items[first] = entry
    for index in range(len(items) - 1, first, -1):
        if _same_name(items[index], name):
            del items[index]


# --- decisions (shared by both I/O backends) --------------------------------------


def _referenced_by_foreign_context(
    doc: Dict[str, Any], field: str, name: str, our_context_name: str
) -> bool:
    """True if any context *other than ours* references cluster/user ``name`` — i.e. the
    entry belongs to a real principal, not a stale copy of our own decoy."""
    for ctx in _named_list(doc, "contexts"):
        if not isinstance(ctx, dict) or ctx.get("name") == our_context_name:
            continue
        if _mapping(ctx.get("context")).get(field) == name:
            return True
    return False


def _decide_write(
    doc: Dict[str, Any], ident: _Identity, force: bool, path: Path
) -> WriteOutcome:
    """Mutate ``doc`` to hold our three entries and return the outcome.

    - all three present and identical → ``ALREADY_CURRENT``
    - a cluster/user name that collides with a real principal (still referenced by a
      foreign context) → refuse even with ``force``: overwriting destroys the real
      credential, and reusing it would funnel that user's token to our capture edge
    - any other of our names present with different content → refuse unless ``force``
    - never claim ``current-context``: the decoy is reachable by name, and hijacking the
      active context would make the legitimate user's next ``kubectl`` trip our own decoy
    """
    doc.setdefault("apiVersion", "v1")
    doc.setdefault("kind", "Config")
    # Normalise the three lists in place: kubectl serialises empty lists as `null` (which
    # `setdefault` leaves untouched), and a hand-edited file may hold a non-list (rejected).
    for key in _LIST_KEYS:
        doc[key] = _named_list(doc, key)

    existing = {
        "clusters": (_find(doc["clusters"], ident.cluster_name), ident.cluster_entry),
        "users": (_find(doc["users"], ident.user_name), ident.user_entry),
        "contexts": (_find(doc["contexts"], ident.context_name), ident.context_entry),
    }
    if all(found is not None for found, _ in existing.values()) and all(
        found == ours for found, ours in existing.values()
    ):
        return WriteOutcome.ALREADY_CURRENT

    collisions = [
        (kind, found)
        for kind, (found, ours) in existing.items()
        if found is not None and found != ours
    ]
    for kind, found in collisions:
        if kind == "clusters" or kind == "users":
            field = "cluster" if kind == "clusters" else "user"
            name = ident.cluster_name if kind == "clusters" else ident.user_name
            if _referenced_by_foreign_context(doc, field, name, ident.context_name):
                raise PlacementError(
                    f"kubeconfig {kind[:-1]} [{name}] in {path} belongs to a real "
                    "cluster/user referenced by another context — refusing to touch it "
                    "even with --force"
                )
    if collisions and not force:
        raise ForceRefusal(collisions[0][1].get("name") or ident.context_name, path)

    _upsert(doc["clusters"], ident.cluster_entry)
    _upsert(doc["users"], ident.user_entry)
    _upsert(doc["contexts"], ident.context_entry)
    return WriteOutcome.WROTE


def _decide_remove(doc: Dict[str, Any], ident: _Identity) -> RemoveOutcome:
    """Drop our context (and any now-orphaned cluster/user) if the on-disk user still
    carries our bearer. Returns the outcome; ``REMOVED`` means the caller must persist.
    """
    contexts = _named_list(doc, "contexts")
    same_named = [ctx for ctx in contexts if _same_name(ctx, ident.context_name)]
    if not same_named:
        return RemoveOutcome.ALREADY_ABSENT

    # Only the same-named contexts that are actually ours (same cluster + user) go; a
    # real context that merely reuses the name is left untouched. Every copy of ours is
    # removed — a duplicated entry must not survive and keep the decoy reachable.
    ours = [
        ctx
        for ctx in same_named
        if _mapping(ctx.get("context")).get("cluster") == ident.cluster_name
        and _mapping(ctx.get("context")).get("user") == ident.user_name
    ]
    if not ours:
        return RemoveOutcome.FOREIGN_KEPT

    existing_user = _find(_named_list(doc, "users"), ident.user_name)
    on_disk_bearer = (
        _mapping(existing_user.get("user")).get("token") if existing_user else None
    )
    if (
        ident.bearer is not None
        and on_disk_bearer is not None
        and on_disk_bearer != ident.bearer
    ):
        return RemoveOutcome.FOREIGN_KEPT

    # Drop our context object(s) by identity — a foreign same-named context stays.
    _remove_where(contexts, lambda ctx: any(ctx is o for o in ours))
    # Drop the cluster/user only if no remaining context still references them (a real
    # context may legitimately share the name, e.g. the common `kubernetes-admin` user).
    still_used_clusters = {
        _mapping(ctx.get("context")).get("cluster")
        for ctx in contexts
        if isinstance(ctx, dict)
    }
    still_used_users = {
        _mapping(ctx.get("context")).get("user")
        for ctx in contexts
        if isinstance(ctx, dict)
    }
    if ident.cluster_name not in still_used_clusters:
        _remove_where(
            _named_list(doc, "clusters"),
            lambda c: _same_name(c, ident.cluster_name),
        )
    if ident.user_name not in still_used_users:
        _remove_where(
            _named_list(doc, "users"), lambda u: _same_name(u, ident.user_name)
        )
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
