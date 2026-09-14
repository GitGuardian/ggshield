"""Tests for provider definitions and their build-time vendoring."""

from pathlib import Path

import pytest

from gitguardian import Provider, SecretError
from gitguardian._definition import ProviderDef

REPO_ROOT = Path(__file__).resolve().parents[3]


def test_every_provider_has_a_loadable_definition():
    for provider in Provider:
        definition = ProviderDef.from_yaml(provider.definition_text())
        assert definition.name == provider.value


def test_bundled_definitions_match_the_repo_contract():
    """providers/*.yaml (repo root) is the single source; the build hook
    vendors it into the package verbatim. Guards that the vendored copy is a
    faithful, untransformed copy of the source."""
    repo_providers = REPO_ROOT / "providers"
    if not repo_providers.is_dir():
        pytest.skip("not running from the repository checkout")
    bundled = Path(__file__).resolve().parents[1] / "src" / "gitguardian" / "providers"
    for repo_file in repo_providers.glob("*.yaml"):
        assert (bundled / repo_file.name).read_text() == repo_file.read_text(), (
            f"{repo_file.name} not vendored from providers/; run `uv sync`"
        )


def test_unknown_definition_keys_are_rejected():
    with pytest.raises(SecretError, match="unknown provider definition keys"):
        ProviderDef.from_yaml(
            "name: x\nbase_url: y\nauth: {strategy: token, token_env: T}\nbogus: 1\n"
        )


def test_provider_enum_identity():
    assert Provider.ONEPASSWORD == Provider.ONEPASSWORD
    assert Provider.VAULT == Provider.VAULT
    assert {Provider.ONEPASSWORD: "ok"}[Provider.ONEPASSWORD] == "ok"
    assert {Provider.VAULT: "ok"}[Provider.VAULT] == "ok"
