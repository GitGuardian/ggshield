from unittest.mock import patch

import pytest

from ggshield.verticals.hmsl.secret_manager.hashicorp_vault.api_client import (
    VaultAPIClient,
)
from ggshield.verticals.hmsl.secret_manager.hashicorp_vault.exceptions import (
    VaultForbiddenItemError,
    VaultNotFoundItemError,
    VaultPathIsNotADirectoryError,
)
from ggshield.verticals.hmsl.secret_manager.hashicorp_vault.models import (
    VaultKvMount,
    VaultSecrets,
)
from tests.unit.conftest import my_vcr


@pytest.fixture(scope="module")
def vault_api_client():
    """
    Get a Vault API client with all rights.
    """
    return VaultAPIClient(
        vault_url="http://localhost:8200",
        api_token="my_vault_token",  # as defined in scripts/hmsl/hashicorp_vault.py
    )


@pytest.fixture(scope="module")
def restricted_vault_api_client():
    """
    Get a Vault API client with restricted permissions
    """
    return VaultAPIClient(
        vault_url="http://localhost:8200",
        api_token="restricted_token",  # as defined in scripts/hmsl/hashicorp_vault.py
    )


@my_vcr.use_cassette(
    "test_hmsl_secret_manager_hashicorp_vault_get_kv_mounts_api_endpoint.yaml",
    ignore_localhost=False,
)
def test_get_kv_mounts_api_endpoint(vault_api_client):
    """
    GIVEN a Vault instance and an API client
    WHEN calling get_kv_mounts
    THEN I get all the kv mounts of this instance
    """
    kv_mounts = list(vault_api_client.get_kv_mounts())

    assert kv_mounts == [
        VaultKvMount(name="secret", version="2"),
        VaultKvMount(name="secret_v1", version="1"),
    ]


@pytest.mark.parametrize(
    "vault_path, expected_results",
    [
        ("", ["b2b", "b2c"]),
        ("b2b", ["web_app", "worker"]),
        ("b2b/worker", ["config.env"]),
        ("b2b/web_app", ["config.env", "prod"]),
        ("b2c", ["web_app", "worker"]),
        ("b2c/worker", ["config.env"]),
        ("b2c/web_app", ["config.env", "prod"]),
        ("/b2b", ["web_app", "worker"]),
        ("/b2b/worker", ["config.env"]),
        ("/b2b/web_app", ["config.env", "prod"]),
        ("/b2c", ["web_app", "worker"]),
        ("/b2c/worker", ["config.env"]),
        ("/b2c/web_app", ["config.env", "prod"]),
    ],
)
def test_list_kv_items_v1(vault_api_client, vault_path, expected_results):
    """
    GIVEN a Vault instance and an API client
    WHEN calling list_kv_items on a v1 mount
    THEN I get all the items
    """
    kv_mount = VaultKvMount(name="secret_v1", version="1")

    with my_vcr.use_cassette(
        f"test_hmsl_secret_manager_hashicorp_vault_list_kv_items_v1_{vault_path.replace('/', '_')}.yaml",
        ignore_localhost=False,
    ):
        kv_items = list(vault_api_client.list_kv_items(kv_mount, vault_path))

    assert kv_items == expected_results


@my_vcr.use_cassette(
    "test_hmsl_secret_manager_hashicorp_vault_list_kv_items_not_a_directory.yaml",
    ignore_localhost=False,
)
def test_list_kv_items_not_a_directory(vault_api_client):
    """
    GIVEN a Vault instance and an API client
    WHEN calling list_kv_items with a path that is actually a file
    THEN VaultPathIsNotADirectoryError is raised
    """
    kv_mount = VaultKvMount(name="secret", version="2")

    with pytest.raises(VaultPathIsNotADirectoryError):
        vault_api_client.list_kv_items(kv_mount, "b2c/worker/config.env")


@my_vcr.use_cassette(
    "test_hmsl_secret_manager_hashicorp_vault_list_kv_items_forbidden.yaml",
    ignore_localhost=False,
)
def test_list_kv_items_forbidden(restricted_vault_api_client):
    """
    GIVEN a Vault instance and an API client
    WHEN calling list_kv_items on a path you don't have access to
    THEN VaultForbiddenItemError is raised
    """
    kv_mount = VaultKvMount(name="secret", version="2")

    with pytest.raises(VaultForbiddenItemError):
        restricted_vault_api_client.list_kv_items(kv_mount, "")


@pytest.mark.parametrize(
    "vault_path, expected_results",
    [
        ("", ["b2b", "b2c"]),
        ("b2b", ["web_app", "worker"]),
        ("b2b/worker", ["config.env"]),
        ("b2b/web_app", ["config.env", "prod"]),
        ("b2c", ["web_app", "worker"]),
        ("b2c/worker", ["config.env"]),
        ("b2c/web_app", ["config.env", "prod"]),
        ("/b2b", ["web_app", "worker"]),
        ("/b2b/worker", ["config.env"]),
        ("/b2b/web_app", ["config.env", "prod"]),
        ("/b2c", ["web_app", "worker"]),
        ("/b2c/worker", ["config.env"]),
        ("/b2c/web_app", ["config.env", "prod"]),
    ],
)
def test_list_kv_items_v2(vault_api_client, vault_path, expected_results):
    """
    GIVEN a Vault instance and an API client
    WHEN calling list_kv_items on a v2 mount
    THEN I get all the items
    """
    kv_mount = VaultKvMount(name="secret", version="2")

    with my_vcr.use_cassette(
        f"test_hmsl_secret_manager_hashicorp_vault_list_kv_items_v2_{vault_path.replace('/', '_')}.yaml",
        ignore_localhost=False,
    ):
        kv_items = list(vault_api_client.list_kv_items(kv_mount, vault_path))

    assert kv_items == expected_results


@pytest.mark.parametrize(
    "vault_path, expected_results",
    [
        (
            "b2b/web_app/prod/config.env",
            [("b2b/web_app/prod/config.env/PROD_STUFF", "test")],
        ),
        (
            "b2b/worker/config.env",
            [
                ("b2b/worker/config.env/ANOTHER_PASSWORD", "my_secret_key"),
                ("b2b/worker/config.env/SECRET", "super_secret"),
            ],
        ),
    ],
)
def test_get_kv_secrets_v1(vault_api_client, vault_path, expected_results):
    """
    GIVEN a Vault instance and an API client
    WHEN calling get_kv_secrets on a v1 mount
    THEN I get all the expected secrets
    """
    kv_mount = VaultKvMount(name="secret_v1", version="1")

    with my_vcr.use_cassette(
        f"test_hmsl_secret_manager_hashicorp_vault_get_kv_secrets_v1_{vault_path.replace('/', '_')}.yaml",
        ignore_localhost=False,
    ):
        secrets = vault_api_client.get_kv_secrets(kv_mount, vault_path)

    assert secrets == expected_results


@pytest.mark.parametrize(
    "vault_path, expected_results",
    [
        (
            "b2b/web_app/prod/config.env",
            [("b2b/web_app/prod/config.env/PROD_STUFF", "test")],
        ),
        (
            "b2b/worker/config.env",
            [
                ("b2b/worker/config.env/ANOTHER_PASSWORD", "my_secret_key"),
                ("b2b/worker/config.env/SECRET", "super_secret"),
            ],
        ),
    ],
)
def test_get_kv_secrets_v2(vault_api_client, vault_path, expected_results):
    """
    GIVEN a Vault instance and an API client
    WHEN calling get_kv_secrets on a v2 mount
    THEN I get all the expected secrets
    """
    kv_mount = VaultKvMount(name="secret", version="2")

    with my_vcr.use_cassette(
        f"test_hmsl_secret_manager_hashicorp_vault_get_kv_secrets_v2_{vault_path.replace('/', '_')}.yaml",
        ignore_localhost=False,
    ):
        secrets = vault_api_client.get_kv_secrets(kv_mount, vault_path)

    assert secrets == expected_results


@my_vcr.use_cassette(
    "test_hmsl_secret_manager_hashicorp_vault_get_kv_secrets_not_found.yaml",
    ignore_localhost=False,
)
def test_get_kv_secrets_not_found(vault_api_client):
    """
    GIVEN a Vault instance and an API client
    WHEN calling get_kv_secrets with a path that doesn't exist
    THEN VaultNotFoundItemError is raised
    """
    kv_mount = VaultKvMount(name="secret", version="2")

    with pytest.raises(VaultNotFoundItemError):
        vault_api_client.get_kv_secrets(
            kv_mount, "these_are_not_the_secrets_you_are_looking_for.env"
        )


@my_vcr.use_cassette(
    "test_hmsl_secret_manager_hashicorp_vault_get_kv_secrets_forbidden.yaml",
    ignore_localhost=False,
)
def test_get_kv_secrets_forbidden(restricted_vault_api_client):
    """
    GIVEN a Vault instance and an API client
    WHEN calling get_kv_secrets on a path you don't have access to
    THEN VaultForbiddenItemError is raised
    """
    kv_mount = VaultKvMount(name="secret", version="2")

    with pytest.raises(VaultForbiddenItemError):
        restricted_vault_api_client.get_kv_secrets(kv_mount, "b2c/web_app/config.env")


def test_get_secrets_or_empty_success():
    """
    GIVEN a valid mount and path
    WHEN calling _get_secrets_or_empty
    THEN the secrets are returned
    """

    secrets = [("PASSWORD", "my_password"), ("SECRET_KEY", "my_secret_key")]
    with patch(
        "ggshield.verticals.hmsl.secret_manager.hashicorp_vault.api_client."
        "VaultAPIClient.get_kv_secrets",
        return_value=secrets,
    ):
        api_client = VaultAPIClient("vault_url", "vault_token")
        ret = api_client._get_secrets_or_empty(
            VaultKvMount(name="mount_name", version="2"), "my_path"
        )

        assert ret.secrets == secrets
        assert ret.not_fetched_paths == []


def test_get_secrets_or_empty_vault_not_found_item_error():
    """
    GIVEN a valid mount with a path that doesn't exist
    WHEN calling _get_secrets_or_empty
    THEN the inner exception is catched and no secrets are returned
    """

    with patch(
        "ggshield.verticals.hmsl.secret_manager.hashicorp_vault.api_client."
        "VaultAPIClient.get_kv_secrets",
        side_effect=VaultNotFoundItemError,
    ):
        api_client = VaultAPIClient("vault_url", "vault_token")
        ret = api_client._get_secrets_or_empty(
            VaultKvMount(name="mount_name", version="2"), "my_path"
        )

        assert ret.secrets == []
        assert ret.not_fetched_paths == ["my_path"]


def test_get_secrets_or_empty_vault_forbidden_item_error():
    """
    GIVEN a valid mount with a forbidden path
    WHEN calling _get_secrets_or_empty
    THEN the inner exception is catched and no secrets are returned
    """

    with patch(
        "ggshield.verticals.hmsl.secret_manager.hashicorp_vault.api_client."
        "VaultAPIClient.get_kv_secrets",
        side_effect=VaultForbiddenItemError,
    ):
        api_client = VaultAPIClient("vault_url", "vault_token")
        ret = api_client._get_secrets_or_empty(
            VaultKvMount(name="mount_name", version="2"), "my_path"
        )

        assert ret.secrets == []
        assert ret.not_fetched_paths == ["my_path"]


@pytest.mark.parametrize("recursive", [True, False])
def test_get_secrets_from_path_on_directory(recursive):
    """
    GIVEN a valid mount and path of a directory
    WHEN calling _get_secrets_from_path
    THEN the expected results are returned depending on if recursive was set
    """

    directories_res = ["prod", "dev"]
    api_client = VaultAPIClient("vault_url", "vault_token")
    mount = VaultKvMount(name="mount_name", version="2")

    # It's a recursive function, so copy the non-mocked function
    # first for the initial call
    api_client._get_secrets_from_path_not_mocked = api_client._get_secrets_from_path
    with patch(
        "ggshield.verticals.hmsl.secret_manager.hashicorp_vault.api_client."
        "VaultAPIClient._get_secrets_from_path",
    ):
        with patch(
            "ggshield.verticals.hmsl.secret_manager.hashicorp_vault.api_client."
            "VaultAPIClient.list_kv_items",
            return_value=directories_res,
        ):
            ret = api_client._get_secrets_from_path_not_mocked(
                mount, "my_path", recursive
            )

            if not recursive:
                assert ret == VaultSecrets(secrets=[], not_fetched_paths=[])
            else:
                api_client.list_kv_items.assert_called_once_with(mount, "my_path")
                assert api_client._get_secrets_from_path.call_count == 2
                assert api_client._get_secrets_from_path.call_args_list[0][0] == (
                    mount,
                    "my_path/prod",
                    True,
                )
                assert api_client._get_secrets_from_path.call_args_list[1][0] == (
                    VaultKvMount(name="mount_name", version="2"),
                    "my_path/dev",
                    True,
                )


@pytest.mark.parametrize("recursive", [True, False])
def test_get_secrets_from_path_on_file(recursive):
    """
    GIVEN a valid mount and path of a file
    WHEN calling _get_secrets_from_path
    THEN the expected results are returned and recursive parameter has no effect
    """

    secrets_res = VaultSecrets(secrets=[("PASSWORD", "test")], not_fetched_paths=[])
    api_client = VaultAPIClient("vault_url", "vault_token")
    mount = VaultKvMount(name="mount_name", version="2")
    vault_path = "my_path"

    with patch(
        "ggshield.verticals.hmsl.secret_manager.hashicorp_vault.api_client."
        "VaultAPIClient.list_kv_items",
        side_effect=VaultPathIsNotADirectoryError,
    ):
        with patch(
            "ggshield.verticals.hmsl.secret_manager.hashicorp_vault.api_client."
            "VaultAPIClient._get_secrets_or_empty",
            return_value=secrets_res,
        ):
            returned_secrets = api_client._get_secrets_from_path(
                mount, vault_path, recursive
            )

            api_client.list_kv_items.assert_called_once_with(mount, vault_path)
            api_client._get_secrets_or_empty.assert_called_once_with(mount, vault_path)
            assert returned_secrets == secrets_res


@pytest.mark.parametrize("recursive", [True, False])
def test_get_secrets_on_file(recursive):
    """
    GIVEN a valid mount and path of a file
    WHEN calling get_secrets
    THEN we directly return with the secrets of the file and recursive parameter has no effect
    """

    secrets = [
        ("DATABASE_PASSWORD", "my_password"),
        ("ADMIN_PASSWORD", "another_password"),
    ]
    mount = VaultKvMount(name="test", version="2")
    api_client = VaultAPIClient("my_vault_url", "my_vault_token")
    vault_path = "dev/env"

    with patch(
        "ggshield.verticals.hmsl.secret_manager.hashicorp_vault.api_client."
        "VaultAPIClient.list_kv_items",
        side_effect=VaultPathIsNotADirectoryError,
    ):
        with patch(
            "ggshield.verticals.hmsl.secret_manager.hashicorp_vault.api_client."
            "VaultAPIClient._get_secrets_or_empty",
            return_value=VaultSecrets(secrets=secrets, not_fetched_paths=[]),
        ):
            returned_secrets = api_client.get_secrets(mount, vault_path, recursive)
            api_client._get_secrets_or_empty.assert_called_once_with(mount, vault_path)

            assert returned_secrets.secrets == secrets
            assert returned_secrets.not_fetched_paths == []


@pytest.mark.parametrize("recursive", [True, False])
def test_get_secrets_on_directory(recursive):
    """
    GIVEN a valid mount and path of a directory
    WHEN calling get_secrets
    THEN _get_secrets_from_path is called with the correct parameters
    """

    directories = ["dev", "prod", "sandbox"]
    mount = VaultKvMount(name="test", version="2")
    api_client = VaultAPIClient("my_vault_url", "my_vault_token")
    vault_path = ""

    with patch(
        "ggshield.verticals.hmsl.secret_manager.hashicorp_vault.api_client."
        "VaultAPIClient.list_kv_items",
        return_value=directories,
    ):
        with patch(
            "ggshield.verticals.hmsl.secret_manager.hashicorp_vault.api_client."
            "VaultAPIClient._get_secrets_from_path",
            side_effect=lambda _, called_path, __: VaultSecrets(
                secrets=[
                    (
                        f"PASSWORD_{called_path}",
                        "my_password",
                    )
                ],
                not_fetched_paths=[],
            ),
        ):
            returned_secrets = api_client.get_secrets(mount, vault_path, recursive)

            api_client.list_kv_items.assert_called_once_with(mount, vault_path)
            assert api_client._get_secrets_from_path.call_count == 3

            assert api_client._get_secrets_from_path.call_args_list[0][0] == (
                mount,
                "dev",
                recursive,
            )
            assert api_client._get_secrets_from_path.call_args_list[1][0] == (
                mount,
                "prod",
                recursive,
            )
            assert api_client._get_secrets_from_path.call_args_list[2][0] == (
                mount,
                "sandbox",
                recursive,
            )
            assert returned_secrets.secrets == [
                ("PASSWORD_dev", "my_password"),
                ("PASSWORD_prod", "my_password"),
                ("PASSWORD_sandbox", "my_password"),
            ]
