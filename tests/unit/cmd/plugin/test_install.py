"""
Tests for the enterprise install command.
"""

from contextlib import contextmanager
from pathlib import Path
from unittest import mock

from ggshield.__main__ import cli
from ggshield.cmd.plugin.install import detect_source_type
from ggshield.core.errors import ExitCode
from ggshield.core.plugin.client import (
    PluginCatalog,
    PluginDownloadInfo,
    PluginInfo,
    PluginSourceType,
)


class TestPluginInstall:
    """Tests for 'ggshield plugin install' command."""

    def test_install_requires_plugin_source(self, cli_fs_runner):
        """
        GIVEN no plugin source
        WHEN running 'ggshield plugin install'
        THEN it shows a usage error
        """
        result = cli_fs_runner.invoke(cli, ["plugin", "install"])

        assert result.exit_code == ExitCode.USAGE_ERROR
        assert "PLUGIN_SOURCE" in result.output

    def test_install_single_plugin(self, cli_fs_runner):
        """
        GIVEN a plugin is available
        WHEN running 'ggshield plugin install <plugin>'
        THEN the plugin is downloaded and installed via streaming
        """
        mock_catalog = PluginCatalog(
            plugins=[
                PluginInfo(
                    name="tokenscanner",
                    display_name="Token Scanner",
                    description="Local secret scanning",
                    available=True,
                    latest_version="1.0.0",
                    reason=None,
                ),
            ],
        )
        mock_info = PluginDownloadInfo(
            filename="tokenscanner-1.0.0-py3-none-any.whl",
            sha256="abc123",
            version="1.0.0",
            size_bytes=100,
        )

        @contextmanager
        def fake_download_plugin(*args, **kwargs):
            yield mock_info, iter([b"wheel-data"])

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginAPIClient"
            ) as mock_plugin_api_client_class,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
        ):
            mock_create_client.return_value = mock.MagicMock()

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client.download_plugin = fake_download_plugin
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_downloader = mock.MagicMock()
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "install", "tokenscanner"],
                catch_exceptions=False,
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "Installing tokenscanner" in result.output
        assert "Installed tokenscanner v1.0.0" in result.output
        mock_downloader.download_and_install.assert_called_once()
        mock_plugin_api_client.report_installation.assert_called_once_with(
            "tokenscanner", "1.0.0", mock.ANY, mock.ANY
        )
        mock_config.enable_plugin.assert_called_once_with(
            "tokenscanner", version="1.0.0"
        )
        mock_config.save.assert_called_once()

    def test_install_platform_uses_entry_point_name_for_config_key(
        self, cli_fs_runner, tmp_path: Path
    ) -> None:
        """
        GIVEN a catalog reference (``machine-scan``) whose installed wheel
            exposes a divergent entry-point name (``machine_scan``)
        WHEN ``ggshield plugin install machine-scan`` succeeds via the
            platform flow
        THEN ``enable_plugin`` is called with the entry-point name —
            matching the loader's enablement key — so ``plugin list``
            shows the plugin enabled and the loader picks it up.
        """
        import zipfile

        installed_wheel = tmp_path / "satori_python-1.0.0-py3-none-any.whl"
        with zipfile.ZipFile(installed_wheel, "w") as zf:
            zf.writestr(
                "satori_python-1.0.0.dist-info/entry_points.txt",
                "[ggshield.plugins]\nmachine_scan = satori_python.plugin:Plugin\n",
            )

        mock_catalog = PluginCatalog(
            plugins=[
                PluginInfo(
                    name="machine-scan",
                    display_name="Machine Scan",
                    description="",
                    available=True,
                    latest_version="1.0.0",
                    reason=None,
                ),
            ],
        )
        mock_info = PluginDownloadInfo(
            filename="satori_python-1.0.0-py3-none-any.whl",
            sha256="a" * 64,
            version="1.0.0",
            size_bytes=100,
        )

        @contextmanager
        def fake_download_plugin(*args, **kwargs):
            yield mock_info, iter([b"wheel-data"])

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginAPIClient"
            ) as mock_plugin_api_client_class,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
        ):
            mock_create_client.return_value = mock.MagicMock()

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client.download_plugin = fake_download_plugin
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_downloader = mock.MagicMock()
            mock_downloader.download_and_install.return_value = installed_wheel
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "install", "machine-scan"],
                catch_exceptions=False,
            )

        assert result.exit_code == ExitCode.SUCCESS
        mock_config.enable_plugin.assert_called_once_with(
            "machine_scan", version="1.0.0"
        )

    def test_install_warn_mode_continues_when_signature_bundle_fails(
        self, cli_fs_runner
    ):
        """
        GIVEN --allow-unsigned and a backend whose signature proxy 5xxs
        WHEN running 'ggshield plugin install <plugin> --allow-unsigned'
        THEN the install still succeeds; bundle_bytes is None and a
        warning is surfaced.

        The bundle fetch failing here is a server issue, not user input;
        the user already opted out of strict signature verification by
        passing --allow-unsigned, so refusing to install an otherwise
        valid wheel because of an unrelated proxy outage is wrong.
        """
        from ggshield.core.plugin.client import PluginAPIError

        mock_catalog = PluginCatalog(
            plugins=[
                PluginInfo(
                    name="tokenscanner",
                    display_name="Token Scanner",
                    description="Local secret scanning",
                    available=True,
                    latest_version="1.0.0",
                    reason=None,
                ),
            ],
        )
        mock_info = PluginDownloadInfo(
            filename="tokenscanner-1.0.0-py3-none-any.whl",
            sha256="abc123",
            version="1.0.0",
            size_bytes=100,
            signature_url="https://api.example/v1/.../signature",
        )

        @contextmanager
        def fake_download_plugin(*args, **kwargs):
            yield mock_info, iter([b"wheel-data"])

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginAPIClient"
            ) as mock_plugin_api_client_class,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
        ):
            mock_create_client.return_value = mock.MagicMock()

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client.download_plugin = fake_download_plugin
            mock_plugin_api_client.download_signature_bundle.side_effect = (
                PluginAPIError("upstream 500")
            )
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_downloader = mock.MagicMock()
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "install", "tokenscanner", "--allow-unsigned"],
                catch_exceptions=False,
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "Installed tokenscanner v1.0.0" in result.output
        assert "Could not fetch signature bundle" in result.output
        mock_downloader.download_and_install.assert_called_once()
        # bundle_bytes must have been None — STRICT would have re-raised
        # before this call.
        kwargs = mock_downloader.download_and_install.call_args.kwargs
        assert kwargs["bundle_bytes"] is None

    def test_install_strict_mode_fails_when_signature_bundle_fails(self, cli_fs_runner):
        """
        GIVEN strict signature verification (default) and a broken
              signature URL on the catalog response
        WHEN running 'ggshield plugin install <plugin>'
        THEN the install aborts; the wheel is never written.
        """
        from ggshield.core.plugin.client import PluginAPIError

        mock_catalog = PluginCatalog(
            plugins=[
                PluginInfo(
                    name="tokenscanner",
                    display_name="Token Scanner",
                    description="Local secret scanning",
                    available=True,
                    latest_version="1.0.0",
                    reason=None,
                ),
            ],
        )
        mock_info = PluginDownloadInfo(
            filename="tokenscanner-1.0.0-py3-none-any.whl",
            sha256="abc123",
            version="1.0.0",
            size_bytes=100,
            signature_url="https://api.example/v1/.../signature",
        )

        @contextmanager
        def fake_download_plugin(*args, **kwargs):
            yield mock_info, iter([b"wheel-data"])

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginAPIClient"
            ) as mock_plugin_api_client_class,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
        ):
            mock_create_client.return_value = mock.MagicMock()

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client.download_plugin = fake_download_plugin
            mock_plugin_api_client.download_signature_bundle.side_effect = (
                PluginAPIError("upstream 500")
            )
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_downloader = mock.MagicMock()
            mock_downloader_class.return_value = mock_downloader

            mock_config_class.load.return_value = mock.MagicMock()

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "install", "tokenscanner"],
                catch_exceptions=False,
            )

        assert result.exit_code != ExitCode.SUCCESS
        mock_downloader.download_and_install.assert_not_called()

    def test_install_plugins_not_enabled(self, cli_fs_runner):
        """
        GIVEN the platform has plugins disabled (feature flag OFF)
        WHEN running 'ggshield plugin install tokenscanner'
        THEN it shows a clean error message about workspace configuration
        """
        from ggshield.core.plugin.client import PluginsNotEnabledError

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginAPIClient"
            ) as mock_plugin_api_client_class,
        ):
            mock_create_client.return_value = mock.MagicMock()
            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.side_effect = (
                PluginsNotEnabledError()
            )
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            result = cli_fs_runner.invoke(cli, ["plugin", "install", "tokenscanner"])

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "not available" in result.output.lower()
        assert "administrator" in result.output.lower()

    def test_install_calls_report_installation_after_success(self, cli_fs_runner):
        """
        GIVEN a successful plugin install
        WHEN running 'ggshield plugin install tokenscanner'
        THEN report_installation is called (best-effort analytics)
        """
        mock_catalog = PluginCatalog(
            plugins=[
                PluginInfo(
                    name="tokenscanner",
                    display_name="Token Scanner",
                    description="Local secret scanning",
                    available=True,
                    latest_version="1.0.0",
                    reason=None,
                ),
            ],
        )
        mock_info = PluginDownloadInfo(
            filename="tokenscanner-1.0.0-py3-none-any.whl",
            sha256="abc123",
            version="1.0.0",
            size_bytes=100,
        )

        @contextmanager
        def fake_download_plugin(*args, **kwargs):
            yield mock_info, iter([b""])

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginAPIClient"
            ) as mock_plugin_api_client_class,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
        ):
            mock_create_client.return_value = mock.MagicMock()

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client.download_plugin = fake_download_plugin
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_downloader = mock.MagicMock()
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "install", "tokenscanner"],
                catch_exceptions=False,
            )

        assert result.exit_code == ExitCode.SUCCESS
        mock_plugin_api_client.report_installation.assert_called_once_with(
            "tokenscanner", "1.0.0", mock.ANY, mock.ANY
        )

    def test_install_unavailable_plugin(self, cli_fs_runner):
        """
        GIVEN a plugin exists but is not available
        WHEN running 'ggshield plugin install <plugin>'
        THEN it shows an error with reason
        """
        mock_catalog = PluginCatalog(
            plugins=[
                PluginInfo(
                    name="tokenscanner",
                    display_name="Token Scanner",
                    description="Local secret scanning",
                    available=False,
                    latest_version="1.0.0",
                    reason="Requires Business plan",
                ),
            ],
        )

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginAPIClient"
            ) as mock_plugin_api_client_class,
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            result = cli_fs_runner.invoke(cli, ["plugin", "install", "tokenscanner"])

        assert result.exit_code == ExitCode.USAGE_ERROR
        assert "not available" in result.output
        assert "Requires Business plan" in result.output

    def test_install_unknown_plugin(self, cli_fs_runner):
        """
        GIVEN a plugin does not exist
        WHEN running 'ggshield plugin install <plugin>'
        THEN it shows an error
        """
        mock_catalog = PluginCatalog(
            plugins=[],
        )

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginAPIClient"
            ) as mock_plugin_api_client_class,
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            result = cli_fs_runner.invoke(cli, ["plugin", "install", "nonexistent"])

        assert result.exit_code == ExitCode.USAGE_ERROR
        assert "Unknown plugin" in result.output
        assert "ggshield plugin status" in result.output

    def test_install_with_version(self, cli_fs_runner):
        """
        GIVEN a plugin is available
        WHEN running 'ggshield plugin install <plugin> --version X.Y.Z'
        THEN the specified version is requested
        """
        mock_catalog = PluginCatalog(
            plugins=[
                PluginInfo(
                    name="tokenscanner",
                    display_name="Token Scanner",
                    description="Local secret scanning",
                    available=True,
                    latest_version="2.0.0",
                    reason=None,
                ),
            ],
        )
        mock_info = PluginDownloadInfo(
            filename="tokenscanner-1.5.0-py3-none-any.whl",
            sha256="abc123",
            version="1.5.0",
            size_bytes=100,
        )
        captured_kwargs: dict = {}

        @contextmanager
        def fake_download_plugin(*args, **kwargs):
            captured_kwargs.update(kwargs)
            yield mock_info, iter([b""])

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginAPIClient"
            ) as mock_plugin_api_client_class,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
        ):
            mock_create_client.return_value = mock.MagicMock()

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client.download_plugin = fake_download_plugin
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_downloader = mock.MagicMock()
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "install", "tokenscanner", "--version", "1.5.0"],
                catch_exceptions=False,
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert captured_kwargs.get("version") == "1.5.0"

    def test_install_download_error(self, cli_fs_runner):
        """
        GIVEN downloading a plugin fails
        WHEN running 'ggshield plugin install <plugin>'
        THEN it shows an error
        """
        from ggshield.core.plugin.downloader import DownloadError

        mock_catalog = PluginCatalog(
            plugins=[
                PluginInfo(
                    name="tokenscanner",
                    display_name="Token Scanner",
                    description="Local secret scanning",
                    available=True,
                    latest_version="1.0.0",
                    reason=None,
                ),
            ],
        )

        mock_info = PluginDownloadInfo(
            filename="tokenscanner-1.0.0-py3-none-any.whl",
            sha256="abc123",
            version="1.0.0",
            size_bytes=100,
        )

        @contextmanager
        def fake_download_plugin(*args, **kwargs):
            yield mock_info, iter([b""])

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginAPIClient"
            ) as mock_plugin_api_client_class,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
        ):
            mock_create_client.return_value = mock.MagicMock()

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client.download_plugin = fake_download_plugin
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_downloader = mock.MagicMock()
            mock_downloader.download_and_install.side_effect = DownloadError(
                "Network error"
            )
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(cli, ["plugin", "install", "tokenscanner"])

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "Failed to install tokenscanner" in result.output
        assert "Network error" in result.output

    def test_install_api_error(self, cli_fs_runner):
        """
        GIVEN the API returns an error
        WHEN running 'ggshield plugin install <plugin>'
        THEN it shows an error
        """
        from ggshield.core.plugin.client import PluginAPIError

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginAPIClient"
            ) as mock_plugin_api_client_class,
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.side_effect = PluginAPIError(
                "API error"
            )
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            result = cli_fs_runner.invoke(cli, ["plugin", "install", "tokenscanner"])

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "API error" in result.output

    def test_install_connection_error(self, cli_fs_runner):
        """
        GIVEN connection to GitGuardian fails
        WHEN running 'ggshield plugin install <plugin>'
        THEN it shows an error
        """
        with (
            mock.patch(
                "ggshield.cmd.plugin.install.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginAPIClient"
            ) as mock_plugin_api_client_class,
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.side_effect = Exception(
                "Connection refused"
            )
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            result = cli_fs_runner.invoke(cli, ["plugin", "install", "tokenscanner"])

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "Failed to connect to GitGuardian" in result.output

    def test_install_plugin_not_available_error(self, cli_fs_runner):
        """
        GIVEN downloading raises PluginNotAvailableError
        WHEN running 'ggshield plugin install <plugin>'
        THEN it shows an error
        """
        from ggshield.core.plugin.client import PluginNotAvailableError

        mock_catalog = PluginCatalog(
            plugins=[
                PluginInfo(
                    name="tokenscanner",
                    display_name="Token Scanner",
                    description="Local secret scanning",
                    available=True,
                    latest_version="1.0.0",
                    reason=None,
                ),
            ],
        )

        @contextmanager
        def fake_download_plugin(*args, **kwargs):
            raise PluginNotAvailableError("tokenscanner", "Version not found")
            yield  # make it a generator

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginAPIClient"
            ) as mock_plugin_api_client_class,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
        ):
            mock_create_client.return_value = mock.MagicMock()

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client.download_plugin = fake_download_plugin
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_downloader = mock.MagicMock()
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(cli, ["plugin", "install", "tokenscanner"])

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "Failed to install tokenscanner" in result.output

    def test_install_generic_error(self, cli_fs_runner):
        """
        GIVEN an unexpected error occurs during install
        WHEN running 'ggshield plugin install <plugin>'
        THEN it shows an error
        """
        mock_catalog = PluginCatalog(
            plugins=[
                PluginInfo(
                    name="tokenscanner",
                    display_name="Token Scanner",
                    description="Local secret scanning",
                    available=True,
                    latest_version="1.0.0",
                    reason=None,
                ),
            ],
        )
        mock_info = PluginDownloadInfo(
            filename="tokenscanner-1.0.0-py3-none-any.whl",
            sha256="abc123",
            version="1.0.0",
            size_bytes=100,
        )

        @contextmanager
        def fake_download_plugin(*args, **kwargs):
            yield mock_info, iter([b""])

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginAPIClient"
            ) as mock_plugin_api_client_class,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
        ):
            mock_create_client.return_value = mock.MagicMock()

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client.download_plugin = fake_download_plugin
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_downloader = mock.MagicMock()
            mock_downloader.download_and_install.side_effect = Exception(
                "Unexpected error"
            )
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(cli, ["plugin", "install", "tokenscanner"])

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "Failed to install tokenscanner" in result.output

    def test_install_unavailable_plugin_without_reason(self, cli_fs_runner):
        """
        GIVEN a plugin exists but is not available (without reason)
        WHEN running 'ggshield plugin install <plugin>'
        THEN it shows an error without reason
        """
        mock_catalog = PluginCatalog(
            plugins=[
                PluginInfo(
                    name="tokenscanner",
                    display_name="Token Scanner",
                    description="Local secret scanning",
                    available=False,
                    latest_version="1.0.0",
                    reason=None,
                ),
            ],
        )

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginAPIClient"
            ) as mock_plugin_api_client_class,
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            result = cli_fs_runner.invoke(cli, ["plugin", "install", "tokenscanner"])

        assert result.exit_code == ExitCode.USAGE_ERROR
        assert "not available" in result.output
        # Should not show "Reason:" when reason is None
        assert "Reason:" not in result.output


class TestDetectSourceType:
    """Tests for detect_source_type function."""

    def test_detect_github_artifact(self) -> None:
        """Test detection of GitHub artifact URLs."""
        url = "https://github.com/owner/repo/actions/runs/123456/artifacts/789"
        assert detect_source_type(url) == PluginSourceType.GITHUB_ARTIFACT

    def test_detect_github_release(self) -> None:
        """Test detection of GitHub release URLs."""
        url = "https://github.com/owner/repo/releases/download/v1.0.0/plugin.whl"
        assert detect_source_type(url) == PluginSourceType.GITHUB_RELEASE

    def test_detect_generic_url(self) -> None:
        """Test detection of generic HTTPS URLs."""
        assert (
            detect_source_type("https://example.com/plugin.whl") == PluginSourceType.URL
        )
        assert (
            detect_source_type("https://pypi.org/packages/plugin.whl")
            == PluginSourceType.URL
        )

    def test_detect_http_url(self) -> None:
        """Test detection of HTTP URLs (will be rejected later)."""
        assert (
            detect_source_type("http://example.com/plugin.whl") == PluginSourceType.URL
        )

    def test_detect_local_file(self, tmp_path: Path) -> None:
        """Test detection of local wheel files."""
        wheel_path = tmp_path / "plugin.whl"
        wheel_path.touch()
        assert detect_source_type(str(wheel_path)) == PluginSourceType.LOCAL_FILE

    def test_detect_local_file_nonexistent(self) -> None:
        """Test non-existent local wheel paths are treated as local sources."""
        assert detect_source_type("./nonexistent.whl") == PluginSourceType.LOCAL_FILE

    def test_detect_plugin_name(self) -> None:
        """Test plugin names default to GitGuardian API."""
        assert detect_source_type("tokenscanner") == PluginSourceType.PLATFORM
        assert detect_source_type("my-plugin") == PluginSourceType.PLATFORM


class TestInstallFromLocalWheel:
    """Tests for installing from local wheel files."""

    def test_install_local_wheel_success(self, cli_fs_runner, tmp_path: Path) -> None:
        """
        GIVEN a valid local wheel file
        WHEN running 'ggshield plugin install <path>'
        THEN the plugin is installed from the wheel
        """
        wheel_path = tmp_path / "myplugin-1.0.0.whl"
        wheel_path.touch()

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch(
                "ggshield.cmd.plugin.install.detect_source_type",
                return_value=PluginSourceType.LOCAL_FILE,
            ),
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.install_from_wheel.return_value = (
                "myplugin",
                "1.0.0",
                wheel_path,
            )
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "install", str(wheel_path)],
                catch_exceptions=False,
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "Installed myplugin v1.0.0" in result.output
        mock_downloader.install_from_wheel.assert_called_once()
        mock_config.enable_plugin.assert_called_once_with("myplugin", version="1.0.0")

    def test_install_local_wheel_uses_entry_point_name_for_config_key(
        self, cli_fs_runner, tmp_path: Path
    ) -> None:
        """The config key must match the ggshield.plugins entry point name."""
        import zipfile

        wheel_path = tmp_path / "package_name-1.0.0-py3-none-any.whl"
        with zipfile.ZipFile(wheel_path, "w") as zf:
            zf.writestr(
                "package_name-1.0.0.dist-info/entry_points.txt",
                "[ggshield.plugins]\nmy_plugin = package_name.plugin:Plugin\n",
            )

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch(
                "ggshield.cmd.plugin.install.detect_source_type",
                return_value=PluginSourceType.LOCAL_FILE,
            ),
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.install_from_wheel.return_value = (
                "package-name",
                "1.0.0",
                wheel_path,
            )
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "install", str(wheel_path)],
                catch_exceptions=False,
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "Installed my_plugin v1.0.0" in result.output
        mock_config.remove_plugin.assert_called_once_with("package-name")
        mock_config.enable_plugin.assert_called_once_with("my_plugin", version="1.0.0")

    def test_install_local_wheel_entry_point_matches_package_name(
        self, cli_fs_runner, tmp_path: Path
    ) -> None:
        """When the entry-point name matches the package name, do not remove the config."""
        wheel_path = tmp_path / "myplugin-1.0.0.whl"
        wheel_path.touch()
        installed_wheel_path = tmp_path / "plugins" / "myplugin" / wheel_path.name

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch(
                "ggshield.cmd.plugin.install.detect_source_type",
                return_value=PluginSourceType.LOCAL_FILE,
            ),
            mock.patch(
                "ggshield.core.plugin.loader.read_entry_point_from_wheel",
                return_value=("myplugin", "myplugin.plugin:Plugin"),
            ),
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.install_from_wheel.return_value = (
                "myplugin",
                "1.0.0",
                installed_wheel_path,
            )
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "install", str(wheel_path)],
                catch_exceptions=False,
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "Installed myplugin v1.0.0" in result.output
        mock_config.remove_plugin.assert_not_called()
        mock_config.enable_plugin.assert_called_once_with("myplugin", version="1.0.0")

    def test_install_local_wheel_without_entry_point_falls_back_to_package_name(
        self, cli_fs_runner, tmp_path: Path
    ) -> None:
        """If the wheel has no ggshield.plugins entry point, use the package name."""
        wheel_path = tmp_path / "myplugin-1.0.0.whl"
        wheel_path.touch()
        installed_wheel_path = tmp_path / "plugins" / "myplugin" / wheel_path.name

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch(
                "ggshield.cmd.plugin.install.detect_source_type",
                return_value=PluginSourceType.LOCAL_FILE,
            ),
            mock.patch(
                "ggshield.core.plugin.loader.read_entry_point_from_wheel",
                return_value=None,
            ),
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.install_from_wheel.return_value = (
                "myplugin",
                "1.0.0",
                installed_wheel_path,
            )
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "install", str(wheel_path)],
                catch_exceptions=False,
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "Installed myplugin v1.0.0" in result.output
        mock_config.remove_plugin.assert_not_called()
        mock_config.enable_plugin.assert_called_once_with("myplugin", version="1.0.0")


class TestInstallFromUrl:
    """Tests for installing from URLs."""

    def test_install_url_with_sha256(self, cli_fs_runner) -> None:
        """
        GIVEN a URL with SHA256 checksum
        WHEN running 'ggshield plugin install <url> --sha256 <hash>'
        THEN the plugin is downloaded and verified
        """
        with (
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch(
                "ggshield.cmd.plugin.install.detect_source_type",
                return_value=PluginSourceType.URL,
            ),
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.download_from_url.return_value = (
                "urlplugin",
                "2.0.0",
                Path("/fake/path.whl"),
            )
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(
                cli,
                [
                    "plugin",
                    "install",
                    "https://example.com/plugin.whl",
                    "--sha256",
                    "abc123",
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "Installed urlplugin v2.0.0" in result.output
        mock_downloader.download_from_url.assert_called_once_with(
            "https://example.com/plugin.whl",
            "abc123",
            signature_mode=mock.ANY,
        )

    def test_install_url_warning_no_sha256(self, cli_fs_runner) -> None:
        """
        GIVEN a URL without SHA256 checksum
        WHEN running 'ggshield plugin install <url>' without --force
        THEN a warning about missing checksum is displayed
        """
        with (
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch(
                "ggshield.cmd.plugin.install.detect_source_type",
                return_value=PluginSourceType.URL,
            ),
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.download_from_url.return_value = (
                "urlplugin",
                "2.0.0",
                Path("/fake/path.whl"),
            )
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "install", "https://example.com/plugin.whl"],
                catch_exceptions=False,
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "Installed urlplugin v2.0.0" in result.output

    def test_install_http_url_rejected(self, cli_fs_runner) -> None:
        """
        GIVEN an HTTP URL (not HTTPS)
        WHEN running 'ggshield plugin install <url>'
        THEN the install fails with security error
        """
        from ggshield.core.plugin.downloader import InsecureSourceError

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch(
                "ggshield.cmd.plugin.install.detect_source_type",
                return_value=PluginSourceType.URL,
            ),
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.download_from_url.side_effect = InsecureSourceError(
                "HTTP URLs are not allowed"
            )
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "install", "http://example.com/plugin.whl"],
            )

        assert result.exit_code == ExitCode.USAGE_ERROR
        assert "HTTP URLs are not allowed" in result.output


class TestInstallFromGitHubRelease:
    """Tests for installing from GitHub releases."""

    def test_install_github_release(self, cli_fs_runner) -> None:
        """
        GIVEN a GitHub release URL
        WHEN running 'ggshield plugin install <url>'
        THEN the plugin is installed from the release
        """
        with (
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch(
                "ggshield.cmd.plugin.install.detect_source_type",
                return_value=PluginSourceType.GITHUB_RELEASE,
            ),
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.download_from_github_release.return_value = (
                "ghplugin",
                "1.5.0",
                Path("/fake/path.whl"),
            )
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(
                cli,
                [
                    "plugin",
                    "install",
                    "https://github.com/owner/repo/releases/download/v1.5.0/plugin.whl",
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "Installed ghplugin v1.5.0" in result.output


class TestInstallFromGitHubArtifact:
    """Tests for installing from GitHub Actions artifacts."""

    def test_install_github_artifact(self, cli_fs_runner) -> None:
        """
        GIVEN a GitHub artifact URL
        WHEN running 'ggshield plugin install <url>'
        THEN the plugin is installed from the artifact
        """
        with (
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch(
                "ggshield.cmd.plugin.install.detect_source_type",
                return_value=PluginSourceType.GITHUB_ARTIFACT,
            ),
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.download_from_github_artifact.return_value = (
                "artifactplugin",
                "0.1.0",
                Path("/fake/path.whl"),
            )
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(
                cli,
                [
                    "plugin",
                    "install",
                    "https://github.com/owner/repo/actions/runs/123/artifacts/456",
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "Installed artifactplugin v0.1.0" in result.output

    def test_install_github_artifact_warning(self, cli_fs_runner) -> None:
        """
        GIVEN a GitHub artifact URL without --force
        WHEN running 'ggshield plugin install <url>'
        THEN a warning about ephemeral artifacts is displayed
        """
        with (
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch(
                "ggshield.cmd.plugin.install.detect_source_type",
                return_value=PluginSourceType.GITHUB_ARTIFACT,
            ),
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.download_from_github_artifact.return_value = (
                "artifactplugin",
                "0.1.0",
                Path("/fake/path.whl"),
            )
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(
                cli,
                [
                    "plugin",
                    "install",
                    "https://github.com/owner/repo/actions/runs/123/artifacts/456",
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "ephemeral" in result.output.lower()

    def test_install_github_artifact_auth_error(self, cli_fs_runner) -> None:
        """
        GIVEN a GitHub artifact URL with missing authentication
        WHEN running 'ggshield plugin install <url>'
        THEN an authentication error is displayed
        """
        from ggshield.core.plugin.downloader import GitHubArtifactError

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch(
                "ggshield.cmd.plugin.install.detect_source_type",
                return_value=PluginSourceType.GITHUB_ARTIFACT,
            ),
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.download_from_github_artifact.side_effect = (
                GitHubArtifactError("GitHub authentication required")
            )
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(
                cli,
                [
                    "plugin",
                    "install",
                    "https://github.com/owner/repo/actions/runs/123/artifacts/456",
                ],
            )

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "GitHub authentication required" in result.output


class TestInstallErrorHandling:
    """Tests for error handling in various install scenarios."""

    def test_install_local_wheel_not_found(self, cli_fs_runner, tmp_path: Path) -> None:
        """
        GIVEN a non-existent wheel file path
        WHEN running 'ggshield plugin install <path>'
        THEN it shows a file not found error
        """
        wheel_path = tmp_path / "nonexistent.whl"

        with mock.patch(
            "ggshield.cmd.plugin.install.detect_source_type",
            return_value=PluginSourceType.LOCAL_FILE,
        ):
            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "install", str(wheel_path)],
            )

        assert result.exit_code == ExitCode.USAGE_ERROR
        assert "Wheel file not found" in result.output

    def test_install_local_wheel_download_error(
        self, cli_fs_runner, tmp_path: Path
    ) -> None:
        """
        GIVEN a local wheel file that fails to install
        WHEN running 'ggshield plugin install <path>'
        THEN it shows an error
        """
        from ggshield.core.plugin.downloader import DownloadError

        wheel_path = tmp_path / "broken.whl"
        wheel_path.touch()

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch("ggshield.cmd.plugin.install.EnterpriseConfig"),
            mock.patch(
                "ggshield.cmd.plugin.install.detect_source_type",
                return_value=PluginSourceType.LOCAL_FILE,
            ),
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.install_from_wheel.side_effect = DownloadError(
                "Invalid wheel"
            )
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "install", str(wheel_path)],
            )

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "Failed to install from wheel" in result.output

    def test_install_local_wheel_generic_error(
        self, cli_fs_runner, tmp_path: Path
    ) -> None:
        """
        GIVEN a local wheel file with unexpected error
        WHEN running 'ggshield plugin install <path>'
        THEN it shows an error
        """
        wheel_path = tmp_path / "problem.whl"
        wheel_path.touch()

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch("ggshield.cmd.plugin.install.EnterpriseConfig"),
            mock.patch(
                "ggshield.cmd.plugin.install.detect_source_type",
                return_value=PluginSourceType.LOCAL_FILE,
            ),
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.install_from_wheel.side_effect = Exception("Unexpected")
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "install", str(wheel_path)],
            )

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "Failed to install from wheel" in result.output

    def test_install_url_checksum_mismatch(self, cli_fs_runner) -> None:
        """
        GIVEN a URL with wrong checksum
        WHEN running 'ggshield plugin install <url> --sha256 <hash>'
        THEN it shows a checksum error
        """
        from ggshield.core.plugin.downloader import ChecksumMismatchError

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch("ggshield.cmd.plugin.install.EnterpriseConfig"),
            mock.patch(
                "ggshield.cmd.plugin.install.detect_source_type",
                return_value=PluginSourceType.URL,
            ),
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.download_from_url.side_effect = ChecksumMismatchError(
                "expected123", "actual456"
            )
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(
                cli,
                [
                    "plugin",
                    "install",
                    "https://example.com/plugin.whl",
                    "--sha256",
                    "wrong",
                ],
            )

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "Checksum verification failed" in result.output

    def test_install_url_download_error(self, cli_fs_runner) -> None:
        """
        GIVEN a URL that fails to download
        WHEN running 'ggshield plugin install <url>'
        THEN it shows a download error
        """
        from ggshield.core.plugin.downloader import DownloadError

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch("ggshield.cmd.plugin.install.EnterpriseConfig"),
            mock.patch(
                "ggshield.cmd.plugin.install.detect_source_type",
                return_value=PluginSourceType.URL,
            ),
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.download_from_url.side_effect = DownloadError(
                "Network error"
            )
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "install", "https://example.com/plugin.whl"],
            )

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "Failed to install from URL" in result.output

    def test_install_url_generic_error(self, cli_fs_runner) -> None:
        """
        GIVEN a URL with unexpected error
        WHEN running 'ggshield plugin install <url>'
        THEN it shows an error
        """
        with (
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch("ggshield.cmd.plugin.install.EnterpriseConfig"),
            mock.patch(
                "ggshield.cmd.plugin.install.detect_source_type",
                return_value=PluginSourceType.URL,
            ),
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.download_from_url.side_effect = Exception("Unexpected")
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "install", "https://example.com/plugin.whl"],
            )

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "Failed to install from URL" in result.output

    def test_install_github_release_checksum_mismatch(self, cli_fs_runner) -> None:
        """
        GIVEN a GitHub release URL with wrong checksum
        WHEN running 'ggshield plugin install <url> --sha256 <hash>'
        THEN it shows a checksum error
        """
        from ggshield.core.plugin.downloader import ChecksumMismatchError

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch("ggshield.cmd.plugin.install.EnterpriseConfig"),
            mock.patch(
                "ggshield.cmd.plugin.install.detect_source_type",
                return_value=PluginSourceType.GITHUB_RELEASE,
            ),
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.download_from_github_release.side_effect = (
                ChecksumMismatchError("expected", "actual")
            )
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(
                cli,
                [
                    "plugin",
                    "install",
                    "https://github.com/owner/repo/releases/download/v1/p.whl",
                    "--sha256",
                    "wrong",
                ],
            )

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "Checksum verification failed" in result.output

    def test_install_github_release_download_error(self, cli_fs_runner) -> None:
        """
        GIVEN a GitHub release URL that fails to download
        WHEN running 'ggshield plugin install <url>'
        THEN it shows a download error
        """
        from ggshield.core.plugin.downloader import DownloadError

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch("ggshield.cmd.plugin.install.EnterpriseConfig"),
            mock.patch(
                "ggshield.cmd.plugin.install.detect_source_type",
                return_value=PluginSourceType.GITHUB_RELEASE,
            ),
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.download_from_github_release.side_effect = DownloadError(
                "Not found"
            )
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(
                cli,
                [
                    "plugin",
                    "install",
                    "https://github.com/owner/repo/releases/download/v1/p.whl",
                ],
            )

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "Failed to install from GitHub release" in result.output

    def test_install_github_release_generic_error(self, cli_fs_runner) -> None:
        """
        GIVEN a GitHub release URL with unexpected error
        WHEN running 'ggshield plugin install <url>'
        THEN it shows an error
        """
        with (
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch("ggshield.cmd.plugin.install.EnterpriseConfig"),
            mock.patch(
                "ggshield.cmd.plugin.install.detect_source_type",
                return_value=PluginSourceType.GITHUB_RELEASE,
            ),
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.download_from_github_release.side_effect = Exception(
                "Unexpected"
            )
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(
                cli,
                [
                    "plugin",
                    "install",
                    "https://github.com/owner/repo/releases/download/v1/p.whl",
                ],
            )

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "Failed to install from GitHub release" in result.output

    def test_install_github_artifact_download_error(self, cli_fs_runner) -> None:
        """
        GIVEN a GitHub artifact URL that fails to download
        WHEN running 'ggshield plugin install <url>'
        THEN it shows a download error
        """
        from ggshield.core.plugin.downloader import DownloadError

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch("ggshield.cmd.plugin.install.EnterpriseConfig"),
            mock.patch(
                "ggshield.cmd.plugin.install.detect_source_type",
                return_value=PluginSourceType.GITHUB_ARTIFACT,
            ),
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.download_from_github_artifact.side_effect = DownloadError(
                "Failed to extract"
            )
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(
                cli,
                [
                    "plugin",
                    "install",
                    "https://github.com/owner/repo/actions/runs/123/artifacts/456",
                ],
            )

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "Failed to install from GitHub artifact" in result.output

    def test_install_github_artifact_generic_error(self, cli_fs_runner) -> None:
        """
        GIVEN a GitHub artifact URL with unexpected error
        WHEN running 'ggshield plugin install <url>'
        THEN it shows an error
        """
        with (
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch("ggshield.cmd.plugin.install.EnterpriseConfig"),
            mock.patch(
                "ggshield.cmd.plugin.install.detect_source_type",
                return_value=PluginSourceType.GITHUB_ARTIFACT,
            ),
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.download_from_github_artifact.side_effect = Exception(
                "Unexpected"
            )
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(
                cli,
                [
                    "plugin",
                    "install",
                    "https://github.com/owner/repo/actions/runs/123/artifacts/456",
                ],
            )

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "Failed to install from GitHub artifact" in result.output
