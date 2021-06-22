from pathlib import Path
from typing import Dict

import pytest

from ggshield.scan.docker import (
    InvalidDockerArchiveException,
    _get_config,
    _should_scan_layer,
    get_files_from_docker_archive,
)


DOCKER_EXAMPLE_PATH = Path(__file__).parent.parent / "data" / "docker-example.tar.xz"


class ManifestMock:
    def read(self, amount: int = None) -> bytes:
        return '[{"Config": "8b907fee27ad927c595fcf873c8256796cab27e7a3fb4bf3952308a76ad791c4.json"}]'.encode(  # noqa: E501
            "utf-8"
        )


class TarMock:
    def __init__(self, members: Dict[str, str], *args, **kwargs):
        self.members = members

    def extractfile(self, member: str):
        if "8b907fee27ad927c595fcf873c8256796cab27e7a3fb4bf3952308a76ad791c4" in member:
            return None
        return self.members.get(member, None)

    def getmember(self, member: str):
        return member if self.members.get(member, None) else None


class TestDockerScan:
    @pytest.mark.parametrize(
        ["op", "want"],
        [
            pytest.param(
                "/bin/sh -c #(nop) COPY dir:xxx in / ",
                True,
            ),
            pytest.param("/bin/sh -c #(nop) ADD dir:xxx in / ", True),
            pytest.param(
                '/bin/sh -c #(nop)  CMD ["/usr/bin/bash"',
                False,
            ),
        ],
    )
    def test_should_scan_layer(self, op: str, want: bool):
        assert _should_scan_layer({"created_by": op}) is want

    @pytest.mark.parametrize(
        ["members", "match"],
        [
            pytest.param({}, "No manifest file found."),
            pytest.param(
                {"manifest.json": ManifestMock()},
                "No config file found.",
            ),
            pytest.param(
                {
                    "manifest.json": ManifestMock(),
                    "8b907fee27ad927c595fcf873c8256796cab27e7a3fb4bf3952308a76ad791c4.json": "layer file",  # noqa: E501
                },  # noqa: E501
                "Config file could not be extracted.",
            ),
        ],
    )
    def test_get_config(self, members, match):
        tarfile = TarMock(members)
        with pytest.raises(InvalidDockerArchiveException, match=match):
            _get_config(tarfile)

    def test_get_files_from_docker_archive(self):
        files = get_files_from_docker_archive(DOCKER_EXAMPLE_PATH)

        expected_files = {
            "Dockerfile or build-args": None,  # noqa: E501
            DOCKER_EXAMPLE_PATH
            / "64a345482d74ea1c0699988da4b4fe6cda54a2b0ad5da49853a9739f7a7e5bbc/layer.tar/app/file_one": "Hello, I am the first file!\n",  # noqa: E501
            DOCKER_EXAMPLE_PATH
            / "2d185b802fb3c2e6458fe1ac98e027488cd6aedff2e3d05eb030029c1f24d60f/layer.tar/app/file_three.sh": "echo Life is beautiful.\n",  # noqa: E501
            DOCKER_EXAMPLE_PATH
            / "2d185b802fb3c2e6458fe1ac98e027488cd6aedff2e3d05eb030029c1f24d60f/layer.tar/app/file_two.py": """print("Hi! I'm the second file but I'm happy.")\n""",  # noqa: E501
        }

        assert set(files.files) == {str(file_path) for file_path in expected_files}

        for file_path, expected_content in expected_files.items():
            file = files.files[str(file_path)]
            assert expected_content is None or file.document == expected_content
