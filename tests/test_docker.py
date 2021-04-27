from pathlib import Path

from ggshield.docker import get_files_from_docker_archive


DOCKER_EXAMPLE_PATH = Path(__file__).parent / "data" / "docker-example.tar.xz"


def test_get_files_from_docker_archive():
    files = get_files_from_docker_archive(DOCKER_EXAMPLE_PATH)

    expected_files = {
        "6f19b02ab98ac5757d206a2f0f5a4741ad82d39b08b948321196988acb9de8b1.json": None,
        "64a345482d74ea1c0699988da4b4fe6cda54a2b0ad5da49853a9739f7a7e5bbc/layer.tar/app/file_one": "Hello, I am the first file!\n",  # noqa: E501
        "2d185b802fb3c2e6458fe1ac98e027488cd6aedff2e3d05eb030029c1f24d60f/layer.tar/app/file_three.sh": "echo Life is beautiful.\n",  # noqa: E501
        "2d185b802fb3c2e6458fe1ac98e027488cd6aedff2e3d05eb030029c1f24d60f/layer.tar/app/file_two.py": """print("Hi! I'm the second file but I'm happy.")\n""",  # noqa: E501
    }

    assert set(files.files) == {
        str(DOCKER_EXAMPLE_PATH / file_path) for file_path in expected_files
    }

    for file_path, expected_content in expected_files.items():
        full_path = DOCKER_EXAMPLE_PATH / file_path
        file = files.files[str(full_path)]
        assert expected_content is None or file.document == expected_content
