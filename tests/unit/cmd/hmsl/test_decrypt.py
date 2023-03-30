import pytest
from click.testing import CliRunner

from ggshield.cmd.main import cli
from ggshield.hmsl.crypto import hash_string
from tests.unit.conftest import assert_invoke_exited_with, assert_invoke_ok


RESULTS_CONTENT = (
    '{"hint": "f7f17c88638b42465b6c620a0c7648ef470e611c1fdf90166aac613601799f81", "payload": '
    '"KzzhJEq/pM2RaWav9NAvjw45Gfp/26UGDDzYiDNuOCup0PfoAHNViOGX14/a7uUNWLk53zGIar3s2xOW/xxzMEgTT2owjH52gGalhwKBfTY="}\n'
    '{"hint": "71d27eee3aa6c1751110ea338f23a5cfe11da717ea27453e7fe09e1594c3f8e7", "payload": '
    '"zmrGtuhTtgxNkk9SA250HTxXQ+mfoJQlZ76CPx50juK4XFCCTbFNv6ZeahGRQqW4+vf92DEwpGTHVzjiQEF6JebJsoRuaMQDSntHQ17z0UU="}\n'
    '{"hint": "f1b2fcaf134f3a08513ec6603ee3281511f349166fea5ef3356dd62051a76aa8", "payload": '
    '"Qzp7zRkFeIlPhiy6VMeUyo4vaCJAFmuqDQITH4WFC1BH51eHDNcL1UOw5u8dKmBWRJMfY7Zh7atyTl++hbsYDnIItJi8LFO5Yyzj+xte+ik="}\n'
    '{"hint": "89740ad4cd63fa9a7637325a7bef91c0ba93d0a45bbf687beb76bacaf5fa8da3", "payload": '
    '"kUlYx2lO5dOtFAM7XPT7uyk5v81ajJeg7Uepq1D4oyWQcf3ijMRThqsMrkKkUXSXHcAL182yCAgbub/NDF2wFA+Lyr5qBdb3qBBFLztfFz0="}\n'
    '{"hint": "3be2d605a3d143bfea373887ed16e7935be0e3c189cbee4d343c92ed6c89fdb8", "payload": '
    '"GZIG82jOLH5gXB5NNJt7NyfUOQUpk720wA3LItmVrXKCIK2PursytFkg/pPtzBXyPifNZtsOaNf5an+5Pz3mVysVMoCF9dXGFt1AFRi8lXk="}\n'
    '{"hint": "16787b637f7787685909539f65cc100b591d8c8d1074d0e5491aab33f364c86b", "payload": '
    '"4XgUM9pXWrLbQ8tH0AH7Za3u7tObAmlDXBSgwS+IE2m/NeDn3y7KF5H7yPB/faFDfKFirNiijhEfkBgfCz+FmZhDLCCzsga6hZN0S9he6EM="}\n'
    '{"hint": "e9ecc350e213860e9472057339443c830581c53e2b4dfb3aaa7e5fa4a854d5a3", "payload": '
    '"UDIP09t3tSk2IyQhxnJmF2gaDxhOY4zgrGpOzLeakIOZEmRxlyXYfdN3uFuTutnfdT7ZY+2Am2Q0Vst0L3EfuvomNdx/yL3desUApHq5o5I="}\n'
    '{"hint": "31ded0b51235ebde7d5fa10685d33b95e8a20a4e284220351812ca98ed20836b", "payload": '
    '"+FuUB48xvYQg1VTf1Jvyif14T8rLJETu3L0y2SJa7fJ+P7HDTDf/ESH8pLjJmadyNB3vl3t8KS3VH+lveCae53yVY66LncUCwuXVKd9s7G0="}\n'
    '{"hint": "19b9ba15c838c44d8965ac2300718fd8f9e2a038ff3ca7b3982fae50ec4afbfa", "payload": '
    '"YKk5NCIkiS5tmab2lXO1V2mpsPbRC+vAsz+TNHroEcpo8b0YhEjy6SCUXWkYMm2mBUFz3Kmvkqqd59Pdj4EXmvqrl1yNV2LlCCoJGD91SUY="}\n'
    '{"hint": "23ef947812513a59de504af2e291f9bbab287b941e0551f442e63f19f979679d", "payload": '
    '"0XmzWJNyq3gHbeqb5+T5xSjuwP1qFdrIbvsW4K5Spk+Yn2mfBs92Z3ipEngis2nZMNS+K99h/sh3+hvqTH5T5Z0p/YnCd2f+1E4suGEbVnA="}\n'
    '{"hint": "9c9e78a410131e548c733e08b1de9a3dcccbe5cda970cb6ad740655b7741e7b3", "payload": '
    '"WDmh3FQvY+i5DO+6bWeOkY5J78jHBHCsEFjl9u1PEpftDS5Htzcc/dQqrzFcYvBwU+RbPLag2z/w7PBW+m472D9R1OExamCWs6MjN65j3L0="}\n'
)

RESULTS_CLEARTEXT_CONTENT = (
    '{"hash": "743d9fde380b7064cc6a8d3071184fc47905cf7440e5615cd46c7b6cbfb46d47", '
    '"count": 14, "url": "https://github.com/edly-io/devstack/commit/ccfc9c2d63c29'
    '17be60a9fd2a4c36ff3a8b9bb8c#diff-e45e45baeda1c1e73482975a664062aa56f20c03dd9d64a827aba57775bed0d3L158"}'
)


@pytest.fixture
def mapping(cli_fs_runner):
    """Prepare a mapping file"""
    secrets = ["foo", "bar", "password", "1234"]
    mapping = {hash_string(secret): secret for secret in secrets}
    with open("mapping.txt", "w") as f:
        f.write("\n".join(f"{key}:{value}" for key, value in mapping.items()))
    return mapping


@pytest.fixture
def results(mapping):
    """Prepare a results file"""
    with open("results.txt", "w") as f:
        f.write(RESULTS_CONTENT)


@pytest.fixture
def full_hash_result(mapping):
    """Prepare a results file"""
    with open("results.txt", "w") as f:
        f.write(RESULTS_CLEARTEXT_CONTENT)


@pytest.mark.parametrize(
    "command",
    [
        ["hmsl", "decrypt"],
        ["hmsl", "decrypt", "none.txt"],
        ["hmsl", "decrypt", "-m", "none.txt"],
        ["hmsl", "decrypt", "-m", "none.txt", "void.txt"],
    ],
)
def test_hmsl_decrypt_no_files(cli_fs_runner: CliRunner, command) -> None:
    """
    GIVEN a cli
    WHEN running on non-existing files or other issues
    THEN the return code is 2
    """
    result = cli_fs_runner.invoke(cli, command)
    assert_invoke_exited_with(result, 2)


@pytest.mark.parametrize(
    "command",
    [
        ["hmsl", "decrypt", "none.txt"],
        ["hmsl", "decrypt", "-m", "none.txt", "results.txt"],
    ],
)
def test_hmsl_decrypt_no_files2(
    cli_fs_runner: CliRunner, command, mapping, results
) -> None:
    """
    Same as above but with some files created
    """
    result = cli_fs_runner.invoke(cli, command)
    assert_invoke_exited_with(result, 2)


def test_hmsl_decrypt(cli_fs_runner: CliRunner, mapping, results) -> None:
    """
    GIVEN some secrets
    WHEN running the decrypt command with an non-existing file
    THEN the return code is 2
    """
    result = cli_fs_runner.invoke(cli, ["hmsl", "decrypt"])
    assert_invoke_exited_with(result, 2)


def test_hmsl_decrypt_default_behavior(cli_fs_runner: CliRunner, results) -> None:
    """
    GIVEN some secrets
    WHEN running the decrypt command on a file
    THEN the secrets are correctly decrypted
    """
    result = cli_fs_runner.invoke(cli, ["hmsl", "decrypt", "results.txt"])
    assert_invoke_ok(result)
    assert result.output.count("> Secret ") == 1
    assert 'Secret name: "foo"' in result.output


def test_hmsl_decrypt_full_hashes_behavior(
    cli_fs_runner: CliRunner, full_hash_result
) -> None:
    """
    GIVEN a some full hashes response
    WHEN running the decrypt command on a file
    THEN the command accepts the decrypted payloads seamlessly
    """
    result = cli_fs_runner.invoke(cli, ["hmsl", "decrypt", "results.txt"])
    assert_invoke_ok(result)
    assert result.output.count("> Secret ") == 1
    assert 'Secret name: "password"' in result.output
