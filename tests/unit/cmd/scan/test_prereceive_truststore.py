import ssl
import sys
from unittest.mock import Mock

import pytest

from ggshield.cmd.secret.scan import prereceive


@pytest.fixture
def truststore_not_injected():
    """
    Puts the test process in the state of a child process started with the spawn
    or forkserver start method, in which truststore has not been injected, and
    restores the initial state afterwards.
    """
    import truststore

    was_injected = ssl.SSLContext is truststore.SSLContext
    truststore.extract_from_ssl()
    yield truststore
    if was_injected:
        truststore.inject_into_ssl()
    else:
        truststore.extract_from_ssl()


@pytest.mark.skipif(
    sys.version_info < (3, 10), reason="truststore requires Python 3.10+"
)
def test_execute_prereceive_uses_system_trust_store(
    monkeypatch, truststore_not_injected
) -> None:
    """
    GIVEN a process in which truststore has not been injected, as is the case
      for a child process started with the spawn or forkserver start method
    WHEN _execute_prereceive runs
    THEN the scan runs with truststore's SSLContext installed
    """
    truststore = truststore_not_injected
    assert ssl.SSLContext is not truststore.SSLContext

    contexts_seen_by_scan = []

    def fake_scan_commit_range(**kwargs):
        contexts_seen_by_scan.append(ssl.SSLContext)
        return 0

    monkeypatch.setattr(prereceive, "scan_commit_range", fake_scan_commit_range)

    with pytest.raises(SystemExit) as exc_info:
        prereceive._execute_prereceive(
            config=Mock(),
            output_handler=Mock(),
            commit_list=["a" * 40],
            command_path="ggshield secret scan pre-receive",
            client=Mock(),
            exclusion_regexes=set(),
        )

    assert exc_info.value.code == 0
    assert contexts_seen_by_scan == [truststore.SSLContext]
