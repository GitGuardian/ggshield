import re

from tests.functional.utils import run_ggshield


def test_cli_order():
    """
    Because it is more natural.
    """
    # GIVEN a call to ggshield hmsl help
    result = run_ggshield("hmsl", "-h", expected_code=0)
    # fingerprint, query and decrypt command follow each other in this order.
    assert re.search(
        "\n  fingerprint +[^\n]+\n  query +[^\n]+\n  decrypt", result.stdout
    ), result.stdout
