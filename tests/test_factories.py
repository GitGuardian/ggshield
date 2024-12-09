import pytest

from tests.factories import get_line_index


TEST_CONTENT = """aaa
bb
cccc"""


@pytest.mark.parametrize(
    ("index", "expected_line_index"),
    (
        (1, 0),
        (4, 0),
        (5, 1),
        (7, 1),
        (8, 2),
        (11, 2),
    ),
)
def test_get_line_index(index, expected_line_index):
    assert get_line_index(TEST_CONTENT, index) == expected_line_index
