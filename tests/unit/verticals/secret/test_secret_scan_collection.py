from ggshield.verticals.secret import Results


class MyException(Exception):
    pass


def test_results_from_exception():
    """
    GIVEN an exception
    WHEN creating a Results from it
    THEN it contains the right content
    """
    exc = MyException("Hello")
    results = Results.from_exception(exc)

    assert len(results.errors) == 1
    error = results.errors[0]
    assert error.description == "MyException: Hello"

    assert results.results == []
