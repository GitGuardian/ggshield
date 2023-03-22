from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

import pytest


class MockRequestsResponse:
    def __init__(self, json_data: Dict[str, Any], status_code: int = 200):
        self.headers = {"content-type": "application/json"}
        self.status_code = status_code
        self.json_data = json_data
        self.ok = status_code < 400

    def json(self):
        return self.json_data


DataChecker = Callable[[Any], None]


@dataclass
class ExpectedCall:
    method: str
    endpoint: str
    response: MockRequestsResponse

    # If defined, RequestMock will call this function with the value of the `data` field
    # it receives. It can be used to check the payload is as expected.
    data_checker: Optional[DataChecker] = None


class RequestMock:
    """
    Mocks HTTP requests. Usage:

    ```python
    # Create the mock
    mock = RequestMock()

    # Install the mock
    monkeypatch.setattr("ggshield.core.client.Session.request", mock)

    # Add expected calls
    mock.add_GET("/foo1", MockRequestsResponse({"a": 12}))
    mock.add_POST("/login", MockRequestsResponse({"a": 12}))
    mock.add_GET("/not_found", MockRequestsResponse({"msg": "no-such-page"}, 400))

    # Execute the code expected to make the calls
    # If a call does not match the expected calls, an assert will raise
    my_code()

    # Verify the tested code passed all the calls
    mock.assert_all_calls_happened()
    ```
    """

    def __init__(self):
        self._calls: List[ExpectedCall] = []

    def add_GET(
        self,
        endpoint: str,
        response: MockRequestsResponse,
        data_checker: Optional[DataChecker] = None,
    ):
        self.add_call(ExpectedCall("GET", endpoint, response, data_checker))

    def add_POST(
        self,
        endpoint: str,
        response: MockRequestsResponse,
        data_checker: Optional[DataChecker] = None,
    ):
        self.add_call(ExpectedCall("POST", endpoint, response, data_checker))

    def add_call(self, call: ExpectedCall) -> None:
        """Low-level method to add a call, it's simpler to use add_GET or add_POST instead"""
        self._calls.append(call)

    def assert_all_calls_happened(self) -> None:
        assert self._calls == []

    def __call__(
        self, method: str, url: str, data: Optional[Any] = None, **kwargs: Any
    ) -> MockRequestsResponse:
        """This method is called by the tested code. It pops the next expected call and
        checks it matches with the received call."""
        method = method.upper()

        # Get the expected call
        if not self._calls:
            pytest.fail(f"Unexpected call: {method} {url}")
        call = self._calls.pop(0)

        # Check the current call match the expected one
        assert url.endswith(call.endpoint)
        assert method == call.method
        if call.data_checker:
            call.data_checker(data)

        return call.response
