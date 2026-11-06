import queue
import threading
import time

import requests
from requests.adapters import HTTPAdapter
from urllib3 import Retry

from ggshield.core.client import create_client_from_config
from ggshield.core.config import Config
from ggshield.core.machine_id import (
    _get_hostname,
    _get_machine_id,
    endpoint_registration_opt_out,
    running_on_ci,
)
from ggshield.verticals.honeytoken.targets import resolve_targets

_REGISTRATION_BUDGET = 5.0


def register_endpoint(config: Config) -> str:
    opt_out = endpoint_registration_opt_out(config.user_config.endpoint_registration)
    if opt_out:
        return f"skipped (disabled by {opt_out})"
    if running_on_ci():
        return "skipped (CI)"

    deadline = time.monotonic() + _REGISTRATION_BUDGET
    results: queue.Queue[str] = queue.Queue(maxsize=1)

    def run() -> None:
        try:
            message = _register(config, deadline)
        except (TimeoutError, requests.Timeout):
            message = "warning: endpoint registration timed out"
        except Exception:
            message = "warning: endpoint registration failed"
        results.put(message)

    # DNS, credential stores, and identity lookup can outlive a socket timeout.
    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    try:
        return results.get(timeout=max(0.0, deadline - time.monotonic()))
    except queue.Empty:
        return "warning: endpoint registration timed out"


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    return remaining


def _register(config: Config, deadline: float) -> str:
    targets = resolve_targets(None, None)
    _remaining(deadline)
    machine_id = _get_machine_id()
    _remaining(deadline)
    hostname = _get_hostname()
    _remaining(deadline)
    if not targets:
        return "warning: no users available for endpoint registration"

    client = create_client_from_config(config)
    with client.session as session:
        for adapter in session.adapters.values():
            if isinstance(adapter, HTTPAdapter):
                adapter.max_retries = Retry(total=0)
        url = client.base_uri.rstrip("/") + "/v1/endpoints/registrations"
        for start in range(0, len(targets), 200):
            body = {
                "machine_id": machine_id,
                "hostname": hostname,
                "users": [
                    {"username": target.username}
                    for target in targets[start : start + 200]
                ],
            }
            response = session.post(
                url,
                json=body,
                headers={"Authorization": f"Token {client.api_key}"},
                timeout=_remaining(deadline),
                allow_redirects=False,
                stream=True,
            )
            try:
                if response.status_code == 404:
                    return "not available on this workspace (404)"
                if response.status_code != 204:
                    return (
                        "warning: endpoint registration failed "
                        f"(HTTP {response.status_code})"
                    )
            finally:
                response.close()
            _remaining(deadline)
    return f"registered {len(targets)} user(s)"
