import logging
from typing import List

from pygitguardian import GGClient
from pygitguardian.models import SecretBlockRequest

from ggshield.verticals.ai.user import get_user_info

from .models import HookPayload


logger = logging.getLogger(__name__)


def send_secret_block(
    client: GGClient,
    payload: HookPayload,
    detectors: List[str],
    secret_count: int,
) -> None:
    """Report a secret blocked by an AI hook to the GitGuardian API.

    Best effort: a failure here must never break the hook. This is only called
    on the (rare) block path, where the agent is already halted for the user to
    remove the secret, so the extra round-trip is not on the hot path.
    """
    try:
        request = SecretBlockRequest(
            user=get_user_info(),
            tool=payload.raw.get("tool_name", ""),
            agent=payload.agent.name,
            cwd=payload.raw.get("cwd", ""),
            secret_count=secret_count,
            detectors=detectors,
            timestamp=payload.timestamp,
        )
        client.log_secret_block(request)
    except Exception as exc:
        # Best effort: never propagate telemetry failures to the agent.
        logger.debug("Secret block report failed: %s", exc)
