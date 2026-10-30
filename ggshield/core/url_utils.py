from urllib.parse import ParseResult, urlparse

from click import UsageError

from . import ui
from .constants import ON_PREMISE_API_URL_PATH_PREFIX

GITGUARDIAN_DOMAINS = ["gitguardian.com", "gitguardian.tech"]


def is_saas_netloc(netloc: str) -> bool:
    """
    Whether ``netloc`` is a GitGuardian-hosted (SaaS) instance.

    SaaS instances are ``dashboard.*`` / ``api.*`` hosts under a gitguardian.com
    or gitguardian.tech domain, and use a host swap to go between dashboard and
    API URLs. Self-hosted instances use the ``/exposed`` path prefix instead —
    even when deployed under a gitguardian domain, so the domain suffix alone is
    not enough to identify SaaS.

    Some SaaS deployments expose the dashboard/API as ``dashboard-<id>.*`` /
    ``api-<id>.*`` hosts, which are SaaS-mode too, so the first label may also be
    a ``dashboard-`` / ``api-`` prefix rather than the bare word.
    """
    if not any(netloc.endswith("." + domain) for domain in GITGUARDIAN_DOMAINS):
        return False
    first_label = netloc.split(".", 1)[0]
    return first_label in ("dashboard", "api") or first_label.startswith(
        ("dashboard-", "api-")
    )


def clean_url(url: str, warn: bool = False) -> ParseResult:
    """
    Take a dashboard or API URL and removes trailing slashes and useless /v1
    (optionally with a warning).
    """
    parsed_url = urlparse(url)
    if parsed_url.path.endswith("/"):
        parsed_url = parsed_url._replace(path=parsed_url.path[:-1])
    if parsed_url.path.endswith("/v1"):
        parsed_url = parsed_url._replace(path=parsed_url.path[:-3])
        if warn:
            ui.display_warning("Unexpected /v1 path in your URL configuration")
    return parsed_url


def validate_instance_url(url: str, warn: bool = False) -> ParseResult:
    """
    Validate a dashboard URL
    """
    parsed_url = clean_url(url, warn=warn)
    if parsed_url.scheme != "https" and not (
        parsed_url.netloc.startswith("localhost")
        or parsed_url.netloc.startswith("127.0.0.1")
    ):
        raise UsageError(f"Invalid scheme for dashboard URL '{url}', expected HTTPS")
    if is_saas_netloc(parsed_url.netloc):
        if parsed_url.path:
            raise UsageError(
                f"Invalid dashboard URL '{url}', got an unexpected path '{parsed_url.path}'"
            )

    return parsed_url


def dashboard_to_api_url(dashboard_url: str, warn: bool = False) -> str:
    """
    Convert a dashboard URL to an API URL.
    handles the SaaS edge case where the host changes instead of the path
    """
    parsed_url = validate_instance_url(dashboard_url, warn=warn)

    if is_saas_netloc(parsed_url.netloc):
        parsed_url = parsed_url._replace(
            netloc=parsed_url.netloc.replace("dashboard", "api")
        )
    else:
        parsed_url = parsed_url._replace(
            path=f"{parsed_url.path}{ON_PREMISE_API_URL_PATH_PREFIX}"
        )
    return parsed_url.geturl()


def api_to_dashboard_url(api_url: str, warn: bool = False) -> str:
    """
    Convert an API URL to a dashboard URL.
    handles the SaaS edge case where the host changes instead of the path
    """
    parsed_url = clean_url(api_url, warn=warn)
    if parsed_url.scheme != "https" and not parsed_url.netloc.startswith("localhost"):
        raise UsageError(f"Invalid scheme for API URL '{api_url}', expected HTTPS")
    if is_saas_netloc(parsed_url.netloc):  # SaaS
        if parsed_url.path:
            raise UsageError(
                f"Invalid API URL '{api_url}', got an unexpected path '{parsed_url.path}'"
            )
        parsed_url = parsed_url._replace(
            netloc=parsed_url.netloc.replace("api", "dashboard")
        )
    elif parsed_url.path.endswith(ON_PREMISE_API_URL_PATH_PREFIX):
        parsed_url = parsed_url._replace(
            path=parsed_url.path[: -len(ON_PREMISE_API_URL_PATH_PREFIX)]
        )
    return parsed_url.geturl()


def urljoin(url: str, *args: str) -> str:
    """
    concatenate each argument with a slash if not already existing.
    unlike urllib.parse.urljoin, this will make sure each element
    is separated by a slash e.g.
    ('http://somesite.com/path1', 'path2') -> http://somesite.com/path1/path2
    ('http://somesite.com/path1/', 'path2') -> http://somesite.com/path1/path2
    ('http://somesite.com/path1', '/path2') -> http://somesite.com/path1/path2
    """
    if not url:
        raise ValueError("Base URL cannot be empty")
    url = url.rstrip("/")

    for url_part in args:
        if not url_part:
            continue
        if url_part[0] != "/":
            url_part = "/" + url_part
        url += url_part

    return url
