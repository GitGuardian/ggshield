import os

from pygitguardian.config import MULTI_DOCUMENT_LIMIT


def getint(name: str, default: int) -> int:
    value = os.getenv(name)
    return int(value) if value is not None else default


# max file size to accept
MAX_FILE_SIZE = 1048576

# max number of documents to send in a single chunk
MAX_DOC_LIMIT = getint("GG_DOC_LIMIT", MULTI_DOCUMENT_LIMIT)
assert (
    MAX_DOC_LIMIT <= MULTI_DOCUMENT_LIMIT
), f"GG_DOC_LIMIT must be <= {MULTI_DOCUMENT_LIMIT}"

# max number of commits scanned in parallel
MAX_COMMIT_WORKERS = getint("GG_COMMIT_WORKERS", 4)

# max number of threads scanning documents
MAX_SCAN_WORKERS = getint("GG_SCAN_WORKERS", 4)

# max files size to create a tar from
MAX_TAR_CONTENT_SIZE = 30 * 1024 * 1024

CPU_COUNT = os.cpu_count() or 1

CACHE_FILENAME = "./.cache_ggshield"
GLOBAL_CONFIG_FILENAMES = [".gitguardian", ".gitguardian.yml", ".gitguardian.yaml"]
LOCAL_CONFIG_PATHS = ["./.gitguardian", "./.gitguardian.yml", "./.gitguardian.yaml"]
DEFAULT_LOCAL_CONFIG_PATH = "./.gitguardian.yaml"
DEFAULT_DASHBOARD_URL = "https://dashboard.gitguardian.com"
AUTH_CONFIG_FILENAME = "auth_config.yaml"
ON_PREMISE_API_URL_PATH_PREFIX = "/exposed"
