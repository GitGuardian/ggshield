import os


# max file size to accept
MAX_FILE_SIZE = 1048576
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
