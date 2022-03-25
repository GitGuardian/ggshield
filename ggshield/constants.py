import os


# max file size to accept
MAX_FILE_SIZE = 1048576

CPU_COUNT = os.cpu_count() or 1

CACHE_FILENAME = "./.cache_ggshield"
GLOBAL_CONFIG_FILENAMES = [".gitguardian", ".gitguardian.yml", ".gitguardian.yaml"]
LOCAL_CONFIG_PATHS = ["./.gitguardian", "./.gitguardian.yml", "./.gitguardian.yaml"]
DEFAULT_LOCAL_CONFIG_PATH = "./.gitguardian.yaml"
DEFAULT_API_URL = "https://api.gitguardian.com"
DEFAULT_DASHBOARD_URL = "https://dashboard.gitguardian.com"
