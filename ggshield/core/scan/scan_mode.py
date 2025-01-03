from enum import Enum


class ScanMode(Enum):
    REPO = "repo"
    PATH = "path"
    COMMIT_RANGE = "commit_range"
    PRE_COMMIT = "pre_commit"
    PRE_PUSH = "pre_push"
    PRE_RECEIVE = "pre_receive"
    CI = "ci"
    DOCKER = "docker"
    PYPI = "pypi"
    ARCHIVE = "archive"
    DOCSET = "docset"
    CHANGE = "change"
