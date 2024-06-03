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
    DIRECTORY = "directory"
    DIFF = "diff"
    DOCSET = "docset"
    CHANGE = "change"
    # IAC/SCA scan modes
    DIRECTORY_ALL = "directory_all"
    DIRECTORY_DIFF = "directory_diff"
    PRE_COMMIT_ALL = "pre_commit_all"
    PRE_COMMIT_DIFF = "pre_commit_diff"
    PRE_PUSH_ALL = "pre_push_all"
    PRE_PUSH_DIFF = "pre_push_diff"
    PRE_RECEIVE_ALL = "pre_receive_all"
    PRE_RECEIVE_DIFF = "pre_receive_diff"
    CI_ALL = "ci_all"
    CI_DIFF = "ci_diff"
