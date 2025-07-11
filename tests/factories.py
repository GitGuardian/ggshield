import random

import factory
import factory.fuzzy
from pygitguardian.models import Match, PolicyBreak, ScanResult

from ggshield.core.scan.scannable import StringScannable
from ggshield.utils.git_shell import Filemode
from ggshield.verticals.secret.secret_scan_collection import Secret
from tests.factory_constants import DETECTOR_NAMES, MATCH_NAMES


def get_line_index(content, index):
    """Return the index of the line containing the character at the given index"""
    current_line_index = 0
    lines = content.splitlines(keepends=True)
    while True:
        line = lines.pop(0)
        if index <= len(line):
            return current_line_index
        index -= len(line)
        current_line_index += 1


class ScannableFactory(factory.Factory):
    class Meta:
        model = StringScannable

    url = factory.Faker("hostname")
    content = factory.Faker("text")
    # Only returning FILE for new, since diff would need a custom content
    filemode = Filemode.FILE


class MatchFactory(factory.Factory):
    class Meta:
        model = Match

    content = factory.Faker("text")
    match_len = factory.fuzzy.FuzzyInteger(5, 15)
    index_start = factory.lazy_attribute(
        lambda obj: random.randint(0, len(obj.content) - obj.match_len)
    )
    index_end = factory.lazy_attribute(lambda obj: obj.index_start + obj.match_len)
    match = factory.lazy_attribute(
        lambda obj: obj.content[obj.index_start : obj.index_end]
    )
    line_start = factory.lazy_attribute(
        lambda obj: get_line_index(obj.content, obj.index_start)
    )
    line_end = factory.lazy_attribute(
        lambda obj: get_line_index(obj.content, obj.index_end)
    )
    match_type = factory.lazy_attribute(lambda obj: random.choice(MATCH_NAMES))


class PolicyBreakFactory(factory.Factory):
    class Meta:
        model = PolicyBreak

    break_type = factory.lazy_attribute(lambda obj: random.choice(DETECTOR_NAMES))
    policy = "Secrets detection"
    detector_name = factory.lazy_attribute(lambda obj: obj.break_type)
    detector_group_name = factory.lazy_attribute(lambda obj: obj.break_type)
    documentation_url = None
    validity = "valid"
    known_secret = False
    incident_url = None
    is_excluded = False
    is_vaulted = False
    exclude_reason = None
    diff_kind = None
    vault_type = None
    vault_name = None
    vault_path = None
    vault_path_count = None
    content = factory.Faker("text")
    nb_matches = factory.fuzzy.FuzzyInteger(1, 2)

    @factory.lazy_attribute
    def matches(self):
        # Note: matches may overlap, but at least we ensure they
        # have different names
        match_names = random.sample(MATCH_NAMES, self.nb_matches)
        return [
            MatchFactory(match_type=match_name, content=self.content)
            for match_name in match_names
        ]


class ScanResultFactory(factory.Factory):
    class Meta:
        model = ScanResult

    policy_break_count = factory.lazy_attribute(lambda obj: len(obj.policy_breaks))
    policy_breaks = []
    policies = ["Secrets detection"]
    is_diff = False


class SecretFactory(factory.Factory):
    class Meta:
        model = Secret

    detector_display_name = factory.lazy_attribute(
        lambda obj: random.choice(DETECTOR_NAMES)
    )
    detector_name = factory.lazy_attribute(lambda obj: obj.detector_display_name)
    detector_group_name = factory.lazy_attribute(lambda obj: obj.detector_display_name)
    documentation_url = None
    validity = "valid"
    known_secret = True
    incident_url = None
    matches = []
    ignore_reason = None
    diff_kind = None
    is_vaulted = False
    vault_type = None
    vault_name = None
    vault_path = None
    vault_path_count = None
