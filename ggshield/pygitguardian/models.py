from typing import List, Optional


class BaseObject:
    UNSET_STATUS_CODE = 600

    def __init__(self):
        self.status_code = 600

    @property
    def success(self):
        """success returns True if call returned 200

        :return: call status
        :rtype: bool
        """
        return self.status_code == 200


class Detail(BaseObject):
    """Detail is a response object mostly returned on error or when the
    api output is a simple string

    Attributes:
        status_code (int): response status code
        detail (str): response string
    """

    def __init__(self, detail: str, **kwargs):
        super().__init__()
        self.detail = detail

    def __repr__(self):
        return "{0}:{1}".format(self.status_code, self.detail)

    def __bool__(self):
        return self.success


class Match:
    def __init__(
        self,
        match: str,
        match_type: str,
        line_start: Optional[int] = None,
        line_end: Optional[int] = None,
        index_start: Optional[int] = None,
        index_end: Optional[int] = None,
        **kwargs
    ):
        self.match = match
        self.match_type = match_type
        self.line_start = line_start
        self.line_end = line_end
        self.index_start = index_start
        self.index_end = index_end

    def __repr__(self):
        return (
            "match:{0}, "
            "match_type:{1}, "
            "line_start:{2}, "
            "line_end:{3}, "
            "index_start:{4}, "
            "index_end:{5}".format(
                self.match,
                self.match_type,
                repr(self.line_start),
                repr(self.line_end),
                repr(self.index_start),
                repr(self.index_end),
            )
        )


class PolicyBreak:
    def __init__(self, break_type: str, policy: str, matches: List[Match], **kwargs):
        self.break_type = break_type
        self.policy = policy
        self.matches = matches

    def __repr__(self):
        return (
            "break_type:{0}, "
            "policy:{1}, "
            "matches: {2}".format(self.break_type, self.policy, repr(self.matches))
        )


class ScanResult(BaseObject):
    """ScanResult is a response object returned on a Content Scan

    Attributes:
        status_code (int): response status code
        policy_break_count (int): number of policy breaks
        policy_breaks (List): policy break list
        policies (List[str]): string list of policies evaluated
    """

    def __init__(
        self,
        policy_break_count: int,
        policy_breaks: List[PolicyBreak],
        policies: List[str],
        **kwargs
    ):
        """
        :param policy_break_count: number of policy breaks
        :type policy_break_count: int
        :param policy_breaks: policy break list
        :type policy_breaks: List
        :param policies: string list of policies evaluated
        :type policies: List[str]
        """
        super().__init__()
        self.policy_break_count = policy_break_count
        self.policies = policies
        self.policy_breaks = policy_breaks

    @property
    def has_secrets(self) -> bool:
        """has_secrets is an easy way to check if your provided document has policy breaks

        >>> obj = ScanResult(2, [], [])
        >>> obj.has_secrets
        True

        :return: true if there were policy breaks in the documents
        :rtype: bool
        """

        return self.policy_break_count > 0

    def __repr__(self):
        return (
            "policy_break_count:{0}, "
            "policies:{1}, "
            "policy_breaks: {2}".format(
                self.policy_break_count, self.policies, self.policy_breaks
            )
        )

    def __str__(self):
        return "{0} policy breaks from the evaluated policies: {1}".format(
            self.policy_break_count,
            ", ".join([policy_break.policy for policy_break in self.policy_breaks]),
        )
