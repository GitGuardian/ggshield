from typing import List


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
        return f"{self.status_code}:{self.detail}"

    def __bool__(self):
        return self.success


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
        policy_breaks: List,
        policies: List[str],
        **kwargs,
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
