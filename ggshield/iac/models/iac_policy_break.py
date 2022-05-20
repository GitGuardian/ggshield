from typing import Any, Dict, List

from marshmallow import fields, post_load
from pygitguardian.models import PolicyBreak, PolicyBreakSchema

from ggshield.iac.models.iac_match import IaCMatch, IaCMatchSchema


class IaCPolicyBreakSchema(PolicyBreakSchema):
    matches = fields.List(fields.Nested(IaCMatchSchema), required=True)
    policy_details = fields.Dict(
        fields.String(required=True), fields.String(required=True)
    )
    ignore_sha = fields.String(required=True)

    @post_load
    def make_policy_break(
        self, data: Dict[str, Any], **kwargs: Any
    ) -> "IaCPolicyBreak":
        return IaCPolicyBreak(**data)


class IaCPolicyBreak(PolicyBreak):
    SCHEMA = IaCPolicyBreakSchema()

    def __init__(
        self,
        break_type: str,
        policy: str,
        validity: str,
        matches: List[IaCMatch],
        policy_details: Dict[str, str],
        ignore_sha: str,
        **kwargs: Any,
    ) -> None:
        super().__init__(break_type, policy, validity, matches, **kwargs)
        self.policy_details = policy_details
        self.ignore_sha = ignore_sha

    def __repr__(self) -> str:
        return f"{super().__repr__()}, policy_details: {str(self.policy_details)}"
