"""Marshmallow schema definitions

This module contains marshmallow schemas responsible for
serializing/deserializing request and response objects
"""
from marshmallow import Schema, fields, post_load, validate

from .models import Detail, ScanResult


class DocumentSchema(Schema):
    filename = fields.Str(validate=validate.Length(max=256))
    document = fields.Str(validate=validate.Length(max=1000000), required=True)


class MatchSchema(Schema):
    match_type = fields.Str(data_key="type", required=True)
    match = fields.Str(required=True)
    line_start = fields.Int(default=0)
    line_end = fields.Int(default=0)
    index_start = fields.Int(default=0)
    index_end = fields.Int(default=0)


class PolicyBreakSchema(Schema):
    break_type = fields.Str(data_key="type", required=True)
    policy = fields.Str(required=True)
    matches = fields.List(fields.Nested(MatchSchema), required=True)


class ScanResultSchema(Schema):
    policy_break_count = fields.Integer(required=True)
    policies = fields.List(fields.Str(), required=True)
    policy_breaks = fields.List(fields.Nested(PolicyBreakSchema), required=True)

    @post_load
    def make_scan_result(self, data, **kwargs):
        return ScanResult(**data)


class DetailSchema(Schema):
    detail = fields.Str(required=True)

    @post_load
    def make_detail_response(self, data, **kwargs):
        return Detail(**data)
