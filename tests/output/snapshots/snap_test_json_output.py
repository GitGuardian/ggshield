# -*- coding: utf-8 -*-
# snapshottest: v1 - https://goo.gl/zC4yUc
from __future__ import unicode_literals

from snapshottest import GenericRepr, Snapshot


snapshots = Snapshot()

snapshots['test_json_output[_MULTIPLE_SECRETS] 1'] = {
    'id': 'path',
    'results': [
        {
            'filename': 'test.txt',
            'incidents': [
                {
                    'break_type': 'MySQL Assignment',
                    'ignore_sha': '6ea3195be80ceae4996cda16955ac052425901b50896b02f797e61777fd297e7',
                    'occurrences': [
                        GenericRepr('match:go******om, match_type:host, line_start:2, line_end:2, index_start:78, index_end:88'),
                        GenericRepr('match:5**4, match_type:port, line_start:2, line_end:2, index_start:115, index_end:119'),
                        GenericRepr('match:r**t, match_type:username, line_start:2, line_end:2, index_start:138, index_end:142'),
                        GenericRepr('match:m4******wd, match_type:password, line_start:2, line_end:2, index_start:173, index_end:183')
                    ],
                    'policy': 'Secrets detection',
                    'total_occurrences': 1
                }
            ],
            'mode': 'NEW',
            'total_incidents': 1,
            'total_occurrences': 1
        }
    ],
    'secrets_engine_version': '2.43.0',
    'total_incidents': 1,
    'total_occurrences': 1,
    'type': 'test'
}

snapshots['test_json_output[_NO_SECRET] 1'] = {
    'id': 'path',
    'total_incidents': 0,
    'total_occurrences': 0,
    'type': 'test'
}

snapshots['test_json_output[_ONE_LINE_AND_MULTILINE_PATCH] 1'] = {
    'id': 'path',
    'results': [
        {
            'filename': 'test.txt',
            'incidents': [
                {
                    'break_type': 'RSA Private Key',
                    'ignore_sha': 'bc9ae02c5ca67523e8381ac3908089afb0cf9b82c74e92997d5bedda0016bec4',
                    'occurrences': [
                        GenericRepr('match:-----BEGIN RSA PRIVATE KEY-----\n+MIIBOgIBAAJBAIIRkYjxjE3KIZi******************************+******\n+****************************************************************\n+****************************************************************\n+***********+****************************************************\n+****************+***********************************************\n+**********************+*****************************************\n+****+******Xme/ovcDeM1+3W/UmSHYUW4b3WYq4\n+-----END RSA PRIVATE KEY-----, match_type:apikey, line_start:1, line_end:9, index_start:68, index_end:29')
                    ],
                    'policy': 'Secrets detection',
                    'total_occurrences': 1
                },
                {
                    'break_type': 'SendGrid Key',
                    'ignore_sha': 'eea2fa13bdf04725685594cb0115eab7519f3f0a9aa9f339c34ef4a1ae18d908',
                    'occurrences': [
                        GenericRepr('match:SG._Yytrtvlj******************************************-**rRJLGFLBLf0M, match_type:apikey, line_start:9, line_end:9, index_start:37, index_end:106')
                    ],
                    'policy': 'Secrets detection',
                    'total_occurrences': 1
                }
            ],
            'mode': 'NEW',
            'total_incidents': 2,
            'total_occurrences': 2
        }
    ],
    'secrets_engine_version': '2.43.0',
    'total_incidents': 2,
    'total_occurrences': 2,
    'type': 'test'
}

snapshots['test_json_output[_SIMPLE_SECRET] 1'] = {
    'id': 'path',
    'results': [
        {
            'filename': 'test.txt',
            'incidents': [
                {
                    'break_type': 'SendGrid Key',
                    'ignore_sha': 'eea2fa13bdf04725685594cb0115eab7519f3f0a9aa9f339c34ef4a1ae18d908',
                    'occurrences': [
                        GenericRepr('match:SG._Yytrtvlj******************************************-**rRJLGFLBLf0M, match_type:apikey, line_start:2, line_end:2, index_start:10, index_end:79')
                    ],
                    'policy': 'Secrets detection',
                    'total_occurrences': 1
                }
            ],
            'mode': 'NEW',
            'total_incidents': 1,
            'total_occurrences': 1
        }
    ],
    'secrets_engine_version': '2.43.0',
    'total_incidents': 1,
    'total_occurrences': 1,
    'type': 'test'
}
