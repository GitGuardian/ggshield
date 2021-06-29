# -*- coding: utf-8 -*-
# snapshottest: v1 - https://goo.gl/zC4yUc
from __future__ import unicode_literals

from snapshottest import Snapshot


snapshots = Snapshot()

snapshots['test_api_status[test_health_check-False] 1'] = '''status: \x1b[32m\x1b[22m\x1b[22mhealthy\x1b[0m
app-version: 1.26.0-rc.4
secrets-engine-version-version: 2.43.0

'''

snapshots['test_api_status[test_health_check-True] 1'] = '''{"detail": "Valid API key.", "status_code": 200, "app_version": "1.26.0-rc.4", "secrets_engine_version": "2.43.0"}
'''

snapshots['test_api_status[test_health_check_error-False] 1'] = '''status: \x1b[31m\x1b[22m\x1b[22munhealthy (Configuration error.)\x1b[0m
app-version: 1.26.0-rc.4
secrets-engine-version-version: 2.43.0

'''

snapshots['test_quota[quota-False] 1'] = '''Quota available: \x1b[32m\x1b[22m\x1b[22m4998\x1b[0m
Quota used in the last 30 days: 2
Total Quota of the workspace: 5000

'''

snapshots['test_quota[quota-True] 1'] = '''{"count": 2, "limit": 5000, "remaining": 4998, "since": "2021-04-18"}
'''

snapshots['test_quota[quota_half_remaining-False] 1'] = '''Quota available: \x1b[33m\x1b[22m\x1b[22m2500\x1b[0m
Quota used in the last 30 days: 2500
Total Quota of the workspace: 5000

'''

snapshots['test_quota[quota_low_remaining-False] 1'] = '''Quota available: \x1b[31m\x1b[22m\x1b[22m999\x1b[0m
Quota used in the last 30 days: 4001
Total Quota of the workspace: 5000

'''
