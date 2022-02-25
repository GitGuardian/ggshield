# -*- coding: utf-8 -*-
# snapshottest: v1 - https://goo.gl/zC4yUc
from __future__ import unicode_literals

from snapshottest import Snapshot


snapshots = Snapshot()

snapshots['test_api_status[test_health_check-False] 1'] = '''API URL: https://api.gitguardian.com/
Status: healthy
App version: 1.32.0-rc.2
Secrets engine version: 2.56.0

'''

snapshots['test_api_status[test_health_check-True] 1'] = '''{"detail": "Valid API key.", "status_code": 200, "app_version": "1.32.0-rc.2", "secrets_engine_version": "2.56.0"}
'''

snapshots['test_api_status[test_health_check_error-False] 1'] = '''API URL: https://api.gitguardian.com/
Status: healthy
App version: 1.32.0-rc.2
Secrets engine version: 2.56.0

'''

snapshots['test_quota[quota-False] 1'] = '''Quota available: 806
Quota used in the last 30 days: 194
Total Quota of the workspace: 1000

'''

snapshots['test_quota[quota-True] 1'] = '''{"count": 194, "limit": 1000, "remaining": 806, "since": "2021-11-02"}
'''

snapshots['test_quota[quota_half_remaining-False] 1'] = '''Quota available: 806
Quota used in the last 30 days: 194
Total Quota of the workspace: 1000

'''

snapshots['test_quota[quota_low_remaining-False] 1'] = '''Quota available: 806
Quota used in the last 30 days: 194
Total Quota of the workspace: 1000

'''
