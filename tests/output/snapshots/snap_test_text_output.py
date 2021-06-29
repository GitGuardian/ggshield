# -*- coding: utf-8 -*-
# snapshottest: v1 - https://goo.gl/zC4yUc
from __future__ import unicode_literals

from snapshottest import Snapshot


snapshots = Snapshot()

snapshots['test_leak_message[_MULTI_SECRET_ONE_LINE_PATCH_OVERLAY_SCAN_RESULT-clip_long_lines-hide_secrets] 1'] = '''> This is an example header
secrets-engine-version: 2.43.0
🛡️  ⚔️  🛡️  \x1b[94m\x1b[1m\x1b[22m1\x1b[0m incident has been found in file \x1b[93m\x1b[1m\x1b[22mleak.txt\x1b[0m

\x1b[36m\x1b[22m\x1b[22m>>>\x1b[0m Incident 1(\x1b[93m\x1b[1m\x1b[22mSecrets Detection\x1b[0m): \x1b[93m\x1b[1m\x1b[22mFacebook Access Tokens\x1b[0m (Ignore with SHA: \x1b[36m\x1b[22m\x1b[22m38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314\x1b[0m) (1 occurrence)
'''

snapshots['test_leak_message[_MULTI_SECRET_ONE_LINE_PATCH_OVERLAY_SCAN_RESULT-clip_long_lines-show_secrets] 1'] = '''> This is an example header
secrets-engine-version: 2.43.0
🛡️  ⚔️  🛡️  \x1b[94m\x1b[1m\x1b[22m1\x1b[0m incident has been found in file \x1b[93m\x1b[1m\x1b[22mleak.txt\x1b[0m

\x1b[36m\x1b[22m\x1b[22m>>>\x1b[0m Incident 1(\x1b[93m\x1b[1m\x1b[22mSecrets Detection\x1b[0m): \x1b[93m\x1b[1m\x1b[22mFacebook Access Tokens\x1b[0m (Ignore with SHA: \x1b[36m\x1b[22m\x1b[22m38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314\x1b[0m) (1 occurrence)
'''

snapshots['test_leak_message[_MULTI_SECRET_ONE_LINE_PATCH_OVERLAY_SCAN_RESULT-verbose-hide_secrets] 1'] = '''> This is an example header
secrets-engine-version: 2.43.0
🛡️  ⚔️  🛡️  \x1b[94m\x1b[1m\x1b[22m1\x1b[0m incident has been found in file \x1b[93m\x1b[1m\x1b[22mleak.txt\x1b[0m

\x1b[36m\x1b[22m\x1b[22m>>>\x1b[0m Incident 1(\x1b[93m\x1b[1m\x1b[22mSecrets Detection\x1b[0m): \x1b[93m\x1b[1m\x1b[22mFacebook Access Tokens\x1b[0m (Ignore with SHA: \x1b[36m\x1b[22m\x1b[22m38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314\x1b[0m) (1 occurrence)
'''

snapshots['test_leak_message[_MULTI_SECRET_ONE_LINE_PATCH_OVERLAY_SCAN_RESULT-verbose-show_secrets] 1'] = '''> This is an example header
secrets-engine-version: 2.43.0
🛡️  ⚔️  🛡️  \x1b[94m\x1b[1m\x1b[22m1\x1b[0m incident has been found in file \x1b[93m\x1b[1m\x1b[22mleak.txt\x1b[0m

\x1b[36m\x1b[22m\x1b[22m>>>\x1b[0m Incident 1(\x1b[93m\x1b[1m\x1b[22mSecrets Detection\x1b[0m): \x1b[93m\x1b[1m\x1b[22mFacebook Access Tokens\x1b[0m (Ignore with SHA: \x1b[36m\x1b[22m\x1b[22m38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314\x1b[0m) (1 occurrence)
'''

snapshots['test_leak_message[_MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT-clip_long_lines-hide_secrets] 1'] = '''> This is an example header
secrets-engine-version: 2.43.0
🛡️  ⚔️  🛡️  \x1b[94m\x1b[1m\x1b[22m1\x1b[0m incident has been found in file \x1b[93m\x1b[1m\x1b[22mleak.txt\x1b[0m

\x1b[36m\x1b[22m\x1b[22m>>>\x1b[0m Incident 1(\x1b[93m\x1b[1m\x1b[22mSecrets Detection\x1b[0m): \x1b[93m\x1b[1m\x1b[22mFacebook Access Tokens\x1b[0m (Ignore with SHA: \x1b[36m\x1b[22m\x1b[22m38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314\x1b[0m) (1 occurrence)
'''

snapshots['test_leak_message[_MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT-clip_long_lines-show_secrets] 1'] = '''> This is an example header
secrets-engine-version: 2.43.0
🛡️  ⚔️  🛡️  \x1b[94m\x1b[1m\x1b[22m1\x1b[0m incident has been found in file \x1b[93m\x1b[1m\x1b[22mleak.txt\x1b[0m

\x1b[36m\x1b[22m\x1b[22m>>>\x1b[0m Incident 1(\x1b[93m\x1b[1m\x1b[22mSecrets Detection\x1b[0m): \x1b[93m\x1b[1m\x1b[22mFacebook Access Tokens\x1b[0m (Ignore with SHA: \x1b[36m\x1b[22m\x1b[22m38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314\x1b[0m) (1 occurrence)
'''

snapshots['test_leak_message[_MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT-verbose-hide_secrets] 1'] = '''> This is an example header
secrets-engine-version: 2.43.0
🛡️  ⚔️  🛡️  \x1b[94m\x1b[1m\x1b[22m1\x1b[0m incident has been found in file \x1b[93m\x1b[1m\x1b[22mleak.txt\x1b[0m

\x1b[36m\x1b[22m\x1b[22m>>>\x1b[0m Incident 1(\x1b[93m\x1b[1m\x1b[22mSecrets Detection\x1b[0m): \x1b[93m\x1b[1m\x1b[22mFacebook Access Tokens\x1b[0m (Ignore with SHA: \x1b[36m\x1b[22m\x1b[22m38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314\x1b[0m) (1 occurrence)
'''

snapshots['test_leak_message[_MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT-verbose-show_secrets] 1'] = '''> This is an example header
secrets-engine-version: 2.43.0
🛡️  ⚔️  🛡️  \x1b[94m\x1b[1m\x1b[22m1\x1b[0m incident has been found in file \x1b[93m\x1b[1m\x1b[22mleak.txt\x1b[0m

\x1b[36m\x1b[22m\x1b[22m>>>\x1b[0m Incident 1(\x1b[93m\x1b[1m\x1b[22mSecrets Detection\x1b[0m): \x1b[93m\x1b[1m\x1b[22mFacebook Access Tokens\x1b[0m (Ignore with SHA: \x1b[36m\x1b[22m\x1b[22m38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314\x1b[0m) (1 occurrence)
'''

snapshots['test_leak_message[_MULTI_SECRET_TWO_LINES_PATCH_SCAN_RESULT-clip_long_lines-hide_secrets] 1'] = '''> This is an example header
secrets-engine-version: 2.43.0
🛡️  ⚔️  🛡️  \x1b[94m\x1b[1m\x1b[22m1\x1b[0m incident has been found in file \x1b[93m\x1b[1m\x1b[22mleak.txt\x1b[0m

\x1b[36m\x1b[22m\x1b[22m>>>\x1b[0m Incident 1(\x1b[93m\x1b[1m\x1b[22mSecrets Detection\x1b[0m): \x1b[93m\x1b[1m\x1b[22mFacebook Access Tokens\x1b[0m (Ignore with SHA: \x1b[36m\x1b[22m\x1b[22m38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314\x1b[0m) (1 occurrence)
'''

snapshots['test_leak_message[_MULTI_SECRET_TWO_LINES_PATCH_SCAN_RESULT-clip_long_lines-show_secrets] 1'] = '''> This is an example header
secrets-engine-version: 2.43.0
🛡️  ⚔️  🛡️  \x1b[94m\x1b[1m\x1b[22m1\x1b[0m incident has been found in file \x1b[93m\x1b[1m\x1b[22mleak.txt\x1b[0m

\x1b[36m\x1b[22m\x1b[22m>>>\x1b[0m Incident 1(\x1b[93m\x1b[1m\x1b[22mSecrets Detection\x1b[0m): \x1b[93m\x1b[1m\x1b[22mFacebook Access Tokens\x1b[0m (Ignore with SHA: \x1b[36m\x1b[22m\x1b[22m38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314\x1b[0m) (1 occurrence)
'''

snapshots['test_leak_message[_MULTI_SECRET_TWO_LINES_PATCH_SCAN_RESULT-verbose-hide_secrets] 1'] = '''> This is an example header
secrets-engine-version: 2.43.0
🛡️  ⚔️  🛡️  \x1b[94m\x1b[1m\x1b[22m1\x1b[0m incident has been found in file \x1b[93m\x1b[1m\x1b[22mleak.txt\x1b[0m

\x1b[36m\x1b[22m\x1b[22m>>>\x1b[0m Incident 1(\x1b[93m\x1b[1m\x1b[22mSecrets Detection\x1b[0m): \x1b[93m\x1b[1m\x1b[22mFacebook Access Tokens\x1b[0m (Ignore with SHA: \x1b[36m\x1b[22m\x1b[22m38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314\x1b[0m) (1 occurrence)
'''

snapshots['test_leak_message[_MULTI_SECRET_TWO_LINES_PATCH_SCAN_RESULT-verbose-show_secrets] 1'] = '''> This is an example header
secrets-engine-version: 2.43.0
🛡️  ⚔️  🛡️  \x1b[94m\x1b[1m\x1b[22m1\x1b[0m incident has been found in file \x1b[93m\x1b[1m\x1b[22mleak.txt\x1b[0m

\x1b[36m\x1b[22m\x1b[22m>>>\x1b[0m Incident 1(\x1b[93m\x1b[1m\x1b[22mSecrets Detection\x1b[0m): \x1b[93m\x1b[1m\x1b[22mFacebook Access Tokens\x1b[0m (Ignore with SHA: \x1b[36m\x1b[22m\x1b[22m38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314\x1b[0m) (1 occurrence)
'''

snapshots['test_leak_message[_ONE_LINE_AND_MULTILINE_PATCH_CONTENT-clip_long_lines-hide_secrets] 1'] = '''> This is an example header
secrets-engine-version: 2.43.0
🛡️  ⚔️  🛡️  \x1b[94m\x1b[1m\x1b[22m3\x1b[0m incidents have been found in file \x1b[93m\x1b[1m\x1b[22mleak.txt\x1b[0m

\x1b[36m\x1b[22m\x1b[22m>>>\x1b[0m Incident 1(\x1b[93m\x1b[1m\x1b[22mSecrets Detection\x1b[0m): \x1b[93m\x1b[1m\x1b[22mFacebook Access Tokens\x1b[0m (Ignore with SHA: \x1b[36m\x1b[22m\x1b[22m1945f4a0c42abb19c1a420ddd09b4b4681249a3057c427b95f794b18595e7ffa\x1b[0m) (1 occurrence)

\x1b[36m\x1b[22m\x1b[22m>>>\x1b[0m Incident 2(\x1b[93m\x1b[1m\x1b[22mSecrets detection\x1b[0m): \x1b[93m\x1b[1m\x1b[22mRSA Private Key\x1b[0m (Ignore with SHA: \x1b[36m\x1b[22m\x1b[22m060bf63de122848f5efa122fe6cea504aae3b24cea393d887fdefa1529c6a02e\x1b[0m) (1 occurrence)
\x1b[37m\x1b[22m\x1b[2m \x1b[0m \x1b[37m\x1b[22m\x1b[2m \x1b[0m | \x1b[37m\x1b[22m\x1b[22m@@ -0,0 +1,29 @\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m1\x1b[0m | \x1b[37m\x1b[22m\x1b[22m…**5733 /ce3f9f********************5e43711 \x1b[0m\x1b[91m\x1b[22m\x1b[22m-----BEGIN RSA PRIVATE KEY-----\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m2\x1b[0m | \x1b[91m\x1b[22m\x1b[22m+MIIBOgIBAAJBAIIRkYjxjE3KIZi******************************+******\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m3\x1b[0m | \x1b[91m\x1b[22m\x1b[22m+****************************************************************\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m4\x1b[0m | \x1b[91m\x1b[22m\x1b[22m+****************************************************************\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m5\x1b[0m | \x1b[91m\x1b[22m\x1b[22m+***********+****************************************************\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m6\x1b[0m | \x1b[91m\x1b[22m\x1b[22m+****************+***********************************************\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m7\x1b[0m | \x1b[91m\x1b[22m\x1b[22m+**********************+*****************************************\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m8\x1b[0m | \x1b[91m\x1b[22m\x1b[22m+****+******Xme/ovcDeM1+3W/UmSHYUW4b3WYq4\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m9\x1b[0m | \x1b[91m\x1b[22m\x1b[22m-----END RSA PRIVATE KEY----- \x1b[0m\x1b[37m\x1b[22m\x1b[22mtoken: SG._Yytrtvlj************************…\x1b[0m
      \x1b[93m\x1b[1m\x1b[22m\x1b[93m\x1b[1m\x1b[22m|_________________________________apikey_________________________________|\x1b[0m
\x1b[0m
\x1b[36m\x1b[22m\x1b[22m>>>\x1b[0m Incident 3(\x1b[93m\x1b[1m\x1b[22mSecrets detection\x1b[0m): \x1b[93m\x1b[1m\x1b[22mSendGrid Key\x1b[0m (Ignore with SHA: \x1b[36m\x1b[22m\x1b[22m530e5a4a7ea00814db8845dd0cae5efaa4b974a3ce1c76d0384ba715248a5dc1\x1b[0m) (1 occurrence)
\x1b[37m\x1b[22m\x1b[2m \x1b[0m \x1b[37m\x1b[22m\x1b[2m7\x1b[0m | \x1b[37m\x1b[22m\x1b[22m**********************+*****************************************\x1b[0m
\x1b[37m\x1b[22m\x1b[2m \x1b[0m \x1b[37m\x1b[22m\x1b[2m8\x1b[0m | \x1b[37m\x1b[22m\x1b[22m****+******Xme/ovcDeM1+3W/UmSHYUW4b3WYq4\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m9\x1b[0m | \x1b[37m\x1b[22m\x1b[22m…-- token: \x1b[0m\x1b[91m\x1b[22m\x1b[22mSG._Yytrtvlj******************************************-**rRJLGFLBLf0M\x1b[0m
      \x1b[93m\x1b[1m\x1b[22m           \x1b[93m\x1b[1m\x1b[22m|_______________________________apikey______________________________|\x1b[0m
\x1b[0m'''

snapshots['test_leak_message[_ONE_LINE_AND_MULTILINE_PATCH_CONTENT-clip_long_lines-show_secrets] 1'] = '''> This is an example header
secrets-engine-version: 2.43.0
🛡️  ⚔️  🛡️  \x1b[94m\x1b[1m\x1b[22m3\x1b[0m incidents have been found in file \x1b[93m\x1b[1m\x1b[22mleak.txt\x1b[0m

\x1b[36m\x1b[22m\x1b[22m>>>\x1b[0m Incident 1(\x1b[93m\x1b[1m\x1b[22mSecrets Detection\x1b[0m): \x1b[93m\x1b[1m\x1b[22mFacebook Access Tokens\x1b[0m (Ignore with SHA: \x1b[36m\x1b[22m\x1b[22m1945f4a0c42abb19c1a420ddd09b4b4681249a3057c427b95f794b18595e7ffa\x1b[0m) (1 occurrence)

\x1b[36m\x1b[22m\x1b[22m>>>\x1b[0m Incident 2(\x1b[93m\x1b[1m\x1b[22mSecrets detection\x1b[0m): \x1b[93m\x1b[1m\x1b[22mRSA Private Key\x1b[0m (Ignore with SHA: \x1b[36m\x1b[22m\x1b[22m060bf63de122848f5efa122fe6cea504aae3b24cea393d887fdefa1529c6a02e\x1b[0m) (1 occurrence)
\x1b[37m\x1b[22m\x1b[2m \x1b[0m \x1b[37m\x1b[22m\x1b[2m \x1b[0m | \x1b[37m\x1b[22m\x1b[22m@@ -0,0 +1,29 @\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m1\x1b[0m | \x1b[37m\x1b[22m\x1b[22m…041573 / ce3f9f0362bbe5ab01dfc8ee565e4371 \x1b[0m\x1b[91m\x1b[22m\x1b[22m-----BEGIN RSA PRIVATE KEY-----\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m2\x1b[0m | \x1b[91m\x1b[22m\x1b[22m+MIIBOgIBAAJBAIIRkYjxjE3KIZiEc8k4sWWGNsPYRNE0u0bl5oFVApPLm+uXQ/4l\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m3\x1b[0m | \x1b[91m\x1b[22m\x1b[22m+bKO9LFtMiVPy700oMWLScwAN5OAiqVLMvHUCAwEAAQJANLr8nmEWuV6t2hAwhK5I\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m4\x1b[0m | \x1b[91m\x1b[22m\x1b[22m+NNmBkEo4M/xFxEtl9J7LKbE2gtNrlCQiJlPP1EMhwAjDOzQcJ3lgFB28dkqH5rMW\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m5\x1b[0m | \x1b[91m\x1b[22m\x1b[22m+TQIhANrCE7O+wlCKe0WJqQ3lYlHG91XWyGVgfExJwBDsAD9LAiEAmDY5OSsH0n2A\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m6\x1b[0m | \x1b[91m\x1b[22m\x1b[22m+22tthkAvcN1s66lG+0DztOVJ4QLI2z8CIBPeDGwGpx8pdIicN/5LFuLWbyAcoZaT\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m7\x1b[0m | \x1b[91m\x1b[22m\x1b[22m+bLaA/DCNPniBAiA0l//bzg+M3srIhm04xzLdR9Vb9IjPRlkvN074zdKDVwIhAKJb\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m8\x1b[0m | \x1b[91m\x1b[22m\x1b[22m+RF3C+CMFb0wXme/ovcDeM1+3W/UmSHYUW4b3WYq4\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m9\x1b[0m | \x1b[91m\x1b[22m\x1b[22m-----END RSA PRIVATE KEY----- \x1b[0m\x1b[37m\x1b[22m\x1b[22mtoken: SG._YytrtvljkWqCrkMa3r5hw.yijiPf2qxr…\x1b[0m
      \x1b[93m\x1b[1m\x1b[22m\x1b[93m\x1b[1m\x1b[22m|_________________________________apikey_________________________________|\x1b[0m
\x1b[0m
\x1b[36m\x1b[22m\x1b[22m>>>\x1b[0m Incident 3(\x1b[93m\x1b[1m\x1b[22mSecrets detection\x1b[0m): \x1b[93m\x1b[1m\x1b[22mSendGrid Key\x1b[0m (Ignore with SHA: \x1b[36m\x1b[22m\x1b[22m530e5a4a7ea00814db8845dd0cae5efaa4b974a3ce1c76d0384ba715248a5dc1\x1b[0m) (1 occurrence)
\x1b[37m\x1b[22m\x1b[2m \x1b[0m \x1b[37m\x1b[22m\x1b[2m7\x1b[0m | \x1b[37m\x1b[22m\x1b[22mbLaA/DCNPniBAiA0l//bzg+M3srIhm04xzLdR9Vb9IjPRlkvN074zdKDVwIhAKJb\x1b[0m
\x1b[37m\x1b[22m\x1b[2m \x1b[0m \x1b[37m\x1b[22m\x1b[2m8\x1b[0m | \x1b[37m\x1b[22m\x1b[22mRF3C+CMFb0wXme/ovcDeM1+3W/UmSHYUW4b3WYq4\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m9\x1b[0m | \x1b[37m\x1b[22m\x1b[22m…-- token: \x1b[0m\x1b[91m\x1b[22m\x1b[22mSG._YytrtvljkWqCrkMa3r5hw.yijiPf2qxr2rYArkz3xlLrbv5Zr7-gtrRJLGFLBLf0M\x1b[0m
      \x1b[93m\x1b[1m\x1b[22m           \x1b[93m\x1b[1m\x1b[22m|_______________________________apikey______________________________|\x1b[0m
\x1b[0m'''

snapshots['test_leak_message[_ONE_LINE_AND_MULTILINE_PATCH_CONTENT-verbose-hide_secrets] 1'] = '''> This is an example header
secrets-engine-version: 2.43.0
🛡️  ⚔️  🛡️  \x1b[94m\x1b[1m\x1b[22m3\x1b[0m incidents have been found in file \x1b[93m\x1b[1m\x1b[22mleak.txt\x1b[0m

\x1b[36m\x1b[22m\x1b[22m>>>\x1b[0m Incident 1(\x1b[93m\x1b[1m\x1b[22mSecrets Detection\x1b[0m): \x1b[93m\x1b[1m\x1b[22mFacebook Access Tokens\x1b[0m (Ignore with SHA: \x1b[36m\x1b[22m\x1b[22m1945f4a0c42abb19c1a420ddd09b4b4681249a3057c427b95f794b18595e7ffa\x1b[0m) (1 occurrence)

\x1b[36m\x1b[22m\x1b[22m>>>\x1b[0m Incident 2(\x1b[93m\x1b[1m\x1b[22mSecrets detection\x1b[0m): \x1b[93m\x1b[1m\x1b[22mRSA Private Key\x1b[0m (Ignore with SHA: \x1b[36m\x1b[22m\x1b[22m060bf63de122848f5efa122fe6cea504aae3b24cea393d887fdefa1529c6a02e\x1b[0m) (1 occurrence)
\x1b[37m\x1b[22m\x1b[2m \x1b[0m \x1b[37m\x1b[22m\x1b[2m \x1b[0m | \x1b[37m\x1b[22m\x1b[22m@@ -0,0 +1,29 @\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m1\x1b[0m | \x1b[37m\x1b[22m\x1b[22mFacebookAppKeys:294*********5733 /ce3f9f********************5e43711 \x1b[0m\x1b[91m\x1b[22m\x1b[22m-----BEGIN RSA PRIVATE KEY-----\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m2\x1b[0m | \x1b[91m\x1b[22m\x1b[22m+MIIBOgIBAAJBAIIRkYjxjE3KIZi******************************+******\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m3\x1b[0m | \x1b[91m\x1b[22m\x1b[22m+****************************************************************\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m4\x1b[0m | \x1b[91m\x1b[22m\x1b[22m+****************************************************************\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m5\x1b[0m | \x1b[91m\x1b[22m\x1b[22m+***********+****************************************************\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m6\x1b[0m | \x1b[91m\x1b[22m\x1b[22m+****************+***********************************************\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m7\x1b[0m | \x1b[91m\x1b[22m\x1b[22m+**********************+*****************************************\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m8\x1b[0m | \x1b[91m\x1b[22m\x1b[22m+****+******Xme/ovcDeM1+3W/UmSHYUW4b3WYq4\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m9\x1b[0m | \x1b[91m\x1b[22m\x1b[22m-----END RSA PRIVATE KEY----- \x1b[0m\x1b[37m\x1b[22m\x1b[22mtoken: SG._Yytrtvlj******************************************-**rRJLGFLBLf0M\x1b[0m
      \x1b[93m\x1b[1m\x1b[22m\x1b[93m\x1b[1m\x1b[22m\x1b[0m
\x1b[0m
\x1b[36m\x1b[22m\x1b[22m>>>\x1b[0m Incident 3(\x1b[93m\x1b[1m\x1b[22mSecrets detection\x1b[0m): \x1b[93m\x1b[1m\x1b[22mSendGrid Key\x1b[0m (Ignore with SHA: \x1b[36m\x1b[22m\x1b[22m530e5a4a7ea00814db8845dd0cae5efaa4b974a3ce1c76d0384ba715248a5dc1\x1b[0m) (1 occurrence)
\x1b[37m\x1b[22m\x1b[2m \x1b[0m \x1b[37m\x1b[22m\x1b[2m7\x1b[0m | \x1b[37m\x1b[22m\x1b[22m**********************+*****************************************\x1b[0m
\x1b[37m\x1b[22m\x1b[2m \x1b[0m \x1b[37m\x1b[22m\x1b[2m8\x1b[0m | \x1b[37m\x1b[22m\x1b[22m****+******Xme/ovcDeM1+3W/UmSHYUW4b3WYq4\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m9\x1b[0m | \x1b[37m\x1b[22m\x1b[22m-----END RSA PRIVATE KEY----- token: \x1b[0m\x1b[91m\x1b[22m\x1b[22mSG._Yytrtvlj******************************************-**rRJLGFLBLf0M\x1b[0m
      \x1b[93m\x1b[1m\x1b[22m                                     \x1b[93m\x1b[1m\x1b[22m|_______________________________apikey______________________________|\x1b[0m
\x1b[0m'''

snapshots['test_leak_message[_ONE_LINE_AND_MULTILINE_PATCH_CONTENT-verbose-show_secrets] 1'] = '''> This is an example header
secrets-engine-version: 2.43.0
🛡️  ⚔️  🛡️  \x1b[94m\x1b[1m\x1b[22m3\x1b[0m incidents have been found in file \x1b[93m\x1b[1m\x1b[22mleak.txt\x1b[0m

\x1b[36m\x1b[22m\x1b[22m>>>\x1b[0m Incident 1(\x1b[93m\x1b[1m\x1b[22mSecrets Detection\x1b[0m): \x1b[93m\x1b[1m\x1b[22mFacebook Access Tokens\x1b[0m (Ignore with SHA: \x1b[36m\x1b[22m\x1b[22m1945f4a0c42abb19c1a420ddd09b4b4681249a3057c427b95f794b18595e7ffa\x1b[0m) (1 occurrence)

\x1b[36m\x1b[22m\x1b[22m>>>\x1b[0m Incident 2(\x1b[93m\x1b[1m\x1b[22mSecrets detection\x1b[0m): \x1b[93m\x1b[1m\x1b[22mRSA Private Key\x1b[0m (Ignore with SHA: \x1b[36m\x1b[22m\x1b[22m060bf63de122848f5efa122fe6cea504aae3b24cea393d887fdefa1529c6a02e\x1b[0m) (1 occurrence)
\x1b[37m\x1b[22m\x1b[2m \x1b[0m \x1b[37m\x1b[22m\x1b[2m \x1b[0m | \x1b[37m\x1b[22m\x1b[22m@@ -0,0 +1,29 @\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m1\x1b[0m | \x1b[37m\x1b[22m\x1b[22mFacebookAppKeys: 294790898041573 / ce3f9f0362bbe5ab01dfc8ee565e4371 \x1b[0m\x1b[91m\x1b[22m\x1b[22m-----BEGIN RSA PRIVATE KEY-----\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m2\x1b[0m | \x1b[91m\x1b[22m\x1b[22m+MIIBOgIBAAJBAIIRkYjxjE3KIZiEc8k4sWWGNsPYRNE0u0bl5oFVApPLm+uXQ/4l\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m3\x1b[0m | \x1b[91m\x1b[22m\x1b[22m+bKO9LFtMiVPy700oMWLScwAN5OAiqVLMvHUCAwEAAQJANLr8nmEWuV6t2hAwhK5I\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m4\x1b[0m | \x1b[91m\x1b[22m\x1b[22m+NNmBkEo4M/xFxEtl9J7LKbE2gtNrlCQiJlPP1EMhwAjDOzQcJ3lgFB28dkqH5rMW\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m5\x1b[0m | \x1b[91m\x1b[22m\x1b[22m+TQIhANrCE7O+wlCKe0WJqQ3lYlHG91XWyGVgfExJwBDsAD9LAiEAmDY5OSsH0n2A\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m6\x1b[0m | \x1b[91m\x1b[22m\x1b[22m+22tthkAvcN1s66lG+0DztOVJ4QLI2z8CIBPeDGwGpx8pdIicN/5LFuLWbyAcoZaT\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m7\x1b[0m | \x1b[91m\x1b[22m\x1b[22m+bLaA/DCNPniBAiA0l//bzg+M3srIhm04xzLdR9Vb9IjPRlkvN074zdKDVwIhAKJb\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m8\x1b[0m | \x1b[91m\x1b[22m\x1b[22m+RF3C+CMFb0wXme/ovcDeM1+3W/UmSHYUW4b3WYq4\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m9\x1b[0m | \x1b[91m\x1b[22m\x1b[22m-----END RSA PRIVATE KEY----- \x1b[0m\x1b[37m\x1b[22m\x1b[22mtoken: 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\x1b[0m
      \x1b[93m\x1b[1m\x1b[22m\x1b[93m\x1b[1m\x1b[22m\x1b[0m
\x1b[0m
\x1b[36m\x1b[22m\x1b[22m>>>\x1b[0m Incident 3(\x1b[93m\x1b[1m\x1b[22mSecrets detection\x1b[0m): \x1b[93m\x1b[1m\x1b[22mSendGrid Key\x1b[0m (Ignore with SHA: \x1b[36m\x1b[22m\x1b[22m530e5a4a7ea00814db8845dd0cae5efaa4b974a3ce1c76d0384ba715248a5dc1\x1b[0m) (1 occurrence)
\x1b[37m\x1b[22m\x1b[2m \x1b[0m \x1b[37m\x1b[22m\x1b[2m7\x1b[0m | \x1b[37m\x1b[22m\x1b[22mbLaA/DCNPniBAiA0l//bzg+M3srIhm04xzLdR9Vb9IjPRlkvN074zdKDVwIhAKJb\x1b[0m
\x1b[37m\x1b[22m\x1b[2m \x1b[0m \x1b[37m\x1b[22m\x1b[2m8\x1b[0m | \x1b[37m\x1b[22m\x1b[22mRF3C+CMFb0wXme/ovcDeM1+3W/UmSHYUW4b3WYq4\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m9\x1b[0m | \x1b[37m\x1b[22m\x1b[22m-----END RSA PRIVATE KEY----- token: \x1b[0m\x1b[91m\x1b[22m\x1b[22mSG._YytrtvljkWqCrkMa3r5hw.yijiPf2qxr2rYArkz3xlLrbv5Zr7-gtrRJLGFLBLf0M\x1b[0m
      \x1b[93m\x1b[1m\x1b[22m                                     \x1b[93m\x1b[1m\x1b[22m|_______________________________apikey______________________________|\x1b[0m
\x1b[0m'''

snapshots['test_leak_message[_SIMPLE_SECRET_MULTILINE_PATCH_SCAN_RESULT-clip_long_lines-hide_secrets] 1'] = '''> This is an example header
secrets-engine-version: 2.43.0
🛡️  ⚔️  🛡️  \x1b[94m\x1b[1m\x1b[22m1\x1b[0m incident has been found in file \x1b[93m\x1b[1m\x1b[22mleak.txt\x1b[0m

\x1b[36m\x1b[22m\x1b[22m>>>\x1b[0m Incident 1(\x1b[93m\x1b[1m\x1b[22mSecrets Detection\x1b[0m): \x1b[93m\x1b[1m\x1b[22mRSA Private Key\x1b[0m (Ignore with SHA: \x1b[36m\x1b[22m\x1b[22m060bf63de122848f5efa122fe6cea504aae3b24cea393d887fdefa1529c6a02e\x1b[0m) (1 occurrence)
'''

snapshots['test_leak_message[_SIMPLE_SECRET_MULTILINE_PATCH_SCAN_RESULT-clip_long_lines-show_secrets] 1'] = '''> This is an example header
secrets-engine-version: 2.43.0
🛡️  ⚔️  🛡️  \x1b[94m\x1b[1m\x1b[22m1\x1b[0m incident has been found in file \x1b[93m\x1b[1m\x1b[22mleak.txt\x1b[0m

\x1b[36m\x1b[22m\x1b[22m>>>\x1b[0m Incident 1(\x1b[93m\x1b[1m\x1b[22mSecrets Detection\x1b[0m): \x1b[93m\x1b[1m\x1b[22mRSA Private Key\x1b[0m (Ignore with SHA: \x1b[36m\x1b[22m\x1b[22m060bf63de122848f5efa122fe6cea504aae3b24cea393d887fdefa1529c6a02e\x1b[0m) (1 occurrence)
'''

snapshots['test_leak_message[_SIMPLE_SECRET_MULTILINE_PATCH_SCAN_RESULT-verbose-hide_secrets] 1'] = '''> This is an example header
secrets-engine-version: 2.43.0
🛡️  ⚔️  🛡️  \x1b[94m\x1b[1m\x1b[22m1\x1b[0m incident has been found in file \x1b[93m\x1b[1m\x1b[22mleak.txt\x1b[0m

\x1b[36m\x1b[22m\x1b[22m>>>\x1b[0m Incident 1(\x1b[93m\x1b[1m\x1b[22mSecrets Detection\x1b[0m): \x1b[93m\x1b[1m\x1b[22mRSA Private Key\x1b[0m (Ignore with SHA: \x1b[36m\x1b[22m\x1b[22m060bf63de122848f5efa122fe6cea504aae3b24cea393d887fdefa1529c6a02e\x1b[0m) (1 occurrence)
'''

snapshots['test_leak_message[_SIMPLE_SECRET_MULTILINE_PATCH_SCAN_RESULT-verbose-show_secrets] 1'] = '''> This is an example header
secrets-engine-version: 2.43.0
🛡️  ⚔️  🛡️  \x1b[94m\x1b[1m\x1b[22m1\x1b[0m incident has been found in file \x1b[93m\x1b[1m\x1b[22mleak.txt\x1b[0m

\x1b[36m\x1b[22m\x1b[22m>>>\x1b[0m Incident 1(\x1b[93m\x1b[1m\x1b[22mSecrets Detection\x1b[0m): \x1b[93m\x1b[1m\x1b[22mRSA Private Key\x1b[0m (Ignore with SHA: \x1b[36m\x1b[22m\x1b[22m060bf63de122848f5efa122fe6cea504aae3b24cea393d887fdefa1529c6a02e\x1b[0m) (1 occurrence)
'''

snapshots['test_leak_message[_SIMPLE_SECRET_PATCH_SCAN_RESULT-clip_long_lines-hide_secrets] 1'] = '''> This is an example header
secrets-engine-version: 2.43.0
🛡️  ⚔️  🛡️  \x1b[94m\x1b[1m\x1b[22m1\x1b[0m incident has been found in file \x1b[93m\x1b[1m\x1b[22mleak.txt\x1b[0m

\x1b[36m\x1b[22m\x1b[22m>>>\x1b[0m Incident 1(\x1b[93m\x1b[1m\x1b[22mSecrets Detection\x1b[0m): \x1b[93m\x1b[1m\x1b[22mGitHub Token\x1b[0m (Ignore with SHA: \x1b[36m\x1b[22m\x1b[22m2b5840babacb6f089ddcce1fe5a56b803f8b1f636c6f44cdbf14b0c77a194c93\x1b[0m) (1 occurrence)
'''

snapshots['test_leak_message[_SIMPLE_SECRET_PATCH_SCAN_RESULT-clip_long_lines-show_secrets] 1'] = '''> This is an example header
secrets-engine-version: 2.43.0
🛡️  ⚔️  🛡️  \x1b[94m\x1b[1m\x1b[22m1\x1b[0m incident has been found in file \x1b[93m\x1b[1m\x1b[22mleak.txt\x1b[0m

\x1b[36m\x1b[22m\x1b[22m>>>\x1b[0m Incident 1(\x1b[93m\x1b[1m\x1b[22mSecrets Detection\x1b[0m): \x1b[93m\x1b[1m\x1b[22mGitHub Token\x1b[0m (Ignore with SHA: \x1b[36m\x1b[22m\x1b[22m2b5840babacb6f089ddcce1fe5a56b803f8b1f636c6f44cdbf14b0c77a194c93\x1b[0m) (1 occurrence)
'''

snapshots['test_leak_message[_SIMPLE_SECRET_PATCH_SCAN_RESULT-verbose-hide_secrets] 1'] = '''> This is an example header
secrets-engine-version: 2.43.0
🛡️  ⚔️  🛡️  \x1b[94m\x1b[1m\x1b[22m1\x1b[0m incident has been found in file \x1b[93m\x1b[1m\x1b[22mleak.txt\x1b[0m

\x1b[36m\x1b[22m\x1b[22m>>>\x1b[0m Incident 1(\x1b[93m\x1b[1m\x1b[22mSecrets Detection\x1b[0m): \x1b[93m\x1b[1m\x1b[22mGitHub Token\x1b[0m (Ignore with SHA: \x1b[36m\x1b[22m\x1b[22m2b5840babacb6f089ddcce1fe5a56b803f8b1f636c6f44cdbf14b0c77a194c93\x1b[0m) (1 occurrence)
'''

snapshots['test_leak_message[_SIMPLE_SECRET_PATCH_SCAN_RESULT-verbose-show_secrets] 1'] = '''> This is an example header
secrets-engine-version: 2.43.0
🛡️  ⚔️  🛡️  \x1b[94m\x1b[1m\x1b[22m1\x1b[0m incident has been found in file \x1b[93m\x1b[1m\x1b[22mleak.txt\x1b[0m

\x1b[36m\x1b[22m\x1b[22m>>>\x1b[0m Incident 1(\x1b[93m\x1b[1m\x1b[22mSecrets Detection\x1b[0m): \x1b[93m\x1b[1m\x1b[22mGitHub Token\x1b[0m (Ignore with SHA: \x1b[36m\x1b[22m\x1b[22m2b5840babacb6f089ddcce1fe5a56b803f8b1f636c6f44cdbf14b0c77a194c93\x1b[0m) (1 occurrence)
'''
