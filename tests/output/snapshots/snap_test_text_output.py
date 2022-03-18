# -*- coding: utf-8 -*-
# snapshottest: v1 - https://goo.gl/zC4yUc
from __future__ import unicode_literals

from snapshottest import Snapshot


snapshots = Snapshot()

snapshots['test_leak_message[_MULTI_SECRET_ONE_LINE_PATCH_OVERLAY_SCAN_RESULT-clip_long_lines-hide_secrets] 1'] = '''> This is an example header
secrets-engine-version: 3.14.159

>>> 1 incident has been found in file leak.txt

>>> Incident 1(Secrets Detection): Facebook Access Tokens (Ignore with SHA: 38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314) (1 occurrence)
'''

snapshots['test_leak_message[_MULTI_SECRET_ONE_LINE_PATCH_OVERLAY_SCAN_RESULT-clip_long_lines-show_secrets] 1'] = '''> This is an example header
secrets-engine-version: 3.14.159

>>> 1 incident has been found in file leak.txt

>>> Incident 1(Secrets Detection): Facebook Access Tokens (Ignore with SHA: 38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314) (1 occurrence)
'''

snapshots['test_leak_message[_MULTI_SECRET_ONE_LINE_PATCH_OVERLAY_SCAN_RESULT-verbose-hide_secrets] 1'] = '''> This is an example header
secrets-engine-version: 3.14.159

>>> 1 incident has been found in file leak.txt

>>> Incident 1(Secrets Detection): Facebook Access Tokens (Ignore with SHA: 38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314) (1 occurrence)
'''

snapshots['test_leak_message[_MULTI_SECRET_ONE_LINE_PATCH_OVERLAY_SCAN_RESULT-verbose-show_secrets] 1'] = '''> This is an example header
secrets-engine-version: 3.14.159

>>> 1 incident has been found in file leak.txt

>>> Incident 1(Secrets Detection): Facebook Access Tokens (Ignore with SHA: 38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314) (1 occurrence)
'''

snapshots['test_leak_message[_MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT-clip_long_lines-hide_secrets] 1'] = '''> This is an example header
secrets-engine-version: 3.14.159

>>> 1 incident has been found in file leak.txt

>>> Incident 1(Secrets Detection): Facebook Access Tokens (Ignore with SHA: 38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314) (1 occurrence)
'''

snapshots['test_leak_message[_MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT-clip_long_lines-show_secrets] 1'] = '''> This is an example header
secrets-engine-version: 3.14.159

>>> 1 incident has been found in file leak.txt

>>> Incident 1(Secrets Detection): Facebook Access Tokens (Ignore with SHA: 38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314) (1 occurrence)
'''

snapshots['test_leak_message[_MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT-verbose-hide_secrets] 1'] = '''> This is an example header
secrets-engine-version: 3.14.159

>>> 1 incident has been found in file leak.txt

>>> Incident 1(Secrets Detection): Facebook Access Tokens (Ignore with SHA: 38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314) (1 occurrence)
'''

snapshots['test_leak_message[_MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT-verbose-show_secrets] 1'] = '''> This is an example header
secrets-engine-version: 3.14.159

>>> 1 incident has been found in file leak.txt

>>> Incident 1(Secrets Detection): Facebook Access Tokens (Ignore with SHA: 38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314) (1 occurrence)
'''

snapshots['test_leak_message[_MULTI_SECRET_TWO_LINES_PATCH_SCAN_RESULT-clip_long_lines-hide_secrets] 1'] = '''> This is an example header
secrets-engine-version: 3.14.159

>>> 1 incident has been found in file leak.txt

>>> Incident 1(Secrets Detection): Facebook Access Tokens (Ignore with SHA: 38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314) (1 occurrence)
'''

snapshots['test_leak_message[_MULTI_SECRET_TWO_LINES_PATCH_SCAN_RESULT-clip_long_lines-show_secrets] 1'] = '''> This is an example header
secrets-engine-version: 3.14.159

>>> 1 incident has been found in file leak.txt

>>> Incident 1(Secrets Detection): Facebook Access Tokens (Ignore with SHA: 38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314) (1 occurrence)
'''

snapshots['test_leak_message[_MULTI_SECRET_TWO_LINES_PATCH_SCAN_RESULT-verbose-hide_secrets] 1'] = '''> This is an example header
secrets-engine-version: 3.14.159

>>> 1 incident has been found in file leak.txt

>>> Incident 1(Secrets Detection): Facebook Access Tokens (Ignore with SHA: 38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314) (1 occurrence)
'''

snapshots['test_leak_message[_MULTI_SECRET_TWO_LINES_PATCH_SCAN_RESULT-verbose-show_secrets] 1'] = '''> This is an example header
secrets-engine-version: 3.14.159

>>> 1 incident has been found in file leak.txt

>>> Incident 1(Secrets Detection): Facebook Access Tokens (Ignore with SHA: 38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314) (1 occurrence)
'''

snapshots['test_leak_message[_ONE_LINE_AND_MULTILINE_PATCH_CONTENT-clip_long_lines-hide_secrets] 1'] = '''> This is an example header
secrets-engine-version: 3.14.159

>>> 3 incidents have been found in file leak.txt

>>> Incident 1(Secrets Detection): Facebook Access Tokens (Ignore with SHA: 1945f4a0c42abb19c1a420ddd09b4b4681249a3057c427b95f794b18595e7ffa) (1 occurrence)

>>> Incident 2(Secrets detection): RSA Private Key (Ignore with SHA: 060bf63de122848f5efa122fe6cea504aae3b24cea393d887fdefa1529c6a02e) (1 occurrence)
    | @@ -0,0 +1,29 @
  1 | …**5733 /ce3f9f********************5e43711 -----BEGIN RSA PRIVATE KEY-----
  2 | +MIIBOgIBAAJBAIIRkYjxjE3KIZi******************************+******
  3 | +****************************************************************
  4 | +****************************************************************
  5 | +***********+****************************************************
  6 | +****************+***********************************************
  7 | +**********************+*****************************************
  8 | +****+******Xme/ovcDeM1+3W/UmSHYUW4b3WYq4
  9 | -----END RSA PRIVATE KEY----- token: SG._Yytrtvlj************************…
      |_________________________________apikey_________________________________|

>>> Incident 3(Secrets detection): SendGrid Key (Ignore with SHA: 530e5a4a7ea00814db8845dd0cae5efaa4b974a3ce1c76d0384ba715248a5dc1) (1 occurrence)
  7 | **********************+*****************************************
  8 | ****+******Xme/ovcDeM1+3W/UmSHYUW4b3WYq4
  9 | …-- token: SG._Yytrtvlj******************************************-**rRJLGFLBLf0M
                 |_______________________________apikey______________________________|
'''

snapshots['test_leak_message[_ONE_LINE_AND_MULTILINE_PATCH_CONTENT-clip_long_lines-show_secrets] 1'] = '''> This is an example header
secrets-engine-version: 3.14.159

>>> 3 incidents have been found in file leak.txt

>>> Incident 1(Secrets Detection): Facebook Access Tokens (Ignore with SHA: 1945f4a0c42abb19c1a420ddd09b4b4681249a3057c427b95f794b18595e7ffa) (1 occurrence)

>>> Incident 2(Secrets detection): RSA Private Key (Ignore with SHA: 060bf63de122848f5efa122fe6cea504aae3b24cea393d887fdefa1529c6a02e) (1 occurrence)
    | @@ -0,0 +1,29 @
  1 | …041573 / ce3f9f0362bbe5ab01dfc8ee565e4371 -----BEGIN RSA PRIVATE KEY-----
  2 | +MIIBOgIBAAJBAIIRkYjxjE3KIZiEc8k4sWWGNsPYRNE0u0bl5oFVApPLm+uXQ/4l
  3 | +bKO9LFtMiVPy700oMWLScwAN5OAiqVLMvHUCAwEAAQJANLr8nmEWuV6t2hAwhK5I
  4 | +NNmBkEo4M/xFxEtl9J7LKbE2gtNrlCQiJlPP1EMhwAjDOzQcJ3lgFB28dkqH5rMW
  5 | +TQIhANrCE7O+wlCKe0WJqQ3lYlHG91XWyGVgfExJwBDsAD9LAiEAmDY5OSsH0n2A
  6 | +22tthkAvcN1s66lG+0DztOVJ4QLI2z8CIBPeDGwGpx8pdIicN/5LFuLWbyAcoZaT
  7 | +bLaA/DCNPniBAiA0l//bzg+M3srIhm04xzLdR9Vb9IjPRlkvN074zdKDVwIhAKJb
  8 | +RF3C+CMFb0wXme/ovcDeM1+3W/UmSHYUW4b3WYq4
  9 | -----END RSA PRIVATE KEY----- token: SG._YytrtvljkWqCrkMa3r5hw.yijiPf2qxr…
      |_________________________________apikey_________________________________|

>>> Incident 3(Secrets detection): SendGrid Key (Ignore with SHA: 530e5a4a7ea00814db8845dd0cae5efaa4b974a3ce1c76d0384ba715248a5dc1) (1 occurrence)
  7 | bLaA/DCNPniBAiA0l//bzg+M3srIhm04xzLdR9Vb9IjPRlkvN074zdKDVwIhAKJb
  8 | RF3C+CMFb0wXme/ovcDeM1+3W/UmSHYUW4b3WYq4
  9 | …-- token: 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
                 |_______________________________apikey______________________________|
'''

snapshots['test_leak_message[_ONE_LINE_AND_MULTILINE_PATCH_CONTENT-verbose-hide_secrets] 1'] = '''> This is an example header
secrets-engine-version: 3.14.159

>>> 3 incidents have been found in file leak.txt

>>> Incident 1(Secrets Detection): Facebook Access Tokens (Ignore with SHA: 1945f4a0c42abb19c1a420ddd09b4b4681249a3057c427b95f794b18595e7ffa) (1 occurrence)

>>> Incident 2(Secrets detection): RSA Private Key (Ignore with SHA: 060bf63de122848f5efa122fe6cea504aae3b24cea393d887fdefa1529c6a02e) (1 occurrence)
    | @@ -0,0 +1,29 @
  1 | FacebookAppKeys:294*********5733 /ce3f9f********************5e43711 -----BEGIN RSA PRIVATE KEY-----
  2 | +MIIBOgIBAAJBAIIRkYjxjE3KIZi******************************+******
  3 | +****************************************************************
  4 | +****************************************************************
  5 | +***********+****************************************************
  6 | +****************+***********************************************
  7 | +**********************+*****************************************
  8 | +****+******Xme/ovcDeM1+3W/UmSHYUW4b3WYq4
  9 | -----END RSA PRIVATE KEY----- token: SG._Yytrtvlj******************************************-**rRJLGFLBLf0M
      

>>> Incident 3(Secrets detection): SendGrid Key (Ignore with SHA: 530e5a4a7ea00814db8845dd0cae5efaa4b974a3ce1c76d0384ba715248a5dc1) (1 occurrence)
  7 | **********************+*****************************************
  8 | ****+******Xme/ovcDeM1+3W/UmSHYUW4b3WYq4
  9 | -----END RSA PRIVATE KEY----- token: SG._Yytrtvlj******************************************-**rRJLGFLBLf0M
                                           |_______________________________apikey______________________________|
'''

snapshots['test_leak_message[_ONE_LINE_AND_MULTILINE_PATCH_CONTENT-verbose-show_secrets] 1'] = '''> This is an example header
secrets-engine-version: 3.14.159

>>> 3 incidents have been found in file leak.txt

>>> Incident 1(Secrets Detection): Facebook Access Tokens (Ignore with SHA: 1945f4a0c42abb19c1a420ddd09b4b4681249a3057c427b95f794b18595e7ffa) (1 occurrence)

>>> Incident 2(Secrets detection): RSA Private Key (Ignore with SHA: 060bf63de122848f5efa122fe6cea504aae3b24cea393d887fdefa1529c6a02e) (1 occurrence)
    | @@ -0,0 +1,29 @
  1 | FacebookAppKeys: 294790898041573 / ce3f9f0362bbe5ab01dfc8ee565e4371 -----BEGIN RSA PRIVATE KEY-----
  2 | +MIIBOgIBAAJBAIIRkYjxjE3KIZiEc8k4sWWGNsPYRNE0u0bl5oFVApPLm+uXQ/4l
  3 | +bKO9LFtMiVPy700oMWLScwAN5OAiqVLMvHUCAwEAAQJANLr8nmEWuV6t2hAwhK5I
  4 | +NNmBkEo4M/xFxEtl9J7LKbE2gtNrlCQiJlPP1EMhwAjDOzQcJ3lgFB28dkqH5rMW
  5 | +TQIhANrCE7O+wlCKe0WJqQ3lYlHG91XWyGVgfExJwBDsAD9LAiEAmDY5OSsH0n2A
  6 | +22tthkAvcN1s66lG+0DztOVJ4QLI2z8CIBPeDGwGpx8pdIicN/5LFuLWbyAcoZaT
  7 | +bLaA/DCNPniBAiA0l//bzg+M3srIhm04xzLdR9Vb9IjPRlkvN074zdKDVwIhAKJb
  8 | +RF3C+CMFb0wXme/ovcDeM1+3W/UmSHYUW4b3WYq4
  9 | -----END RSA PRIVATE KEY----- token: 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
      

>>> Incident 3(Secrets detection): SendGrid Key (Ignore with SHA: 530e5a4a7ea00814db8845dd0cae5efaa4b974a3ce1c76d0384ba715248a5dc1) (1 occurrence)
  7 | bLaA/DCNPniBAiA0l//bzg+M3srIhm04xzLdR9Vb9IjPRlkvN074zdKDVwIhAKJb
  8 | RF3C+CMFb0wXme/ovcDeM1+3W/UmSHYUW4b3WYq4
  9 | -----END RSA PRIVATE KEY----- token: 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
                                           |_______________________________apikey______________________________|
'''

snapshots['test_leak_message[_SIMPLE_SECRET_MULTILINE_PATCH_SCAN_RESULT-clip_long_lines-hide_secrets] 1'] = '''> This is an example header
secrets-engine-version: 3.14.159

>>> 1 incident has been found in file leak.txt

>>> Incident 1(Secrets Detection): RSA Private Key (Ignore with SHA: 060bf63de122848f5efa122fe6cea504aae3b24cea393d887fdefa1529c6a02e) (1 occurrence)
'''

snapshots['test_leak_message[_SIMPLE_SECRET_MULTILINE_PATCH_SCAN_RESULT-clip_long_lines-show_secrets] 1'] = '''> This is an example header
secrets-engine-version: 3.14.159

>>> 1 incident has been found in file leak.txt

>>> Incident 1(Secrets Detection): RSA Private Key (Ignore with SHA: 060bf63de122848f5efa122fe6cea504aae3b24cea393d887fdefa1529c6a02e) (1 occurrence)
'''

snapshots['test_leak_message[_SIMPLE_SECRET_MULTILINE_PATCH_SCAN_RESULT-verbose-hide_secrets] 1'] = '''> This is an example header
secrets-engine-version: 3.14.159

>>> 1 incident has been found in file leak.txt

>>> Incident 1(Secrets Detection): RSA Private Key (Ignore with SHA: 060bf63de122848f5efa122fe6cea504aae3b24cea393d887fdefa1529c6a02e) (1 occurrence)
'''

snapshots['test_leak_message[_SIMPLE_SECRET_MULTILINE_PATCH_SCAN_RESULT-verbose-show_secrets] 1'] = '''> This is an example header
secrets-engine-version: 3.14.159

>>> 1 incident has been found in file leak.txt

>>> Incident 1(Secrets Detection): RSA Private Key (Ignore with SHA: 060bf63de122848f5efa122fe6cea504aae3b24cea393d887fdefa1529c6a02e) (1 occurrence)
'''

snapshots['test_leak_message[_SIMPLE_SECRET_PATCH_SCAN_RESULT-clip_long_lines-hide_secrets] 1'] = '''> This is an example header
secrets-engine-version: 3.14.159

>>> 1 incident has been found in file leak.txt

>>> Incident 1(Secrets Detection): GitHub Token (Ignore with SHA: 2b5840babacb6f089ddcce1fe5a56b803f8b1f636c6f44cdbf14b0c77a194c93) (1 occurrence)
'''

snapshots['test_leak_message[_SIMPLE_SECRET_PATCH_SCAN_RESULT-clip_long_lines-show_secrets] 1'] = '''> This is an example header
secrets-engine-version: 3.14.159

>>> 1 incident has been found in file leak.txt

>>> Incident 1(Secrets Detection): GitHub Token (Ignore with SHA: 2b5840babacb6f089ddcce1fe5a56b803f8b1f636c6f44cdbf14b0c77a194c93) (1 occurrence)
'''

snapshots['test_leak_message[_SIMPLE_SECRET_PATCH_SCAN_RESULT-verbose-hide_secrets] 1'] = '''> This is an example header
secrets-engine-version: 3.14.159

>>> 1 incident has been found in file leak.txt

>>> Incident 1(Secrets Detection): GitHub Token (Ignore with SHA: 2b5840babacb6f089ddcce1fe5a56b803f8b1f636c6f44cdbf14b0c77a194c93) (1 occurrence)
'''

snapshots['test_leak_message[_SIMPLE_SECRET_PATCH_SCAN_RESULT-verbose-show_secrets] 1'] = '''> This is an example header
secrets-engine-version: 3.14.159

>>> 1 incident has been found in file leak.txt

>>> Incident 1(Secrets Detection): GitHub Token (Ignore with SHA: 2b5840babacb6f089ddcce1fe5a56b803f8b1f636c6f44cdbf14b0c77a194c93) (1 occurrence)
'''
