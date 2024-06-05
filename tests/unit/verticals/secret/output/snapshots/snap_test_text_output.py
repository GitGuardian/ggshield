# snapshottest: v1 - https://goo.gl/zC4yUc

from snapshottest import Snapshot


snapshots = Snapshot()

snapshots[
    "test_leak_message[_MULTI_SECRET_ONE_LINE_PATCH_OVERLAY_SCAN_RESULT-clip_long_lines-hide_secrets] 1"
] = """> This is an example header
> leak.txt: 1 incident detected

>> Secret detected: Facebook Access Tokens
   Occurrences: 1
   Known by GitGuardian dashboard: NO
   Incident URL: N/A
   Secret SHA: 38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314

    | @@ -0,0 +1 @
  1 | +Facebook = 294*********575 | ce3f9f********************5e4372;
                  |__client_id__|
  1 | +Facebook = 294*********575 | ce3f9f********************5e4372;
                                    |_________client_secret________|
"""

snapshots[
    "test_leak_message[_MULTI_SECRET_ONE_LINE_PATCH_OVERLAY_SCAN_RESULT-clip_long_lines-show_secrets] 1"
] = """> This is an example header
> leak.txt: 1 incident detected

>> Secret detected: Facebook Access Tokens
   Occurrences: 1
   Known by GitGuardian dashboard: NO
   Incident URL: N/A
   Secret SHA: 38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314

    | @@ -0,0 +1 @
  1 | +Facebook = 294790898041575 | ce3f9f0362bbe5ab01dfc8ee565e4372;
                  |__client_id__|
  1 | +Facebook = 294790898041575 | ce3f9f0362bbe5ab01dfc8ee565e4372;
                                    |_________client_secret________|
"""

snapshots[
    "test_leak_message[_MULTI_SECRET_ONE_LINE_PATCH_OVERLAY_SCAN_RESULT-verbose-hide_secrets] 1"
] = """
secrets-engine-version: 3.14.159
> This is an example header
> leak.txt: 1 incident detected

>> Secret detected: Facebook Access Tokens
   Occurrences: 1
   Known by GitGuardian dashboard: NO
   Incident URL: N/A
   Secret SHA: 38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314

    | @@ -0,0 +1 @
  1 | +Facebook = 294*********575 | ce3f9f********************5e4372;
                  |__client_id__|
  1 | +Facebook = 294*********575 | ce3f9f********************5e4372;
                                    |_________client_secret________|
"""

snapshots[
    "test_leak_message[_MULTI_SECRET_ONE_LINE_PATCH_OVERLAY_SCAN_RESULT-verbose-show_secrets] 1"
] = """
secrets-engine-version: 3.14.159
> This is an example header
> leak.txt: 1 incident detected

>> Secret detected: Facebook Access Tokens
   Occurrences: 1
   Known by GitGuardian dashboard: NO
   Incident URL: N/A
   Secret SHA: 38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314

    | @@ -0,0 +1 @
  1 | +Facebook = 294790898041575 | ce3f9f0362bbe5ab01dfc8ee565e4372;
                  |__client_id__|
  1 | +Facebook = 294790898041575 | ce3f9f0362bbe5ab01dfc8ee565e4372;
                                    |_________client_secret________|
"""

snapshots[
    "test_leak_message[_MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT-clip_long_lines-hide_secrets] 1"
] = """> This is an example header
> leak.txt: 1 incident detected

>> Secret detected: Facebook Access Tokens
   Occurrences: 1
   Known by GitGuardian dashboard: NO
   Incident URL: N/A
   Secret SHA: 38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314

    | @@ -0,0 +1 @
  1 | +FacebookAppId = 294*********575; FacebookAppSecret = ce3f9f*************…
                       |__client_id__|
  1 | +…= 294*********575; FacebookAppSecret = ce3f9f********************5e4372;
                                               |_________client_secret________|
"""

snapshots[
    "test_leak_message[_MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT-clip_long_lines-show_secrets] 1"
] = """> This is an example header
> leak.txt: 1 incident detected

>> Secret detected: Facebook Access Tokens
   Occurrences: 1
   Known by GitGuardian dashboard: NO
   Incident URL: N/A
   Secret SHA: 38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314

    | @@ -0,0 +1 @
  1 | +FacebookAppId = 294790898041575; FacebookAppSecret = ce3f9f0362bbe5ab01d…
                       |__client_id__|
  1 | +…= 294790898041575; FacebookAppSecret = ce3f9f0362bbe5ab01dfc8ee565e4372;
                                               |_________client_secret________|
"""

snapshots[
    "test_leak_message[_MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT-verbose-hide_secrets] 1"
] = """
secrets-engine-version: 3.14.159
> This is an example header
> leak.txt: 1 incident detected

>> Secret detected: Facebook Access Tokens
   Occurrences: 1
   Known by GitGuardian dashboard: NO
   Incident URL: N/A
   Secret SHA: 38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314

    | @@ -0,0 +1 @
  1 | +FacebookAppId = 294*********575; FacebookAppSecret = ce3f9f********************5e4372;
                       |__client_id__|
  1 | +FacebookAppId = 294*********575; FacebookAppSecret = ce3f9f********************5e4372;
                                                            |_________client_secret________|
"""

snapshots[
    "test_leak_message[_MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT-verbose-show_secrets] 1"
] = """
secrets-engine-version: 3.14.159
> This is an example header
> leak.txt: 1 incident detected

>> Secret detected: Facebook Access Tokens
   Occurrences: 1
   Known by GitGuardian dashboard: NO
   Incident URL: N/A
   Secret SHA: 38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314

    | @@ -0,0 +1 @
  1 | +FacebookAppId = 294790898041575; FacebookAppSecret = ce3f9f0362bbe5ab01dfc8ee565e4372;
                       |__client_id__|
  1 | +FacebookAppId = 294790898041575; FacebookAppSecret = ce3f9f0362bbe5ab01dfc8ee565e4372;
                                                            |_________client_secret________|
"""

snapshots[
    "test_leak_message[_MULTI_SECRET_TWO_LINES_PATCH_SCAN_RESULT-clip_long_lines-hide_secrets] 1"
] = """> This is an example header
> leak.txt: 1 incident detected

>> Secret detected: Facebook Access Tokens
   Occurrences: 1
   Known by GitGuardian dashboard: NO
   Incident URL: N/A
   Secret SHA: 38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314

    | @@ -0,0 +2 @
  1 | +FacebookAppId = 294*********575;
                       |__client_id__|
  2 | +FacebookAppSecret = ce3f9f********************5e4372;
                           |_________client_secret________|
"""

snapshots[
    "test_leak_message[_MULTI_SECRET_TWO_LINES_PATCH_SCAN_RESULT-clip_long_lines-show_secrets] 1"
] = """> This is an example header
> leak.txt: 1 incident detected

>> Secret detected: Facebook Access Tokens
   Occurrences: 1
   Known by GitGuardian dashboard: NO
   Incident URL: N/A
   Secret SHA: 38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314

    | @@ -0,0 +2 @
  1 | +FacebookAppId = 294790898041575;
                       |__client_id__|
  2 | +FacebookAppSecret = ce3f9f0362bbe5ab01dfc8ee565e4372;
                           |_________client_secret________|
"""

snapshots[
    "test_leak_message[_MULTI_SECRET_TWO_LINES_PATCH_SCAN_RESULT-verbose-hide_secrets] 1"
] = """
secrets-engine-version: 3.14.159
> This is an example header
> leak.txt: 1 incident detected

>> Secret detected: Facebook Access Tokens
   Occurrences: 1
   Known by GitGuardian dashboard: NO
   Incident URL: N/A
   Secret SHA: 38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314

    | @@ -0,0 +2 @
  1 | +FacebookAppId = 294*********575;
                       |__client_id__|
  2 | +FacebookAppSecret = ce3f9f********************5e4372;
                           |_________client_secret________|
"""

snapshots[
    "test_leak_message[_MULTI_SECRET_TWO_LINES_PATCH_SCAN_RESULT-verbose-show_secrets] 1"
] = """
secrets-engine-version: 3.14.159
> This is an example header
> leak.txt: 1 incident detected

>> Secret detected: Facebook Access Tokens
   Occurrences: 1
   Known by GitGuardian dashboard: NO
   Incident URL: N/A
   Secret SHA: 38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314

    | @@ -0,0 +2 @
  1 | +FacebookAppId = 294790898041575;
                       |__client_id__|
  2 | +FacebookAppSecret = ce3f9f0362bbe5ab01dfc8ee565e4372;
                           |_________client_secret________|
"""

snapshots[
    "test_leak_message[_ONE_LINE_AND_MULTILINE_PATCH_CONTENT-clip_long_lines-hide_secrets] 1"
] = """> This is an example header
> leak.txt: 3 incidents detected

>> Secret detected: Facebook Access Tokens
   Occurrences: 1
   Known by GitGuardian dashboard: NO
   Incident URL: N/A
   Secret SHA: 1945f4a0c42abb19c1a420ddd09b4b4681249a3057c427b95f794b18595e7ffa

    | @@ -0,0 +1,29 @
  1 | +FacebookAppKeys: 294*********573 / ce3f9f********************5e4371 ----…
                        |__client_id__|
  1 | +… 294*********573 / ce3f9f********************5e4371 -----BEGIN RSA PRI…
                           |_________client_secret________|
  2 | +MIIBOgIBAAJBAIIRkYjxjE3KIZiE*****************************+******
  3 | +****************************************************************

>> Secret detected: RSA Private Key
   Occurrences: 1
   Known by GitGuardian dashboard: NO
   Incident URL: N/A
   Secret SHA: 060bf63de122848f5efa122fe6cea504aae3b24cea393d887fdefa1529c6a02e

    | @@ -0,0 +1,29 @
  1 | +…**573 / ce3f9f********************5e4371 -----BEGIN RSA PRIVATE KEY-----
  2 | +MIIBOgIBAAJBAIIRkYjxjE3KIZiE*****************************+******
  3 | +****************************************************************
  4 | +****************************************************************
  5 | +***********+****************************************************
  6 | +****************+***********************************************
  7 | +**********************+*****************************************
  8 | +****+*****wXme/ovcDeM1+3W/UmSHYUW4b3WYq4
  9 | +-----END RSA PRIVATE KEY----- token: SG._Yytrtvlj***********************…
       |_________________________________apikey________________________________|

>> Secret detected: SendGrid Key
   Occurrences: 1
   Known by GitGuardian dashboard: NO
   Incident URL: N/A
   Secret SHA: 530e5a4a7ea00814db8845dd0cae5efaa4b974a3ce1c76d0384ba715248a5dc1

  7 | +**********************+*****************************************
  8 | +****+*****wXme/ovcDeM1+3W/UmSHYUW4b3WYq4
  9 | +…-- token: SG._Yytrtvlj******************************************-**rRJLGFLBLf0M
                  |_______________________________apikey______________________________|
"""

snapshots[
    "test_leak_message[_ONE_LINE_AND_MULTILINE_PATCH_CONTENT-clip_long_lines-show_secrets] 1"
] = """> This is an example header
> leak.txt: 3 incidents detected

>> Secret detected: Facebook Access Tokens
   Occurrences: 1
   Known by GitGuardian dashboard: NO
   Incident URL: N/A
   Secret SHA: 1945f4a0c42abb19c1a420ddd09b4b4681249a3057c427b95f794b18595e7ffa

    | @@ -0,0 +1,29 @
  1 | +FacebookAppKeys: 294790898041573 / ce3f9f0362bbe5ab01dfc8ee565e4371 ----…
                        |__client_id__|
  1 | +… 294790898041573 / ce3f9f0362bbe5ab01dfc8ee565e4371 -----BEGIN RSA PRI…
                           |_________client_secret________|
  2 | +MIIBOgIBAAJBAIIRkYjxjE3KIZiEc8k4sWWGNsPYRNE0u0bl5oFVApPLm+uXQ/4l
  3 | +bKO9LFtMiVPy700oMWLScwAN5OAiqVLMvHUCAwEAAQJANLr8nmEWuV6t2hAwhK5I

>> Secret detected: RSA Private Key
   Occurrences: 1
   Known by GitGuardian dashboard: NO
   Incident URL: N/A
   Secret SHA: 060bf63de122848f5efa122fe6cea504aae3b24cea393d887fdefa1529c6a02e

    | @@ -0,0 +1,29 @
  1 | +…41573 / ce3f9f0362bbe5ab01dfc8ee565e4371 -----BEGIN RSA PRIVATE KEY-----
  2 | +MIIBOgIBAAJBAIIRkYjxjE3KIZiEc8k4sWWGNsPYRNE0u0bl5oFVApPLm+uXQ/4l
  3 | +bKO9LFtMiVPy700oMWLScwAN5OAiqVLMvHUCAwEAAQJANLr8nmEWuV6t2hAwhK5I
  4 | +NNmBkEo4M/xFxEtl9J7LKbE2gtNrlCQiJlPP1EMhwAjDOzQcJ3lgFB28dkqH5rMW
  5 | +TQIhANrCE7O+wlCKe0WJqQ3lYlHG91XWyGVgfExJwBDsAD9LAiEAmDY5OSsH0n2A
  6 | +22tthkAvcN1s66lG+0DztOVJ4QLI2z8CIBPeDGwGpx8pdIicN/5LFuLWbyAcoZaT
  7 | +bLaA/DCNPniBAiA0l//bzg+M3srIhm04xzLdR9Vb9IjPRlkvN074zdKDVwIhAKJb
  8 | +RF3C+CMFb0wXme/ovcDeM1+3W/UmSHYUW4b3WYq4
  9 | +-----END RSA PRIVATE KEY----- token: SG._YytrtvljkWqCrkMa3r5hw.yijiPf2qx…
       |_________________________________apikey________________________________|

>> Secret detected: SendGrid Key
   Occurrences: 1
   Known by GitGuardian dashboard: NO
   Incident URL: N/A
   Secret SHA: 530e5a4a7ea00814db8845dd0cae5efaa4b974a3ce1c76d0384ba715248a5dc1

  7 | +bLaA/DCNPniBAiA0l//bzg+M3srIhm04xzLdR9Vb9IjPRlkvN074zdKDVwIhAKJb
  8 | +RF3C+CMFb0wXme/ovcDeM1+3W/UmSHYUW4b3WYq4
  9 | +…-- token: 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
                  |_______________________________apikey______________________________|
"""

snapshots[
    "test_leak_message[_ONE_LINE_AND_MULTILINE_PATCH_CONTENT-verbose-hide_secrets] 1"
] = """
secrets-engine-version: 3.14.159
> This is an example header
> leak.txt: 3 incidents detected

>> Secret detected: Facebook Access Tokens
   Occurrences: 1
   Known by GitGuardian dashboard: NO
   Incident URL: N/A
   Secret SHA: 1945f4a0c42abb19c1a420ddd09b4b4681249a3057c427b95f794b18595e7ffa

    | @@ -0,0 +1,29 @
  1 | +FacebookAppKeys: 294*********573 / ce3f9f********************5e4371 -----BEGIN RSA PRIVATE KEY-----
                        |__client_id__|
  1 | +FacebookAppKeys: 294*********573 / ce3f9f********************5e4371 -----BEGIN RSA PRIVATE KEY-----
                                          |_________client_secret________|
  2 | +MIIBOgIBAAJBAIIRkYjxjE3KIZiE*****************************+******
  3 | +****************************************************************

>> Secret detected: RSA Private Key
   Occurrences: 1
   Known by GitGuardian dashboard: NO
   Incident URL: N/A
   Secret SHA: 060bf63de122848f5efa122fe6cea504aae3b24cea393d887fdefa1529c6a02e

    | @@ -0,0 +1,29 @
  1 | +FacebookAppKeys: 294*********573 / ce3f9f********************5e4371 -----BEGIN RSA PRIVATE KEY-----
  2 | +MIIBOgIBAAJBAIIRkYjxjE3KIZiE*****************************+******
  3 | +****************************************************************
  4 | +****************************************************************
  5 | +***********+****************************************************
  6 | +****************+***********************************************
  7 | +**********************+*****************************************
  8 | +****+*****wXme/ovcDeM1+3W/UmSHYUW4b3WYq4
  9 | +-----END RSA PRIVATE KEY----- token: SG._Yytrtvlj******************************************-**rRJLGFLBLf0M
       

>> Secret detected: SendGrid Key
   Occurrences: 1
   Known by GitGuardian dashboard: NO
   Incident URL: N/A
   Secret SHA: 530e5a4a7ea00814db8845dd0cae5efaa4b974a3ce1c76d0384ba715248a5dc1

  7 | +**********************+*****************************************
  8 | +****+*****wXme/ovcDeM1+3W/UmSHYUW4b3WYq4
  9 | +-----END RSA PRIVATE KEY----- token: SG._Yytrtvlj******************************************-**rRJLGFLBLf0M
                                            |_______________________________apikey______________________________|
"""

snapshots[
    "test_leak_message[_ONE_LINE_AND_MULTILINE_PATCH_CONTENT-verbose-show_secrets] 1"
] = """
secrets-engine-version: 3.14.159
> This is an example header
> leak.txt: 3 incidents detected

>> Secret detected: Facebook Access Tokens
   Occurrences: 1
   Known by GitGuardian dashboard: NO
   Incident URL: N/A
   Secret SHA: 1945f4a0c42abb19c1a420ddd09b4b4681249a3057c427b95f794b18595e7ffa

    | @@ -0,0 +1,29 @
  1 | +FacebookAppKeys: 294790898041573 / ce3f9f0362bbe5ab01dfc8ee565e4371 -----BEGIN RSA PRIVATE KEY-----
                        |__client_id__|
  1 | +FacebookAppKeys: 294790898041573 / ce3f9f0362bbe5ab01dfc8ee565e4371 -----BEGIN RSA PRIVATE KEY-----
                                          |_________client_secret________|
  2 | +MIIBOgIBAAJBAIIRkYjxjE3KIZiEc8k4sWWGNsPYRNE0u0bl5oFVApPLm+uXQ/4l
  3 | +bKO9LFtMiVPy700oMWLScwAN5OAiqVLMvHUCAwEAAQJANLr8nmEWuV6t2hAwhK5I

>> Secret detected: RSA Private Key
   Occurrences: 1
   Known by GitGuardian dashboard: NO
   Incident URL: N/A
   Secret SHA: 060bf63de122848f5efa122fe6cea504aae3b24cea393d887fdefa1529c6a02e

    | @@ -0,0 +1,29 @
  1 | +FacebookAppKeys: 294790898041573 / ce3f9f0362bbe5ab01dfc8ee565e4371 -----BEGIN RSA PRIVATE KEY-----
  2 | +MIIBOgIBAAJBAIIRkYjxjE3KIZiEc8k4sWWGNsPYRNE0u0bl5oFVApPLm+uXQ/4l
  3 | +bKO9LFtMiVPy700oMWLScwAN5OAiqVLMvHUCAwEAAQJANLr8nmEWuV6t2hAwhK5I
  4 | +NNmBkEo4M/xFxEtl9J7LKbE2gtNrlCQiJlPP1EMhwAjDOzQcJ3lgFB28dkqH5rMW
  5 | +TQIhANrCE7O+wlCKe0WJqQ3lYlHG91XWyGVgfExJwBDsAD9LAiEAmDY5OSsH0n2A
  6 | +22tthkAvcN1s66lG+0DztOVJ4QLI2z8CIBPeDGwGpx8pdIicN/5LFuLWbyAcoZaT
  7 | +bLaA/DCNPniBAiA0l//bzg+M3srIhm04xzLdR9Vb9IjPRlkvN074zdKDVwIhAKJb
  8 | +RF3C+CMFb0wXme/ovcDeM1+3W/UmSHYUW4b3WYq4
  9 | +-----END RSA PRIVATE KEY----- token: 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
       

>> Secret detected: SendGrid Key
   Occurrences: 1
   Known by GitGuardian dashboard: NO
   Incident URL: N/A
   Secret SHA: 530e5a4a7ea00814db8845dd0cae5efaa4b974a3ce1c76d0384ba715248a5dc1

  7 | +bLaA/DCNPniBAiA0l//bzg+M3srIhm04xzLdR9Vb9IjPRlkvN074zdKDVwIhAKJb
  8 | +RF3C+CMFb0wXme/ovcDeM1+3W/UmSHYUW4b3WYq4
  9 | +-----END RSA PRIVATE KEY----- token: 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
                                            |_______________________________apikey______________________________|
"""

snapshots[
    "test_leak_message[_SIMPLE_SECRET_MULTILINE_PATCH_SCAN_RESULT-clip_long_lines-hide_secrets] 1"
] = """> This is an example header
> leak.txt: 1 incident detected

>> Secret detected: RSA Private Key
   Occurrences: 1
   Known by GitGuardian dashboard: NO
   Incident URL: N/A
   Secret SHA: 060bf63de122848f5efa122fe6cea504aae3b24cea393d887fdefa1529c6a02e

      | @@ -0,0 +1,29 @
    1 | +PrivateKeyRsa:
    2 | +- text: -----BEGIN RSA PRIVATE KEY-----
    3 | +MIIBOgIBAAJBAIIRkYjxjE3KIZiE*****************************+******
    4 | +****************************************************************
    5 | +****************************************************************
    6 | +***********+****************************************************
    7 | +****************+***********************************************
    8 | +**********************+*****************************************
    9 | +****+*****wXme/ovcDeM1+3W/UmSHYUW4b3WYq4
   10 | +-----END RSA PRIVATE KEY-----
         |____________________________apikey____________________________|
"""

snapshots[
    "test_leak_message[_SIMPLE_SECRET_MULTILINE_PATCH_SCAN_RESULT-clip_long_lines-show_secrets] 1"
] = """> This is an example header
> leak.txt: 1 incident detected

>> Secret detected: RSA Private Key
   Occurrences: 1
   Known by GitGuardian dashboard: NO
   Incident URL: N/A
   Secret SHA: 060bf63de122848f5efa122fe6cea504aae3b24cea393d887fdefa1529c6a02e

      | @@ -0,0 +1,29 @
    1 | +PrivateKeyRsa:
    2 | +- text: -----BEGIN RSA PRIVATE KEY-----
    3 | +MIIBOgIBAAJBAIIRkYjxjE3KIZiEc8k4sWWGNsPYRNE0u0bl5oFVApPLm+uXQ/4l
    4 | +bKO9LFtMiVPy700oMWLScwAN5OAiqVLMvHUCAwEAAQJANLr8nmEWuV6t2hAwhK5I
    5 | +NNmBkEo4M/xFxEtl9J7LKbE2gtNrlCQiJlPP1EMhwAjDOzQcJ3lgFB28dkqH5rMW
    6 | +TQIhANrCE7O+wlCKe0WJqQ3lYlHG91XWyGVgfExJwBDsAD9LAiEAmDY5OSsH0n2A
    7 | +22tthkAvcN1s66lG+0DztOVJ4QLI2z8CIBPeDGwGpx8pdIicN/5LFuLWbyAcoZaT
    8 | +bLaA/DCNPniBAiA0l//bzg+M3srIhm04xzLdR9Vb9IjPRlkvN074zdKDVwIhAKJb
    9 | +RF3C+CMFb0wXme/ovcDeM1+3W/UmSHYUW4b3WYq4
   10 | +-----END RSA PRIVATE KEY-----
         |____________________________apikey____________________________|
"""

snapshots[
    "test_leak_message[_SIMPLE_SECRET_MULTILINE_PATCH_SCAN_RESULT-verbose-hide_secrets] 1"
] = """
secrets-engine-version: 3.14.159
> This is an example header
> leak.txt: 1 incident detected

>> Secret detected: RSA Private Key
   Occurrences: 1
   Known by GitGuardian dashboard: NO
   Incident URL: N/A
   Secret SHA: 060bf63de122848f5efa122fe6cea504aae3b24cea393d887fdefa1529c6a02e

      | @@ -0,0 +1,29 @
    1 | +PrivateKeyRsa:
    2 | +- text: -----BEGIN RSA PRIVATE KEY-----
    3 | +MIIBOgIBAAJBAIIRkYjxjE3KIZiE*****************************+******
    4 | +****************************************************************
    5 | +****************************************************************
    6 | +***********+****************************************************
    7 | +****************+***********************************************
    8 | +**********************+*****************************************
    9 | +****+*****wXme/ovcDeM1+3W/UmSHYUW4b3WYq4
   10 | +-----END RSA PRIVATE KEY-----
         |____________________________apikey____________________________|
"""

snapshots[
    "test_leak_message[_SIMPLE_SECRET_MULTILINE_PATCH_SCAN_RESULT-verbose-show_secrets] 1"
] = """
secrets-engine-version: 3.14.159
> This is an example header
> leak.txt: 1 incident detected

>> Secret detected: RSA Private Key
   Occurrences: 1
   Known by GitGuardian dashboard: NO
   Incident URL: N/A
   Secret SHA: 060bf63de122848f5efa122fe6cea504aae3b24cea393d887fdefa1529c6a02e

      | @@ -0,0 +1,29 @
    1 | +PrivateKeyRsa:
    2 | +- text: -----BEGIN RSA PRIVATE KEY-----
    3 | +MIIBOgIBAAJBAIIRkYjxjE3KIZiEc8k4sWWGNsPYRNE0u0bl5oFVApPLm+uXQ/4l
    4 | +bKO9LFtMiVPy700oMWLScwAN5OAiqVLMvHUCAwEAAQJANLr8nmEWuV6t2hAwhK5I
    5 | +NNmBkEo4M/xFxEtl9J7LKbE2gtNrlCQiJlPP1EMhwAjDOzQcJ3lgFB28dkqH5rMW
    6 | +TQIhANrCE7O+wlCKe0WJqQ3lYlHG91XWyGVgfExJwBDsAD9LAiEAmDY5OSsH0n2A
    7 | +22tthkAvcN1s66lG+0DztOVJ4QLI2z8CIBPeDGwGpx8pdIicN/5LFuLWbyAcoZaT
    8 | +bLaA/DCNPniBAiA0l//bzg+M3srIhm04xzLdR9Vb9IjPRlkvN074zdKDVwIhAKJb
    9 | +RF3C+CMFb0wXme/ovcDeM1+3W/UmSHYUW4b3WYq4
   10 | +-----END RSA PRIVATE KEY-----
         |____________________________apikey____________________________|
"""

snapshots[
    "test_leak_message[_SIMPLE_SECRET_PATCH_SCAN_RESULT-clip_long_lines-hide_secrets] 1"
] = """> This is an example header
> leak.txt: 1 incident detected

>> Secret detected: GitHub Token
   Occurrences: 1
   Known by GitGuardian dashboard: NO
   Incident URL: N/A
   Secret SHA: 2b5840babacb6f089ddcce1fe5a56b803f8b1f636c6f44cdbf14b0c77a194c93

    | @@ -0,0 +1 @
  1 | +github_token: 368ac3e**************************37ddf91
                     |________________apikey________________|
"""

snapshots[
    "test_leak_message[_SIMPLE_SECRET_PATCH_SCAN_RESULT-clip_long_lines-show_secrets] 1"
] = """> This is an example header
> leak.txt: 1 incident detected

>> Secret detected: GitHub Token
   Occurrences: 1
   Known by GitGuardian dashboard: NO
   Incident URL: N/A
   Secret SHA: 2b5840babacb6f089ddcce1fe5a56b803f8b1f636c6f44cdbf14b0c77a194c93

    | @@ -0,0 +1 @
  1 | +github_token: 368ac3edf9e850d1c0ff9d6c526496f8237ddf91
                     |________________apikey________________|
"""

snapshots[
    "test_leak_message[_SIMPLE_SECRET_PATCH_SCAN_RESULT-verbose-hide_secrets] 1"
] = """
secrets-engine-version: 3.14.159
> This is an example header
> leak.txt: 1 incident detected

>> Secret detected: GitHub Token
   Occurrences: 1
   Known by GitGuardian dashboard: NO
   Incident URL: N/A
   Secret SHA: 2b5840babacb6f089ddcce1fe5a56b803f8b1f636c6f44cdbf14b0c77a194c93

    | @@ -0,0 +1 @
  1 | +github_token: 368ac3e**************************37ddf91
                     |________________apikey________________|
"""

snapshots[
    "test_leak_message[_SIMPLE_SECRET_PATCH_SCAN_RESULT-verbose-show_secrets] 1"
] = """
secrets-engine-version: 3.14.159
> This is an example header
> leak.txt: 1 incident detected

>> Secret detected: GitHub Token
   Occurrences: 1
   Known by GitGuardian dashboard: NO
   Incident URL: N/A
   Secret SHA: 2b5840babacb6f089ddcce1fe5a56b803f8b1f636c6f44cdbf14b0c77a194c93

    | @@ -0,0 +1 @
  1 | +github_token: 368ac3edf9e850d1c0ff9d6c526496f8237ddf91
                     |________________apikey________________|
"""
