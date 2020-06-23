# -*- coding: utf-8 -*-
# snapshottest: v1 - https://goo.gl/zC4yUc
from __future__ import unicode_literals

from snapshottest import Snapshot


snapshots = Snapshot()

snapshots[
    "test_message_no_secret 1"
] = """No secrets have been found
"""

snapshots[
    "test_leak_message[_ONE_LINE_AND_MULTILINE_PATCH_CONTENT] 1"
] = """
🛡️  ⚔️  🛡️  3 policy breaks have been found in file leak.txt


>>> Policy break 1(Secrets Detection): Facebook Access Tokens (Ignore with SHA: 1945f4a0c42abb19c1a420ddd09b4b4681249a3057c427b95f794b18595e7ffa) (1 occurence)


>>> Policy break 2(Secrets detection): RSA Private Key (Ignore with SHA: 060bf63de122848f5efa122fe6cea504aae3b24cea393d887fdefa1529c6a02e) (1 occurence)

    | @@ -0,0 +1,29 @
  1 | FacebookAppKeys:294*********5733 /ce3f9f********************5e43711 -----BEGIN RSA PRIVATE KEY-----
  2 | +MIIBOgIBAAJBAIIRkYjxjE3KIZi******************************+******
  3 | +****************************************************************
  4 | +****************************************************************
  5 | +***********+****************************************************
  6 | +****************+***********************************************
  7 | +**********************+*****************************************
  8 | +****+******Xme/ovcDeM1+3W/UmSHYUW4b3WYq4
  9 | +-----END RSA PRIVATE KEY----- token: SG._Yytrtvlj******************************************-**rRJLGFLBLf0M
      


>>> Policy break 3(Secrets detection): SendGrid Key (Ignore with SHA: 530e5a4a7ea00814db8845dd0cae5efaa4b974a3ce1c76d0384ba715248a5dc1) (1 occurence)

  8 | ****+******Xme/ovcDeM1+3W/UmSHYUW4b3WYq4
  9 | -----END RSA PRIVATE KEY----- token: SG._Yytrtvlj******************************************-**rRJLGFLBLf0M
                                           |_______________________________apikey______________________________|

"""

snapshots[
    "test_leak_message[_ONE_LINE_AND_MULTILINE_PATCH_CONTENT] 2"
] = """
🛡️  ⚔️  🛡️  3 policy breaks have been found in file leak.txt


>>> Policy break 1(Secrets Detection): Facebook Access Tokens (Ignore with SHA: c462cdf25e0c0f3ae5d8e33d5ae5fa554cece3bccc1e2a997cc108cf7b0ec523) (1 occurence)


>>> Policy break 2(Secrets detection): SendGrid Key (Ignore with SHA: eea2fa13bdf04725685594cb0115eab7519f3f0a9aa9f339c34ef4a1ae18d908) (1 occurence)

    | @@ -0,0 +1,29 @
  1 | FacebookAppKeys: 294790898041573 / ce3f9f0362bbe5ab01dfc8ee565e4371 -----BEGIN RSA PRIVATE KEY-----
                         |_______________________________apikey______________________________|

  2 | MIIBOgIBAAJBAIIRkYjxjE3KIZiEc8k4sWWGNsPYRNE0u0bl5oFVApPLm+uXQ/4l

>>> Policy break 3(Secrets detection): RSA Private Key (Ignore with SHA: bc9ae02c5ca67523e8381ac3908089afb0cf9b82c74e92997d5bedda0016bec4) (1 occurence)

    | @@ -0,0 +1,29 @
  1 | FacebookAppKeys: 294790898041573 / ce3f9f0362bbe5aeys: 294790898041573 / ce3f9f0362bbe5ab01dfc8ee565e4371 -----BEGIN RSA PRIVATE KEY-----
                                                        

  2 | MIIBOgIBAAJBAIIRkYjxjE3KIZiEc8k4sWWGNsPYRNE0u0bl5oFVApPLm+uXQ/4l
"""

snapshots[
    "test_leak_message[_SIMPLE_SECRET_PATCH_SCAN_RESULT] 1"
] = """
🛡️  ⚔️  🛡️  1 policy break has been found in file leak.txt


>>> Policy break 1(Secrets Detection): GitHub Token (Ignore with SHA: 2b5840babacb6f089ddcce1fe5a56b803f8b1f636c6f44cdbf14b0c77a194c93) (1 occurence)

"""

snapshots[
    "test_leak_message[_SIMPLE_SECRET_PATCH_SCAN_RESULT] 2"
] = """
🛡️  ⚔️  🛡️  1 policy break has been found in file leak.txt


>>> Policy break 1(Secrets Detection): GitHub Token (Ignore with SHA: bf42b9886893934407b9a54628674bd6d178868f659eb26aa6de779121b9154d) (1 occurence)

"""

snapshots[
    "test_leak_message[_MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT] 1"
] = """
🛡️  ⚔️  🛡️  1 policy break has been found in file leak.txt


>>> Policy break 1(Secrets Detection): Facebook Access Tokens (Ignore with SHA: 38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314) (1 occurence)

"""

snapshots[
    "test_leak_message[_MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT] 2"
] = """
🛡️  ⚔️  🛡️  1 policy break has been found in file leak.txt


>>> Policy break 1(Secrets Detection): Facebook Access Tokens (Ignore with SHA: dad5636a1ae5652c5301ea8368ab9538c7c9f630c084f75e1148232dbd12949b) (1 occurence)

"""

snapshots[
    "test_leak_message[_MULTI_SECRET_ONE_LINE_PATCH_OVERLAY_SCAN_RESULT] 1"
] = """
🛡️  ⚔️  🛡️  1 policy break has been found in file leak.txt


>>> Policy break 1(Secrets Detection): Facebook Access Tokens (Ignore with SHA: 38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314) (1 occurence)

"""

snapshots[
    "test_leak_message[_MULTI_SECRET_ONE_LINE_PATCH_OVERLAY_SCAN_RESULT] 2"
] = """
🛡️  ⚔️  🛡️  1 policy break has been found in file leak.txt


>>> Policy break 1(Secrets Detection): Facebook Access Tokens (Ignore with SHA: dad5636a1ae5652c5301ea8368ab9538c7c9f630c084f75e1148232dbd12949b) (1 occurence)

"""

snapshots[
    "test_leak_message[_MULTI_SECRET_TWO_LINES_PATCH_SCAN_RESULT] 1"
] = """
🛡️  ⚔️  🛡️  1 policy break has been found in file leak.txt


>>> Policy break 1(Secrets Detection): Facebook Access Tokens (Ignore with SHA: 38d9d3464520ed68f18d16e640a4a8b37ef5b17608b455267d100aa487ead314) (1 occurence)

"""

snapshots[
    "test_leak_message[_MULTI_SECRET_TWO_LINES_PATCH_SCAN_RESULT] 2"
] = """
🛡️  ⚔️  🛡️  1 policy break has been found in file leak.txt


>>> Policy break 1(Secrets Detection): Facebook Access Tokens (Ignore with SHA: dad5636a1ae5652c5301ea8368ab9538c7c9f630c084f75e1148232dbd12949b) (1 occurence)

"""

snapshots[
    "test_leak_message[_SIMPLE_SECRET_MULTILINE_PATCH_SCAN_RESULT] 1"
] = """
🛡️  ⚔️  🛡️  1 policy break has been found in file leak.txt


>>> Policy break 1(Secrets Detection): RSA Private Key (Ignore with SHA: 060bf63de122848f5efa122fe6cea504aae3b24cea393d887fdefa1529c6a02e) (1 occurence)

"""

snapshots[
    "test_leak_message[_SIMPLE_SECRET_MULTILINE_PATCH_SCAN_RESULT] 2"
] = """
🛡️  ⚔️  🛡️  1 policy break has been found in file leak.txt


>>> Policy break 1(Secrets Detection): RSA Private Key (Ignore with SHA: bc9ae02c5ca67523e8381ac3908089afb0cf9b82c74e92997d5bedda0016bec4) (1 occurence)

"""
