# -*- coding: utf-8 -*-
# snapshottest: v1 - https://goo.gl/zC4yUc
from __future__ import unicode_literals

from snapshottest import Snapshot

snapshots = Snapshot()

snapshots[
    "TestMessage::test_message_no_secret 1"
] = "\x1b[37m\x1b[22m\x1b[22mNo secrets have been found\x1b[0m"

snapshots[
    "TestMessage::test_message_multiple_secrets_two_lines 1"
] = """
🛡️  ⚔️  🛡️  \x1b[94m\x1b[1m\x1b[22m2\x1b[0m secrets have been found in file \x1b[93m\x1b[1m\x1b[22mleak.txt\x1b[0m

\x1b[37m\x1b[22m\x1b[2m \x1b[0m \x1b[37m\x1b[22m\x1b[2m \x1b[0m | \x1b[37m\x1b[22m\x1b[22m@@ -0,0 +2 @\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m2\x1b[0m | \x1b[37m\x1b[22m\x1b[22mFacebookAppId = \x1b[0m\x1b[91m\x1b[22m\x1b[22m294790898041575;\x1b[0m\x1b[37m\x1b[22m\x1b[22m\x1b[0m
\x1b[97m\x1b[1m\x1b[22m                      |_Facebook Access Tokens_|

\x1b[0m\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m3\x1b[0m | \x1b[37m\x1b[22m\x1b[22mFacebookAppSecret = \x1b[0m\x1b[91m\x1b[22m\x1b[22mce3f9f0362bbe5ab01dfc8ee565e4372;\x1b[0m\x1b[37m\x1b[22m\x1b[22m\x1b[0m
\x1b[97m\x1b[1m\x1b[22m                          |____Facebook Access Tokens____|

\x1b[0m"""

snapshots[
    "TestMessage::test_message_simple_secret_multiple_line 1"
] = """
🛡️  ⚔️  🛡️  \x1b[94m\x1b[1m\x1b[22m1\x1b[0m secret has been found in file \x1b[93m\x1b[1m\x1b[22mleak.txt\x1b[0m

\x1b[37m\x1b[22m\x1b[2m  \x1b[0m \x1b[37m\x1b[22m\x1b[2m  \x1b[0m | \x1b[37m\x1b[22m\x1b[22m@@ -0,0 +1,29 @\x1b[0m
\x1b[37m\x1b[22m\x1b[2m  \x1b[0m \x1b[37m\x1b[22m\x1b[2m 1\x1b[0m | \x1b[37m\x1b[22m\x1b[22mPrivateKeyRsa:\x1b[0m
\x1b[37m\x1b[22m\x1b[2m  \x1b[0m \x1b[37m\x1b[22m\x1b[2m 2\x1b[0m | \x1b[37m\x1b[22m\x1b[22m- text: >\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m 3\x1b[0m | \x1b[37m\x1b[22m\x1b[22m    \x1b[0m\x1b[91m\x1b[22m\x1b[22m-----BEGIN RSA PRIVATE KEY-----\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m 4\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    MIIEpQIBAAKCAQEA0pj32LapDxsvsOdgVWzkZMdp/k7R+KJhuXLUxFTuRQFlBDcc\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m 5\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    mIPbkKzcJZO8pTXlRrqa4TiOLmdSM1AAW4cIX6xNYjO6V6Xx7wsXntg2YlYlN59e\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m 6\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    lbaj08VY59XRwTDNqBnINUVGdJKy2qxe/NUf0+vtp9Fbms4aKYyoP6G6zVUtVjLi\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m 7\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    vZzG8+3zEJlHJzTu5TTurqYLxPSIJCSxCFWuqcmiO7wFr/IdtzbygmI3D4dlCP51\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m 8\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    azZ4PnXYVXBb6TeB0FYEC7kAlSMFbKVRkuRAyrLQbxJWJNQOMFRO4XRyaCEbZKtO\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m 9\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    5ig6zt8An8ncfcNLgYAsvLOgpByq+kU/Ny98CwIDAQABAoIBAQDDQokqKdH965sA\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m10\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    TscG7Xul5S7lV3dfLE+nfky/7G8vE+fxTJf64ObG8T78qEoUdDAsr//CKonJhIq2\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m11\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    gMqUElM1QbBOCOARPA9hL8uqv5VM/8pqFB3CeiDTzPptmdZtZS6JWb5DhgOZOhsS\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m12\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    nRdFHOXxu6ISIw7oLYgcVgn5VZ65mTzN6yB7pKsYkbm0NcJcmLnfuGbpQEP3WmC9\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m13\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    X4wO7galKdHXuSxRdcJxCag2k0W7S4UAbp1tPmRAeDdOXqbGL7hu14rUZYtkiuRP\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m14\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    546GDvOv+meHpDJve1hZ20CH2kRVq4DC64prPNfRJ1exSd94vlhokWL6SzTXItwm\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m15\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    L8TUnHeBAoGBAPTi6WqbVcL9Uy2qJA8fJg7oN4yQ/goOh+mlW3Fsdig0VsQjxWWI\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m16\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    ftb/tDv6UyHw50Ms66gT+h4dWepFVFDPb38HAhoU/RvmNCHWd33Nmhd1qf2jOQiR\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m17\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    Q9q2qJ0gFgKFlrbJNTOkaFni2UdJ7ySS937C2rdOm5GTOaCODl6M4UjRAoGBANwn\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m18\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    sFdT/HeY2lx84+jMxrzVOeNUpelye9G+VYk5poIMBSXX4Qm0V4EhmBOA4dEGwfhR\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m19\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    yW/p1TG0uzvOu2igUVx2YcaxUZMLBSny++awUcnAbIoN175vqS0zhGKfKgsK1ak3\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m20\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    /8P32zMm1vSz3ZR/+tzgcayWmOE8O1Cfw+Zks24bAoGBAIekjKAVTIrGIOWhYXnS\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m21\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    yhTlwaclxOEzLUtY4W7RIh2g6BKascNMuN1EI8Q5IwUg2ChYYGvoLNmzblOadVqR\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m22\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    m/OjoSFrUMu8VlIL5oITeW/XKAKq/3Nka05hcMIfvLFG57V1e/eP8JEhWzLmnAUJ\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m23\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    NvfK3LU+YGNhRkFNjl4G8N6RAoGBAJMmA/uaqzjU9b6zyzGjDYLRkiucPHjYiGIc\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m24\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    sddSrTRnDFnK/SMbYxFwftEqZ8Tqm2N6ZwViaZkbj7nd5+16mmcOyTOg+UErMHxl\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m25\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    aHE8kK4k62cq8XTb9Vu8/1NbxyIyT7UXNOCrHdwGrc5JGmVTVT2k1tXgoraJJ6wv\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m26\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    3SR1UmjZAoGARV26w6VMQKV0Y4ntnSIoGYWO9/15gSe2H3De+IPs4LyOP714Isi+\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m27\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    2JcO4QPvgRfd5I5FY6FTi7T0Gz2/DXHggv9DXM9Q2yXMhV+3tkTuNFeDwBw7qRGy\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m28\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    mCwOcAwHJ6GtCNvBDlpot6SauHEKKpzQobtq7giIEU3aSYR2unNg4wA=\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m29\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    -----END RSA PRIVATE KEY-----\x1b[0m\x1b[37m\x1b[22m\x1b[22m\x1b[0m
\x1b[97m\x1b[1m\x1b[22m        |________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________RSA Private Key_______________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________|

\x1b[0m"""

snapshots[
    "TestMessage::test_message_multiple_secret_one_line_and_multiple_line 1"
] = """
🛡️  ⚔️  🛡️  \x1b[94m\x1b[1m\x1b[22m4\x1b[0m secrets have been found in file \x1b[93m\x1b[1m\x1b[22mleak.txt\x1b[0m

\x1b[37m\x1b[22m\x1b[2m  \x1b[0m \x1b[37m\x1b[22m\x1b[2m  \x1b[0m | \x1b[37m\x1b[22m\x1b[22m@@ -0,0 +1,29 @\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m 1\x1b[0m | \x1b[37m\x1b[22m\x1b[22mFacebookAppKeys:\x1b[0m\x1b[91m\x1b[22m\x1b[22m 294790898041573\x1b[0m\x1b[37m\x1b[22m\x1b[22m /\x1b[0m\x1b[91m\x1b[22m\x1b[22m ce3f9f0362bbe5ab01dfc8ee565e4371\x1b[0m\x1b[37m\x1b[22m\x1b[22m\x1b[0m\x1b[91m\x1b[22m\x1b[22m -----BEGIN RSA PRIVATE KEY-----\x1b[0m
\x1b[97m\x1b[1m\x1b[22m                        |_Facebook Access Tokens_|
                                          |____Facebook Access Tokens____|

\x1b[0m\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m 2\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    MIIEpQIBAAKCAQEA0pj32LapDxsvsOdgVWzkZMdp/k7R+KJhuXLUxFTuRQFlBDcc\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m 3\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    mIPbkKzcJZO8pTXlRrqa4TiOLmdSM1AAW4cIX6xNYjO6V6Xx7wsXntg2YlYlN59e\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m 4\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    lbaj08VY59XRwTDNqBnINUVGdJKy2qxe/NUf0+vtp9Fbms4aKYyoP6G6zVUtVjLi\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m 5\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    vZzG8+3zEJlHJzTu5TTurqYLxPSIJCSxCFWuqcmiO7wFr/IdtzbygmI3D4dlCP51\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m 6\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    azZ4PnXYVXBb6TeB0FYEC7kAlSMFbKVRkuRAyrLQbxJWJNQOMFRO4XRyaCEbZKtO\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m 7\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    5ig6zt8An8ncfcNLgYAsvLOgpByq+kU/Ny98CwIDAQABAoIBAQDDQokqKdH965sA\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m 8\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    TscG7Xul5S7lV3dfLE+nfky/7G8vE+fxTJf64ObG8T78qEoUdDAsr//CKonJhIq2\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m 9\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    gMqUElM1QbBOCOARPA9hL8uqv5VM/8pqFB3CeiDTzPptmdZtZS6JWb5DhgOZOhsS\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m10\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    nRdFHOXxu6ISIw7oLYgcVgn5VZ65mTzN6yB7pKsYkbm0NcJcmLnfuGbpQEP3WmC9\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m11\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    X4wO7galKdHXuSxRdcJxCag2k0W7S4UAbp1tPmRAeDdOXqbGL7hu14rUZYtkiuRP\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m12\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    546GDvOv+meHpDJve1hZ20CH2kRVq4DC64prPNfRJ1exSd94vlhokWL6SzTXItwm\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m13\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    L8TUnHeBAoGBAPTi6WqbVcL9Uy2qJA8fJg7oN4yQ/goOh+mlW3Fsdig0VsQjxWWI\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m14\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    ftb/tDv6UyHw50Ms66gT+h4dWepFVFDPb38HAhoU/RvmNCHWd33Nmhd1qf2jOQiR\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m15\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    Q9q2qJ0gFgKFlrbJNTOkaFni2UdJ7ySS937C2rdOm5GTOaCODl6M4UjRAoGBANwn\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m16\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    sFdT/HeY2lx84+jMxrzVOeNUpelye9G+VYk5poIMBSXX4Qm0V4EhmBOA4dEGwfhR\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m17\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    yW/p1TG0uzvOu2igUVx2YcaxUZMLBSny++awUcnAbIoN175vqS0zhGKfKgsK1ak3\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m18\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    /8P32zMm1vSz3ZR/+tzgcayWmOE8O1Cfw+Zks24bAoGBAIekjKAVTIrGIOWhYXnS\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m19\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    yhTlwaclxOEzLUtY4W7RIh2g6BKascNMuN1EI8Q5IwUg2ChYYGvoLNmzblOadVqR\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m20\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    m/OjoSFrUMu8VlIL5oITeW/XKAKq/3Nka05hcMIfvLFG57V1e/eP8JEhWzLmnAUJ\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m21\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    NvfK3LU+YGNhRkFNjl4G8N6RAoGBAJMmA/uaqzjU9b6zyzGjDYLRkiucPHjYiGIc\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m22\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    sddSrTRnDFnK/SMbYxFwftEqZ8Tqm2N6ZwViaZkbj7nd5+16mmcOyTOg+UErMHxl\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m23\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    aHE8kK4k62cq8XTb9Vu8/1NbxyIyT7UXNOCrHdwGrc5JGmVTVT2k1tXgoraJJ6wv\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m24\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    3SR1UmjZAoGARV26w6VMQKV0Y4ntnSIoGYWO9/15gSe2H3De+IPs4LyOP714Isi+\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m25\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    2JcO4QPvgRfd5I5FY6FTi7T0Gz2/DXHggv9DXM9Q2yXMhV+3tkTuNFeDwBw7qRGy\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m26\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    mCwOcAwHJ6GtCNvBDlpot6SauHEKKpzQobtq7giIEU3aSYR2unNg4wA=\x1b[0m
\x1b[33m\x1b[22m\x1b[22m  \x1b[0m \x1b[33m\x1b[22m\x1b[22m27\x1b[0m | \x1b[91m\x1b[22m\x1b[22m    -----END RSA PRIVATE KEY-----\x1b[0m\x1b[37m\x1b[22m\x1b[22m github_token:\x1b[0m\x1b[91m\x1b[22m\x1b[22m 368ac3edf9e850d1c0ff9d6c526496f8237ddf91\x1b[0m\x1b[37m\x1b[22m\x1b[22m\x1b[0m
\x1b[97m\x1b[1m\x1b[22m        |________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________RSA Private Key_______________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________|
                                                       |_____________GitHub Token_____________|

\x1b[0m"""

snapshots[
    "TestMessage::test_message_multiple_secrets_one_line 1"
] = """
🛡️  ⚔️  🛡️  \x1b[94m\x1b[1m\x1b[22m2\x1b[0m secrets have been found in file \x1b[93m\x1b[1m\x1b[22mleak.txt\x1b[0m

\x1b[37m\x1b[22m\x1b[2m \x1b[0m \x1b[37m\x1b[22m\x1b[2m \x1b[0m | \x1b[37m\x1b[22m\x1b[22m@@ -0,0 +1 @\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m1\x1b[0m | \x1b[37m\x1b[22m\x1b[22mFacebookAppId = \x1b[0m\x1b[91m\x1b[22m\x1b[22m294790898041575;\x1b[0m\x1b[37m\x1b[22m\x1b[22m FacebookAppSecret = \x1b[0m\x1b[91m\x1b[22m\x1b[22mce3f9f0362bbe5ab01dfc8ee565e4372;\x1b[0m\x1b[37m\x1b[22m\x1b[22m\x1b[0m
\x1b[97m\x1b[1m\x1b[22m                      |_Facebook Access Tokens_|           |____Facebook Access Tokens____|

\x1b[0m"""

snapshots[
    "TestMessage::test_message_multiple_secrets_one_line_overlay 1"
] = """
🛡️  ⚔️  🛡️  \x1b[94m\x1b[1m\x1b[22m2\x1b[0m secrets have been found in file \x1b[93m\x1b[1m\x1b[22mleak.txt\x1b[0m

\x1b[37m\x1b[22m\x1b[2m \x1b[0m \x1b[37m\x1b[22m\x1b[2m \x1b[0m | \x1b[37m\x1b[22m\x1b[22m@@ -0,0 +1 @\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m1\x1b[0m | \x1b[37m\x1b[22m\x1b[22mFacebook = \x1b[0m\x1b[91m\x1b[22m\x1b[22m294790898041575 \x1b[0m\x1b[37m\x1b[22m\x1b[22m| \x1b[0m\x1b[91m\x1b[22m\x1b[22mce3f9f0362bbe5ab01dfc8ee565e4372;\x1b[0m\x1b[37m\x1b[22m\x1b[22m\x1b[0m
\x1b[97m\x1b[1m\x1b[22m                 |_Facebook Access Tokens_|
                                   |____Facebook Access Tokens____|

\x1b[0m"""

snapshots[
    "TestMessage::test_message_simple_secret 1"
] = """
🛡️  ⚔️  🛡️  \x1b[94m\x1b[1m\x1b[22m1\x1b[0m secret has been found in file \x1b[93m\x1b[1m\x1b[22mleak.txt\x1b[0m

\x1b[37m\x1b[22m\x1b[2m \x1b[0m \x1b[37m\x1b[22m\x1b[2m \x1b[0m | \x1b[37m\x1b[22m\x1b[22m@@ -0,0 +1 @\x1b[0m
\x1b[33m\x1b[22m\x1b[22m \x1b[0m \x1b[33m\x1b[22m\x1b[22m1\x1b[0m | \x1b[37m\x1b[22m\x1b[22mgithub_token: \x1b[0m\x1b[91m\x1b[22m\x1b[22m368ac3edf9e850d1c0ff9d6c526496f8237ddf91\x1b[0m\x1b[37m\x1b[22m\x1b[22m\x1b[0m
\x1b[97m\x1b[1m\x1b[22m                    |_____________GitHub Token_____________|

\x1b[0m"""
