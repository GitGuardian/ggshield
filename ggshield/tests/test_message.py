from snapshottest import TestCase

from ggshield.message import leak_message, no_leak_message
from ggshield.pygitguardian import ScanResultSchema


class TestMessage(TestCase):
    def test_message_no_secret(self):
        self.assertMatchSnapshot(no_leak_message())

    def test_message_simple_secret(self):
        result = {
            "content": "@@ -0,0 +1 @@\n+github_token: 368ac3edf9e850d1c0ff9d6c526496f8237ddf91\n",  # noqa
            "filename": "leak.txt",
            "filemode": "new file",
            "error": False,
            "has_leak": True,
            "scan": ScanResultSchema().load(
                {
                    "policies": ["File extensions", "Filenames", "Secrets detection"],
                    "policy_breaks": [
                        {
                            "type": "GitHub Token",
                            "policy": "Secrets Detection",
                            "matches": [
                                {
                                    "match": "368ac3edf9e850d1c0ff9d6c526496f8237ddf91",
                                    "type": "apikey",
                                    "index_start": 29,
                                    "index_end": 69,
                                }
                            ],
                        }
                    ],
                    "policy_break_count": 1,
                }
            ),
        }

        self.assertMatchSnapshot(leak_message(result))

    def test_message_multiple_secrets_one_line(self):
        result = {
            "content": "@@ -0,0 +1 @@\n+FacebookAppId = 294790898041575; FacebookAppSecret = ce3f9f0362bbe5ab01dfc8ee565e4372;\n",  # noqa
            "filename": "leak.txt",
            "filemode": "new file",
            "scan": ScanResultSchema().load(
                {
                    "policies": ["File extensions", "Filenames", "Secrets detection"],
                    "policy_breaks": [
                        {
                            "type": "Facebook Access Tokens",
                            "policy": "Secrets Detection",
                            "matches": [
                                {
                                    "match": "294790898041575",
                                    "index_start": 31,
                                    "index_end": 46,
                                    "type": "client_id",
                                },
                                {
                                    "match": "ce3f9f0362bbe5ab01dfc8ee565e4372",
                                    "index_start": 68,
                                    "index_end": 100,
                                    "type": "client_secret",
                                },
                            ],
                        }
                    ],
                    "policy_break_count": 1,
                }
            ),
            "error": False,
            "has_leak": True,
        }

        self.assertMatchSnapshot(leak_message(result))

    def test_message_multiple_secrets_one_line_overlay(self):
        result = {
            "content": "@@ -0,0 +1 @@\n+Facebook = 294790898041575 | ce3f9f0362bbe5ab01dfc8ee565e4372;\n",  # noqa
            "filename": "leak.txt",
            "filemode": "new file",
            "scan": ScanResultSchema().load(
                {
                    "policies": ["File extensions", "Filenames", "Secrets detection"],
                    "policy_breaks": [
                        {
                            "type": "Facebook Access Tokens",
                            "policy": "Secrets Detection",
                            "matches": [
                                {
                                    "match": "294790898041575",
                                    "index_start": 26,
                                    "index_end": 41,
                                    "type": "client_id",
                                },
                                {
                                    "match": "ce3f9f0362bbe5ab01dfc8ee565e4372",
                                    "index_start": 44,
                                    "index_end": 76,
                                    "type": "client_secret",
                                },
                            ],
                        }
                    ],
                    "policy_break_count": 1,
                }
            ),
            "error": False,
            "has_leak": True,
        }

        self.assertMatchSnapshot(leak_message(result))

    def test_message_multiple_secrets_two_lines(self):
        result = {
            "content": "@@ -0,0 +2 @@\n+FacebookAppId = 294790898041575;\n+FacebookAppSecret = ce3f9f0362bbe5ab01dfc8ee565e4372;\n",  # noqa
            "filename": "leak.txt",
            "filemode": "new file",
            "scan": ScanResultSchema().load(
                {
                    "policies": ["File extensions", "Filenames", "Secrets detection"],
                    "policy_breaks": [
                        {
                            "type": "Facebook Access Tokens",
                            "policy": "Secrets Detection",
                            "matches": [
                                {
                                    "match": "294790898041575",
                                    "index_start": 31,
                                    "index_end": 46,
                                    "type": "client_id",
                                },
                                {
                                    "match": "ce3f9f0362bbe5ab01dfc8ee565e4372",
                                    "index_start": 69,
                                    "index_end": 101,
                                    "type": "client_secret",
                                },
                            ],
                        }
                    ],
                    "policy_break_count": 1,
                }
            ),
            "error": False,
            "has_leak": True,
        }

        self.assertMatchSnapshot(leak_message(result))

    def test_message_simple_secret_multiple_line(self):
        result = {
            "content": "@@ -0,0 +1,29 @@\n+PrivateKeyRsa:\n+- text: >\n+    -----BEGIN RSA PRIVATE KEY-----\n+    MIIEpQIBAAKCAQEA0pj32LapDxsvsOdgVWzkZMdp/k7R+KJhuXLUxFTuRQFlBDcc\n+    mIPbkKzcJZO8pTXlRrqa4TiOLmdSM1AAW4cIX6xNYjO6V6Xx7wsXntg2YlYlN59e\n+    lbaj08VY59XRwTDNqBnINUVGdJKy2qxe/NUf0+vtp9Fbms4aKYyoP6G6zVUtVjLi\n+    vZzG8+3zEJlHJzTu5TTurqYLxPSIJCSxCFWuqcmiO7wFr/IdtzbygmI3D4dlCP51\n+    azZ4PnXYVXBb6TeB0FYEC7kAlSMFbKVRkuRAyrLQbxJWJNQOMFRO4XRyaCEbZKtO\n+    5ig6zt8An8ncfcNLgYAsvLOgpByq+kU/Ny98CwIDAQABAoIBAQDDQokqKdH965sA\n+    TscG7Xul5S7lV3dfLE+nfky/7G8vE+fxTJf64ObG8T78qEoUdDAsr//CKonJhIq2\n+    gMqUElM1QbBOCOARPA9hL8uqv5VM/8pqFB3CeiDTzPptmdZtZS6JWb5DhgOZOhsS\n+    nRdFHOXxu6ISIw7oLYgcVgn5VZ65mTzN6yB7pKsYkbm0NcJcmLnfuGbpQEP3WmC9\n+    X4wO7galKdHXuSxRdcJxCag2k0W7S4UAbp1tPmRAeDdOXqbGL7hu14rUZYtkiuRP\n+    546GDvOv+meHpDJve1hZ20CH2kRVq4DC64prPNfRJ1exSd94vlhokWL6SzTXItwm\n+    L8TUnHeBAoGBAPTi6WqbVcL9Uy2qJA8fJg7oN4yQ/goOh+mlW3Fsdig0VsQjxWWI\n+    ftb/tDv6UyHw50Ms66gT+h4dWepFVFDPb38HAhoU/RvmNCHWd33Nmhd1qf2jOQiR\n+    Q9q2qJ0gFgKFlrbJNTOkaFni2UdJ7ySS937C2rdOm5GTOaCODl6M4UjRAoGBANwn\n+    sFdT/HeY2lx84+jMxrzVOeNUpelye9G+VYk5poIMBSXX4Qm0V4EhmBOA4dEGwfhR\n+    yW/p1TG0uzvOu2igUVx2YcaxUZMLBSny++awUcnAbIoN175vqS0zhGKfKgsK1ak3\n+    /8P32zMm1vSz3ZR/+tzgcayWmOE8O1Cfw+Zks24bAoGBAIekjKAVTIrGIOWhYXnS\n+    yhTlwaclxOEzLUtY4W7RIh2g6BKascNMuN1EI8Q5IwUg2ChYYGvoLNmzblOadVqR\n+    m/OjoSFrUMu8VlIL5oITeW/XKAKq/3Nka05hcMIfvLFG57V1e/eP8JEhWzLmnAUJ\n+    NvfK3LU+YGNhRkFNjl4G8N6RAoGBAJMmA/uaqzjU9b6zyzGjDYLRkiucPHjYiGIc\n+    sddSrTRnDFnK/SMbYxFwftEqZ8Tqm2N6ZwViaZkbj7nd5+16mmcOyTOg+UErMHxl\n+    aHE8kK4k62cq8XTb9Vu8/1NbxyIyT7UXNOCrHdwGrc5JGmVTVT2k1tXgoraJJ6wv\n+    3SR1UmjZAoGARV26w6VMQKV0Y4ntnSIoGYWO9/15gSe2H3De+IPs4LyOP714Isi+\n+    2JcO4QPvgRfd5I5FY6FTi7T0Gz2/DXHggv9DXM9Q2yXMhV+3tkTuNFeDwBw7qRGy\n+    mCwOcAwHJ6GtCNvBDlpot6SauHEKKpzQobtq7giIEU3aSYR2unNg4wA=\n+    -----END RSA PRIVATE KEY-----",  # noqa
            "filename": "leak.txt",
            "filemode": "new file",
            "scan": ScanResultSchema().load(
                {
                    "policies": ["File extensions", "Filenames", "Secrets detection"],
                    "policy_breaks": [
                        {
                            "type": "RSA Private Key",
                            "policy": "Secrets Detection",
                            "matches": [
                                {
                                    "match": "-----BEGIN RSA PRIVATE KEY-----\n+    MIIEpQIBAAKCAQEA0pj32LapDxsvsOdgVWzkZMdp/k7R+KJhuXLUxFTuRQFlBDcc\n+    mIPbkKzcJZO8pTXlRrqa4TiOLmdSM1AAW4cIX6xNYjO6V6Xx7wsXntg2YlYlN59e\n+    lbaj08VY59XRwTDNqBnINUVGdJKy2qxe/NUf0+vtp9Fbms4aKYyoP6G6zVUtVjLi\n+    vZzG8+3zEJlHJzTu5TTurqYLxPSIJCSxCFWuqcmiO7wFr/IdtzbygmI3D4dlCP51\n+    azZ4PnXYVXBb6TeB0FYEC7kAlSMFbKVRkuRAyrLQbxJWJNQOMFRO4XRyaCEbZKtO\n+    5ig6zt8An8ncfcNLgYAsvLOgpByq+kU/Ny98CwIDAQABAoIBAQDDQokqKdH965sA\n+    TscG7Xul5S7lV3dfLE+nfky/7G8vE+fxTJf64ObG8T78qEoUdDAsr//CKonJhIq2\n+    gMqUElM1QbBOCOARPA9hL8uqv5VM/8pqFB3CeiDTzPptmdZtZS6JWb5DhgOZOhsS\n+    nRdFHOXxu6ISIw7oLYgcVgn5VZ65mTzN6yB7pKsYkbm0NcJcmLnfuGbpQEP3WmC9\n+    X4wO7galKdHXuSxRdcJxCag2k0W7S4UAbp1tPmRAeDdOXqbGL7hu14rUZYtkiuRP\n+    546GDvOv+meHpDJve1hZ20CH2kRVq4DC64prPNfRJ1exSd94vlhokWL6SzTXItwm\n+    L8TUnHeBAoGBAPTi6WqbVcL9Uy2qJA8fJg7oN4yQ/goOh+mlW3Fsdig0VsQjxWWI\n+    ftb/tDv6UyHw50Ms66gT+h4dWepFVFDPb38HAhoU/RvmNCHWd33Nmhd1qf2jOQiR\n+    Q9q2qJ0gFgKFlrbJNTOkaFni2UdJ7ySS937C2rdOm5GTOaCODl6M4UjRAoGBANwn\n+    sFdT/HeY2lx84+jMxrzVOeNUpelye9G+VYk5poIMBSXX4Qm0V4EhmBOA4dEGwfhR\n+    yW/p1TG0uzvOu2igUVx2YcaxUZMLBSny++awUcnAbIoN175vqS0zhGKfKgsK1ak3\n+    /8P32zMm1vSz3ZR/+tzgcayWmOE8O1Cfw+Zks24bAoGBAIekjKAVTIrGIOWhYXnS\n+    yhTlwaclxOEzLUtY4W7RIh2g6BKascNMuN1EI8Q5IwUg2ChYYGvoLNmzblOadVqR\n+    m/OjoSFrUMu8VlIL5oITeW/XKAKq/3Nka05hcMIfvLFG57V1e/eP8JEhWzLmnAUJ\n+    NvfK3LU+YGNhRkFNjl4G8N6RAoGBAJMmA/uaqzjU9b6zyzGjDYLRkiucPHjYiGIc\n+    sddSrTRnDFnK/SMbYxFwftEqZ8Tqm2N6ZwViaZkbj7nd5+16mmcOyTOg+UErMHxl\n+    aHE8kK4k62cq8XTb9Vu8/1NbxyIyT7UXNOCrHdwGrc5JGmVTVT2k1tXgoraJJ6wv\n+    3SR1UmjZAoGARV26w6VMQKV0Y4ntnSIoGYWO9/15gSe2H3De+IPs4LyOP714Isi+\n+    2JcO4QPvgRfd5I5FY6FTi7T0Gz2/DXHggv9DXM9Q2yXMhV+3tkTuNFeDwBw7qRGy\n+    mCwOcAwHJ6GtCNvBDlpot6SauHEKKpzQobtq7giIEU3aSYR2unNg4wA=\n+    -----END RSA PRIVATE KEY-----",  # noqa
                                    "index_start": 49,
                                    "index_end": 1857,
                                    "type": "apikey",
                                }
                            ],
                        }
                    ],
                    "policy_break_count": 1,
                }
            ),
            "error": False,
            "has_leak": True,
        }

        self.assertMatchSnapshot(leak_message(result))

    def test_message_multiple_secret_one_line_and_multiple_line(self):
        result = {
            "content": "@@ -0,0 +1,29 @@\n+FacebookAppKeys: 294790898041573 / ce3f9f0362bbe5ab01dfc8ee565e4371 -----BEGIN RSA PRIVATE KEY-----\n+    MIIEpQIBAAKCAQEA0pj32LapDxsvsOdgVWzkZMdp/k7R+KJhuXLUxFTuRQFlBDcc\n+    mIPbkKzcJZO8pTXlRrqa4TiOLmdSM1AAW4cIX6xNYjO6V6Xx7wsXntg2YlYlN59e\n+    lbaj08VY59XRwTDNqBnINUVGdJKy2qxe/NUf0+vtp9Fbms4aKYyoP6G6zVUtVjLi\n+    vZzG8+3zEJlHJzTu5TTurqYLxPSIJCSxCFWuqcmiO7wFr/IdtzbygmI3D4dlCP51\n+    azZ4PnXYVXBb6TeB0FYEC7kAlSMFbKVRkuRAyrLQbxJWJNQOMFRO4XRyaCEbZKtO\n+    5ig6zt8An8ncfcNLgYAsvLOgpByq+kU/Ny98CwIDAQABAoIBAQDDQokqKdH965sA\n+    TscG7Xul5S7lV3dfLE+nfky/7G8vE+fxTJf64ObG8T78qEoUdDAsr//CKonJhIq2\n+    gMqUElM1QbBOCOARPA9hL8uqv5VM/8pqFB3CeiDTzPptmdZtZS6JWb5DhgOZOhsS\n+    nRdFHOXxu6ISIw7oLYgcVgn5VZ65mTzN6yB7pKsYkbm0NcJcmLnfuGbpQEP3WmC9\n+    X4wO7galKdHXuSxRdcJxCag2k0W7S4UAbp1tPmRAeDdOXqbGL7hu14rUZYtkiuRP\n+    546GDvOv+meHpDJve1hZ20CH2kRVq4DC64prPNfRJ1exSd94vlhokWL6SzTXItwm\n+    L8TUnHeBAoGBAPTi6WqbVcL9Uy2qJA8fJg7oN4yQ/goOh+mlW3Fsdig0VsQjxWWI\n+    ftb/tDv6UyHw50Ms66gT+h4dWepFVFDPb38HAhoU/RvmNCHWd33Nmhd1qf2jOQiR\n+    Q9q2qJ0gFgKFlrbJNTOkaFni2UdJ7ySS937C2rdOm5GTOaCODl6M4UjRAoGBANwn\n+    sFdT/HeY2lx84+jMxrzVOeNUpelye9G+VYk5poIMBSXX4Qm0V4EhmBOA4dEGwfhR\n+    yW/p1TG0uzvOu2igUVx2YcaxUZMLBSny++awUcnAbIoN175vqS0zhGKfKgsK1ak3\n+    /8P32zMm1vSz3ZR/+tzgcayWmOE8O1Cfw+Zks24bAoGBAIekjKAVTIrGIOWhYXnS\n+    yhTlwaclxOEzLUtY4W7RIh2g6BKascNMuN1EI8Q5IwUg2ChYYGvoLNmzblOadVqR\n+    m/OjoSFrUMu8VlIL5oITeW/XKAKq/3Nka05hcMIfvLFG57V1e/eP8JEhWzLmnAUJ\n+    NvfK3LU+YGNhRkFNjl4G8N6RAoGBAJMmA/uaqzjU9b6zyzGjDYLRkiucPHjYiGIc\n+    sddSrTRnDFnK/SMbYxFwftEqZ8Tqm2N6ZwViaZkbj7nd5+16mmcOyTOg+UErMHxl\n+    aHE8kK4k62cq8XTb9Vu8/1NbxyIyT7UXNOCrHdwGrc5JGmVTVT2k1tXgoraJJ6wv\n+    3SR1UmjZAoGARV26w6VMQKV0Y4ntnSIoGYWO9/15gSe2H3De+IPs4LyOP714Isi+\n+    2JcO4QPvgRfd5I5FY6FTi7T0Gz2/DXHggv9DXM9Q2yXMhV+3tkTuNFeDwBw7qRGy\n+    mCwOcAwHJ6GtCNvBDlpot6SauHEKKpzQobtq7giIEU3aSYR2unNg4wA=\n+    -----END RSA PRIVATE KEY----- github_token: 368ac3edf9e850d1c0ff9d6c526496f8237ddf91",  # noqa
            "filename": "leak.txt",
            "filemode": "new file",
            "scan": ScanResultSchema().load(
                {
                    "policies": ["File extensions", "Filenames", "Secrets detection"],
                    "policy_breaks": [
                        {
                            "type": "Facebook Access Tokens",
                            "policy": "Secrets Detection",
                            "matches": [
                                {
                                    "match": "294790898041573",
                                    "index_start": 34,
                                    "index_end": 49,
                                    "type": "client_id",
                                },
                                {
                                    "match": "ce3f9f0362bbe5ab01dfc8ee565e4371",
                                    "index_start": 52,
                                    "index_end": 84,
                                    "type": "client_secret",
                                },
                            ],
                        },
                        {
                            "type": "GitHub Token",
                            "policy": "Secrets Detection",
                            "matches": [
                                {
                                    "match": "368ac3edf9e850d1c0ff9d6c526496f8237ddf91",
                                    "index_start": 1908,
                                    "index_end": 1948,
                                    "type": "apikey",
                                }
                            ],
                        },
                        {
                            "type": "RSA Private Key",
                            "policy": "Secrets Detection",
                            "matches": [
                                {
                                    "match": "-----BEGIN RSA PRIVATE KEY-----\n+    MIIEpQIBAAKCAQEA0pj32LapDxsvsOdgVWzkZMdp/k7R+KJhuXLUxFTuRQFlBDcc\n+    mIPbkKzcJZO8pTXlRrqa4TiOLmdSM1AAW4cIX6xNYjO6V6Xx7wsXntg2YlYlN59e\n+    lbaj08VY59XRwTDNqBnINUVGdJKy2qxe/NUf0+vtp9Fbms4aKYyoP6G6zVUtVjLi\n+    vZzG8+3zEJlHJzTu5TTurqYLxPSIJCSxCFWuqcmiO7wFr/IdtzbygmI3D4dlCP51\n+    azZ4PnXYVXBb6TeB0FYEC7kAlSMFbKVRkuRAyrLQbxJWJNQOMFRO4XRyaCEbZKtO\n+    5ig6zt8An8ncfcNLgYAsvLOgpByq+kU/Ny98CwIDAQABAoIBAQDDQokqKdH965sA\n+    TscG7Xul5S7lV3dfLE+nfky/7G8vE+fxTJf64ObG8T78qEoUdDAsr//CKonJhIq2\n+    gMqUElM1QbBOCOARPA9hL8uqv5VM/8pqFB3CeiDTzPptmdZtZS6JWb5DhgOZOhsS\n+    nRdFHOXxu6ISIw7oLYgcVgn5VZ65mTzN6yB7pKsYkbm0NcJcmLnfuGbpQEP3WmC9\n+    X4wO7galKdHXuSxRdcJxCag2k0W7S4UAbp1tPmRAeDdOXqbGL7hu14rUZYtkiuRP\n+    546GDvOv+meHpDJve1hZ20CH2kRVq4DC64prPNfRJ1exSd94vlhokWL6SzTXItwm\n+    L8TUnHeBAoGBAPTi6WqbVcL9Uy2qJA8fJg7oN4yQ/goOh+mlW3Fsdig0VsQjxWWI\n+    ftb/tDv6UyHw50Ms66gT+h4dWepFVFDPb38HAhoU/RvmNCHWd33Nmhd1qf2jOQiR\n+    Q9q2qJ0gFgKFlrbJNTOkaFni2UdJ7ySS937C2rdOm5GTOaCODl6M4UjRAoGBANwn\n+    sFdT/HeY2lx84+jMxrzVOeNUpelye9G+VYk5poIMBSXX4Qm0V4EhmBOA4dEGwfhR\n+    yW/p1TG0uzvOu2igUVx2YcaxUZMLBSny++awUcnAbIoN175vqS0zhGKfKgsK1ak3\n+    /8P32zMm1vSz3ZR/+tzgcayWmOE8O1Cfw+Zks24bAoGBAIekjKAVTIrGIOWhYXnS\n+    yhTlwaclxOEzLUtY4W7RIh2g6BKascNMuN1EI8Q5IwUg2ChYYGvoLNmzblOadVqR\n+    m/OjoSFrUMu8VlIL5oITeW/XKAKq/3Nka05hcMIfvLFG57V1e/eP8JEhWzLmnAUJ\n+    NvfK3LU+YGNhRkFNjl4G8N6RAoGBAJMmA/uaqzjU9b6zyzGjDYLRkiucPHjYiGIc\n+    sddSrTRnDFnK/SMbYxFwftEqZ8Tqm2N6ZwViaZkbj7nd5+16mmcOyTOg+UErMHxl\n+    aHE8kK4k62cq8XTb9Vu8/1NbxyIyT7UXNOCrHdwGrc5JGmVTVT2k1tXgoraJJ6wv\n+    3SR1UmjZAoGARV26w6VMQKV0Y4ntnSIoGYWO9/15gSe2H3De+IPs4LyOP714Isi+\n+    2JcO4QPvgRfd5I5FY6FTi7T0Gz2/DXHggv9DXM9Q2yXMhV+3tkTuNFeDwBw7qRGy\n+    mCwOcAwHJ6GtCNvBDlpot6SauHEKKpzQobtq7giIEU3aSYR2unNg4wA=\n+    -----END RSA PRIVATE KEY-----",  # noqa
                                    "index_start": 85,
                                    "index_end": 1893,
                                    "type": "apikey",
                                }
                            ],
                        },
                    ],
                    "policy_break_count": 3,
                }
            ),
            "error": False,
            "has_leak": True,
        }

        self.assertMatchSnapshot(leak_message(result))
