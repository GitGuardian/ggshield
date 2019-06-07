from snapshottest import TestCase
from secrets_shield.message import leak_message, no_leak_message


class TestMessage(TestCase):
    def test_message_no_secret(self):
        self.assertMatchSnapshot(no_leak_message())

    def test_message_simple_secret(self):
        result = {
            "content": "@@ -0,0 +1 @@\n+github_token: 368ac3edf9e850d1c0ff9d6c526496f8237ddf91\n",
            "filename": "leak.txt",
            "filemode": "new file",
            "error": False,
            "has_leak": True,
            "scan": {
                "secrets": [
                    {
                        "detector": {
                            "name": "github_token",
                            "display_name": "GitHub Token",
                            "category": "Api",
                            "high_recall": False,
                            "metadata": {
                                "company_name": "GithubToken",
                                "company_name_l": "githubtoken",
                                "company_name_normalized": "GitHub",
                            },
                        },
                        "matches": [
                            {
                                "string_matched": "368ac3edf9e850d1c0ff9d6c526496f8237ddf91",
                                "indice_start": 29,
                                "indice_end": 69,
                                "name": "apikey",
                            }
                        ],
                        "status": "not_checked",
                    }
                ],
                "metadata": {"leak_count": 1},
            },
        }

        self.assertMatchSnapshot(leak_message(result))

    def test_message_multiple_secrets_one_line(self):
        result = {
            "content": "@@ -0,0 +1 @@\n+FacebookAppId = 294790898041575; FacebookAppSecret = ce3f9f0362bbe5ab01dfc8ee565e4372;\n",
            "filename": "leak.txt",
            "filemode": "new file",
            "scan": {
                "secrets": [
                    {
                        "detector": {
                            "name": "facebook_app_keys",
                            "display_name": "Facebook Access Tokens",
                            "category": "Api",
                            "high_recall": False,
                            "metadata": {
                                "company_name": "Facebook",
                                "company_name_l": "facebook",
                                "company_name_normalized": "Facebook",
                            },
                        },
                        "matches": [
                            {
                                "string_matched": "294790898041575",
                                "indice_start": 31,
                                "indice_end": 46,
                                "name": "client_id",
                            },
                            {
                                "string_matched": "ce3f9f0362bbe5ab01dfc8ee565e4372",
                                "indice_start": 68,
                                "indice_end": 100,
                                "name": "client_secret",
                            },
                        ],
                        "status": "not_checked",
                    }
                ],
                "metadata": {"leak_count": 1},
            },
            "error": False,
            "has_leak": True,
        }

        self.assertMatchSnapshot(leak_message(result))

    def test_message_multiple_secrets_one_line_overlay(self):
        result = {
            "content": "@@ -0,0 +1 @@\n+Facebook = 294790898041575 | ce3f9f0362bbe5ab01dfc8ee565e4372;\n",
            "filename": "leak.txt",
            "filemode": "new file",
            "scan": {
                "secrets": [
                    {
                        "detector": {
                            "name": "facebook_app_keys",
                            "display_name": "Facebook Access Tokens",
                            "category": "Api",
                            "high_recall": False,
                            "metadata": {
                                "company_name": "Facebook",
                                "company_name_l": "facebook",
                                "company_name_normalized": "Facebook",
                            },
                        },
                        "matches": [
                            {
                                "string_matched": "294790898041575",
                                "indice_start": 26,
                                "indice_end": 41,
                                "name": "client_id",
                            },
                            {
                                "string_matched": "ce3f9f0362bbe5ab01dfc8ee565e4372",
                                "indice_start": 44,
                                "indice_end": 76,
                                "name": "client_secret",
                            },
                        ],
                        "status": "not_checked",
                    }
                ],
                "metadata": {"leak_count": 1},
            },
            "error": False,
            "has_leak": True,
        }

        self.assertMatchSnapshot(leak_message(result))

    def test_message_multiple_secrets_two_lines(self):
        result = {
            "content": "@@ -0,0 +2 @@\n+FacebookAppId = 294790898041575;\n+FacebookAppSecret = ce3f9f0362bbe5ab01dfc8ee565e4372;\n",
            "filename": "leak.txt",
            "filemode": "new file",
            "scan": {
                "secrets": [
                    {
                        "detector": {
                            "name": "facebook_app_keys",
                            "display_name": "Facebook Access Tokens",
                            "category": "Api",
                            "high_recall": False,
                            "metadata": {
                                "company_name": "Facebook",
                                "company_name_l": "facebook",
                                "company_name_normalized": "Facebook",
                            },
                        },
                        "matches": [
                            {
                                "string_matched": "294790898041575",
                                "indice_start": 31,
                                "indice_end": 46,
                                "name": "client_id",
                            },
                            {
                                "string_matched": "ce3f9f0362bbe5ab01dfc8ee565e4372",
                                "indice_start": 69,
                                "indice_end": 101,
                                "name": "client_secret",
                            },
                        ],
                        "status": "not_checked",
                    }
                ],
                "metadata": {"leak_count": 1},
            },
            "error": False,
            "has_leak": True,
        }

        self.assertMatchSnapshot(leak_message(result))

    def test_message_simple_secret_multiple_line(self):
        result = {
            "content": "@@ -0,0 +1,29 @@\n+PrivateKeyRsa:\n+- text: >\n+    -----BEGIN RSA PRIVATE KEY-----\n+    MIIEpQIBAAKCAQEA0pj32LapDxsvsOdgVWzkZMdp/k7R+KJhuXLUxFTuRQFlBDcc\n+    mIPbkKzcJZO8pTXlRrqa4TiOLmdSM1AAW4cIX6xNYjO6V6Xx7wsXntg2YlYlN59e\n+    lbaj08VY59XRwTDNqBnINUVGdJKy2qxe/NUf0+vtp9Fbms4aKYyoP6G6zVUtVjLi\n+    vZzG8+3zEJlHJzTu5TTurqYLxPSIJCSxCFWuqcmiO7wFr/IdtzbygmI3D4dlCP51\n+    azZ4PnXYVXBb6TeB0FYEC7kAlSMFbKVRkuRAyrLQbxJWJNQOMFRO4XRyaCEbZKtO\n+    5ig6zt8An8ncfcNLgYAsvLOgpByq+kU/Ny98CwIDAQABAoIBAQDDQokqKdH965sA\n+    TscG7Xul5S7lV3dfLE+nfky/7G8vE+fxTJf64ObG8T78qEoUdDAsr//CKonJhIq2\n+    gMqUElM1QbBOCOARPA9hL8uqv5VM/8pqFB3CeiDTzPptmdZtZS6JWb5DhgOZOhsS\n+    nRdFHOXxu6ISIw7oLYgcVgn5VZ65mTzN6yB7pKsYkbm0NcJcmLnfuGbpQEP3WmC9\n+    X4wO7galKdHXuSxRdcJxCag2k0W7S4UAbp1tPmRAeDdOXqbGL7hu14rUZYtkiuRP\n+    546GDvOv+meHpDJve1hZ20CH2kRVq4DC64prPNfRJ1exSd94vlhokWL6SzTXItwm\n+    L8TUnHeBAoGBAPTi6WqbVcL9Uy2qJA8fJg7oN4yQ/goOh+mlW3Fsdig0VsQjxWWI\n+    ftb/tDv6UyHw50Ms66gT+h4dWepFVFDPb38HAhoU/RvmNCHWd33Nmhd1qf2jOQiR\n+    Q9q2qJ0gFgKFlrbJNTOkaFni2UdJ7ySS937C2rdOm5GTOaCODl6M4UjRAoGBANwn\n+    sFdT/HeY2lx84+jMxrzVOeNUpelye9G+VYk5poIMBSXX4Qm0V4EhmBOA4dEGwfhR\n+    yW/p1TG0uzvOu2igUVx2YcaxUZMLBSny++awUcnAbIoN175vqS0zhGKfKgsK1ak3\n+    /8P32zMm1vSz3ZR/+tzgcayWmOE8O1Cfw+Zks24bAoGBAIekjKAVTIrGIOWhYXnS\n+    yhTlwaclxOEzLUtY4W7RIh2g6BKascNMuN1EI8Q5IwUg2ChYYGvoLNmzblOadVqR\n+    m/OjoSFrUMu8VlIL5oITeW/XKAKq/3Nka05hcMIfvLFG57V1e/eP8JEhWzLmnAUJ\n+    NvfK3LU+YGNhRkFNjl4G8N6RAoGBAJMmA/uaqzjU9b6zyzGjDYLRkiucPHjYiGIc\n+    sddSrTRnDFnK/SMbYxFwftEqZ8Tqm2N6ZwViaZkbj7nd5+16mmcOyTOg+UErMHxl\n+    aHE8kK4k62cq8XTb9Vu8/1NbxyIyT7UXNOCrHdwGrc5JGmVTVT2k1tXgoraJJ6wv\n+    3SR1UmjZAoGARV26w6VMQKV0Y4ntnSIoGYWO9/15gSe2H3De+IPs4LyOP714Isi+\n+    2JcO4QPvgRfd5I5FY6FTi7T0Gz2/DXHggv9DXM9Q2yXMhV+3tkTuNFeDwBw7qRGy\n+    mCwOcAwHJ6GtCNvBDlpot6SauHEKKpzQobtq7giIEU3aSYR2unNg4wA=\n+    -----END RSA PRIVATE KEY-----",
            "filename": "leak.txt",
            "filemode": "new file",
            "scan": {
                "secrets": [
                    {
                        "detector": {
                            "name": "private_key_rsa",
                            "display_name": "RSA Private Key",
                            "category": "PrivateKey",
                            "high_recall": True,
                            "metadata": {},
                        },
                        "matches": [
                            {
                                "string_matched": "-----BEGIN RSA PRIVATE KEY-----\n+    MIIEpQIBAAKCAQEA0pj32LapDxsvsOdgVWzkZMdp/k7R+KJhuXLUxFTuRQFlBDcc\n+    mIPbkKzcJZO8pTXlRrqa4TiOLmdSM1AAW4cIX6xNYjO6V6Xx7wsXntg2YlYlN59e\n+    lbaj08VY59XRwTDNqBnINUVGdJKy2qxe/NUf0+vtp9Fbms4aKYyoP6G6zVUtVjLi\n+    vZzG8+3zEJlHJzTu5TTurqYLxPSIJCSxCFWuqcmiO7wFr/IdtzbygmI3D4dlCP51\n+    azZ4PnXYVXBb6TeB0FYEC7kAlSMFbKVRkuRAyrLQbxJWJNQOMFRO4XRyaCEbZKtO\n+    5ig6zt8An8ncfcNLgYAsvLOgpByq+kU/Ny98CwIDAQABAoIBAQDDQokqKdH965sA\n+    TscG7Xul5S7lV3dfLE+nfky/7G8vE+fxTJf64ObG8T78qEoUdDAsr//CKonJhIq2\n+    gMqUElM1QbBOCOARPA9hL8uqv5VM/8pqFB3CeiDTzPptmdZtZS6JWb5DhgOZOhsS\n+    nRdFHOXxu6ISIw7oLYgcVgn5VZ65mTzN6yB7pKsYkbm0NcJcmLnfuGbpQEP3WmC9\n+    X4wO7galKdHXuSxRdcJxCag2k0W7S4UAbp1tPmRAeDdOXqbGL7hu14rUZYtkiuRP\n+    546GDvOv+meHpDJve1hZ20CH2kRVq4DC64prPNfRJ1exSd94vlhokWL6SzTXItwm\n+    L8TUnHeBAoGBAPTi6WqbVcL9Uy2qJA8fJg7oN4yQ/goOh+mlW3Fsdig0VsQjxWWI\n+    ftb/tDv6UyHw50Ms66gT+h4dWepFVFDPb38HAhoU/RvmNCHWd33Nmhd1qf2jOQiR\n+    Q9q2qJ0gFgKFlrbJNTOkaFni2UdJ7ySS937C2rdOm5GTOaCODl6M4UjRAoGBANwn\n+    sFdT/HeY2lx84+jMxrzVOeNUpelye9G+VYk5poIMBSXX4Qm0V4EhmBOA4dEGwfhR\n+    yW/p1TG0uzvOu2igUVx2YcaxUZMLBSny++awUcnAbIoN175vqS0zhGKfKgsK1ak3\n+    /8P32zMm1vSz3ZR/+tzgcayWmOE8O1Cfw+Zks24bAoGBAIekjKAVTIrGIOWhYXnS\n+    yhTlwaclxOEzLUtY4W7RIh2g6BKascNMuN1EI8Q5IwUg2ChYYGvoLNmzblOadVqR\n+    m/OjoSFrUMu8VlIL5oITeW/XKAKq/3Nka05hcMIfvLFG57V1e/eP8JEhWzLmnAUJ\n+    NvfK3LU+YGNhRkFNjl4G8N6RAoGBAJMmA/uaqzjU9b6zyzGjDYLRkiucPHjYiGIc\n+    sddSrTRnDFnK/SMbYxFwftEqZ8Tqm2N6ZwViaZkbj7nd5+16mmcOyTOg+UErMHxl\n+    aHE8kK4k62cq8XTb9Vu8/1NbxyIyT7UXNOCrHdwGrc5JGmVTVT2k1tXgoraJJ6wv\n+    3SR1UmjZAoGARV26w6VMQKV0Y4ntnSIoGYWO9/15gSe2H3De+IPs4LyOP714Isi+\n+    2JcO4QPvgRfd5I5FY6FTi7T0Gz2/DXHggv9DXM9Q2yXMhV+3tkTuNFeDwBw7qRGy\n+    mCwOcAwHJ6GtCNvBDlpot6SauHEKKpzQobtq7giIEU3aSYR2unNg4wA=\n+    -----END RSA PRIVATE KEY-----",
                                "indice_start": 49,
                                "indice_end": 1857,
                                "name": "apikey",
                            }
                        ],
                        "status": "can_not_check",
                    }
                ],
                "metadata": {"version": "1.0.21", "leak_count": 1},
            },
            "error": False,
            "has_leak": True,
        }

        self.assertMatchSnapshot(leak_message(result))

    def test_message_multiple_secret_one_line_and_multiple_line(self):
        result = {
            "content": "@@ -0,0 +1,29 @@\n+FacebookAppKeys: 294790898041573 / ce3f9f0362bbe5ab01dfc8ee565e4371 -----BEGIN RSA PRIVATE KEY-----\n+    MIIEpQIBAAKCAQEA0pj32LapDxsvsOdgVWzkZMdp/k7R+KJhuXLUxFTuRQFlBDcc\n+    mIPbkKzcJZO8pTXlRrqa4TiOLmdSM1AAW4cIX6xNYjO6V6Xx7wsXntg2YlYlN59e\n+    lbaj08VY59XRwTDNqBnINUVGdJKy2qxe/NUf0+vtp9Fbms4aKYyoP6G6zVUtVjLi\n+    vZzG8+3zEJlHJzTu5TTurqYLxPSIJCSxCFWuqcmiO7wFr/IdtzbygmI3D4dlCP51\n+    azZ4PnXYVXBb6TeB0FYEC7kAlSMFbKVRkuRAyrLQbxJWJNQOMFRO4XRyaCEbZKtO\n+    5ig6zt8An8ncfcNLgYAsvLOgpByq+kU/Ny98CwIDAQABAoIBAQDDQokqKdH965sA\n+    TscG7Xul5S7lV3dfLE+nfky/7G8vE+fxTJf64ObG8T78qEoUdDAsr//CKonJhIq2\n+    gMqUElM1QbBOCOARPA9hL8uqv5VM/8pqFB3CeiDTzPptmdZtZS6JWb5DhgOZOhsS\n+    nRdFHOXxu6ISIw7oLYgcVgn5VZ65mTzN6yB7pKsYkbm0NcJcmLnfuGbpQEP3WmC9\n+    X4wO7galKdHXuSxRdcJxCag2k0W7S4UAbp1tPmRAeDdOXqbGL7hu14rUZYtkiuRP\n+    546GDvOv+meHpDJve1hZ20CH2kRVq4DC64prPNfRJ1exSd94vlhokWL6SzTXItwm\n+    L8TUnHeBAoGBAPTi6WqbVcL9Uy2qJA8fJg7oN4yQ/goOh+mlW3Fsdig0VsQjxWWI\n+    ftb/tDv6UyHw50Ms66gT+h4dWepFVFDPb38HAhoU/RvmNCHWd33Nmhd1qf2jOQiR\n+    Q9q2qJ0gFgKFlrbJNTOkaFni2UdJ7ySS937C2rdOm5GTOaCODl6M4UjRAoGBANwn\n+    sFdT/HeY2lx84+jMxrzVOeNUpelye9G+VYk5poIMBSXX4Qm0V4EhmBOA4dEGwfhR\n+    yW/p1TG0uzvOu2igUVx2YcaxUZMLBSny++awUcnAbIoN175vqS0zhGKfKgsK1ak3\n+    /8P32zMm1vSz3ZR/+tzgcayWmOE8O1Cfw+Zks24bAoGBAIekjKAVTIrGIOWhYXnS\n+    yhTlwaclxOEzLUtY4W7RIh2g6BKascNMuN1EI8Q5IwUg2ChYYGvoLNmzblOadVqR\n+    m/OjoSFrUMu8VlIL5oITeW/XKAKq/3Nka05hcMIfvLFG57V1e/eP8JEhWzLmnAUJ\n+    NvfK3LU+YGNhRkFNjl4G8N6RAoGBAJMmA/uaqzjU9b6zyzGjDYLRkiucPHjYiGIc\n+    sddSrTRnDFnK/SMbYxFwftEqZ8Tqm2N6ZwViaZkbj7nd5+16mmcOyTOg+UErMHxl\n+    aHE8kK4k62cq8XTb9Vu8/1NbxyIyT7UXNOCrHdwGrc5JGmVTVT2k1tXgoraJJ6wv\n+    3SR1UmjZAoGARV26w6VMQKV0Y4ntnSIoGYWO9/15gSe2H3De+IPs4LyOP714Isi+\n+    2JcO4QPvgRfd5I5FY6FTi7T0Gz2/DXHggv9DXM9Q2yXMhV+3tkTuNFeDwBw7qRGy\n+    mCwOcAwHJ6GtCNvBDlpot6SauHEKKpzQobtq7giIEU3aSYR2unNg4wA=\n+    -----END RSA PRIVATE KEY----- github_token: 368ac3edf9e850d1c0ff9d6c526496f8237ddf91",
            "filename": "leak.txt",
            "filemode": "new file",
            "scan": {
                "secrets": [
                    {
                        "detector": {
                            "name": "facebook_app_keys",
                            "display_name": "Facebook Access Tokens",
                            "category": "Api",
                            "high_recall": False,
                            "metadata": {
                                "company_name": "Facebook",
                                "company_name_l": "facebook",
                                "company_name_normalized": "Facebook",
                            },
                        },
                        "matches": [
                            {
                                "string_matched": "294790898041573",
                                "indice_start": 34,
                                "indice_end": 49,
                                "name": "client_id",
                            },
                            {
                                "string_matched": "ce3f9f0362bbe5ab01dfc8ee565e4371",
                                "indice_start": 52,
                                "indice_end": 84,
                                "name": "client_secret",
                            },
                        ],
                        "status": "not_checked",
                    },
                    {
                        "detector": {
                            "name": "github_token",
                            "display_name": "GitHub Token",
                            "category": "Api",
                            "high_recall": False,
                            "metadata": {
                                "company_name": "GithubToken",
                                "company_name_l": "githubtoken",
                                "company_name_normalized": "GitHub",
                            },
                        },
                        "matches": [
                            {
                                "string_matched": "368ac3edf9e850d1c0ff9d6c526496f8237ddf91",
                                "indice_start": 1908,
                                "indice_end": 1948,
                                "name": "apikey",
                            }
                        ],
                        "status": "not_checked",
                    },
                    {
                        "detector": {
                            "name": "private_key_rsa",
                            "display_name": "RSA Private Key",
                            "category": "PrivateKey",
                            "high_recall": True,
                            "metadata": {},
                        },
                        "matches": [
                            {
                                "string_matched": "-----BEGIN RSA PRIVATE KEY-----\n+    MIIEpQIBAAKCAQEA0pj32LapDxsvsOdgVWzkZMdp/k7R+KJhuXLUxFTuRQFlBDcc\n+    mIPbkKzcJZO8pTXlRrqa4TiOLmdSM1AAW4cIX6xNYjO6V6Xx7wsXntg2YlYlN59e\n+    lbaj08VY59XRwTDNqBnINUVGdJKy2qxe/NUf0+vtp9Fbms4aKYyoP6G6zVUtVjLi\n+    vZzG8+3zEJlHJzTu5TTurqYLxPSIJCSxCFWuqcmiO7wFr/IdtzbygmI3D4dlCP51\n+    azZ4PnXYVXBb6TeB0FYEC7kAlSMFbKVRkuRAyrLQbxJWJNQOMFRO4XRyaCEbZKtO\n+    5ig6zt8An8ncfcNLgYAsvLOgpByq+kU/Ny98CwIDAQABAoIBAQDDQokqKdH965sA\n+    TscG7Xul5S7lV3dfLE+nfky/7G8vE+fxTJf64ObG8T78qEoUdDAsr//CKonJhIq2\n+    gMqUElM1QbBOCOARPA9hL8uqv5VM/8pqFB3CeiDTzPptmdZtZS6JWb5DhgOZOhsS\n+    nRdFHOXxu6ISIw7oLYgcVgn5VZ65mTzN6yB7pKsYkbm0NcJcmLnfuGbpQEP3WmC9\n+    X4wO7galKdHXuSxRdcJxCag2k0W7S4UAbp1tPmRAeDdOXqbGL7hu14rUZYtkiuRP\n+    546GDvOv+meHpDJve1hZ20CH2kRVq4DC64prPNfRJ1exSd94vlhokWL6SzTXItwm\n+    L8TUnHeBAoGBAPTi6WqbVcL9Uy2qJA8fJg7oN4yQ/goOh+mlW3Fsdig0VsQjxWWI\n+    ftb/tDv6UyHw50Ms66gT+h4dWepFVFDPb38HAhoU/RvmNCHWd33Nmhd1qf2jOQiR\n+    Q9q2qJ0gFgKFlrbJNTOkaFni2UdJ7ySS937C2rdOm5GTOaCODl6M4UjRAoGBANwn\n+    sFdT/HeY2lx84+jMxrzVOeNUpelye9G+VYk5poIMBSXX4Qm0V4EhmBOA4dEGwfhR\n+    yW/p1TG0uzvOu2igUVx2YcaxUZMLBSny++awUcnAbIoN175vqS0zhGKfKgsK1ak3\n+    /8P32zMm1vSz3ZR/+tzgcayWmOE8O1Cfw+Zks24bAoGBAIekjKAVTIrGIOWhYXnS\n+    yhTlwaclxOEzLUtY4W7RIh2g6BKascNMuN1EI8Q5IwUg2ChYYGvoLNmzblOadVqR\n+    m/OjoSFrUMu8VlIL5oITeW/XKAKq/3Nka05hcMIfvLFG57V1e/eP8JEhWzLmnAUJ\n+    NvfK3LU+YGNhRkFNjl4G8N6RAoGBAJMmA/uaqzjU9b6zyzGjDYLRkiucPHjYiGIc\n+    sddSrTRnDFnK/SMbYxFwftEqZ8Tqm2N6ZwViaZkbj7nd5+16mmcOyTOg+UErMHxl\n+    aHE8kK4k62cq8XTb9Vu8/1NbxyIyT7UXNOCrHdwGrc5JGmVTVT2k1tXgoraJJ6wv\n+    3SR1UmjZAoGARV26w6VMQKV0Y4ntnSIoGYWO9/15gSe2H3De+IPs4LyOP714Isi+\n+    2JcO4QPvgRfd5I5FY6FTi7T0Gz2/DXHggv9DXM9Q2yXMhV+3tkTuNFeDwBw7qRGy\n+    mCwOcAwHJ6GtCNvBDlpot6SauHEKKpzQobtq7giIEU3aSYR2unNg4wA=\n+    -----END RSA PRIVATE KEY-----",
                                "indice_start": 85,
                                "indice_end": 1893,
                                "name": "apikey",
                            }
                        ],
                        "status": "can_not_check",
                    },
                ],
                "metadata": {"version": "1.0.21", "leak_count": 3},
            },
            "error": False,
            "has_leak": True,
        }

        self.assertMatchSnapshot(leak_message(result))
