from snapshottest import TestCase
from secrets_shield.message import leak_message, no_leak_message


class TestMessage(TestCase):
    def test_message_no_secret(self):
        self.assertMatchSnapshot(no_leak_message())

    def test_message_simple_secret(self):
        result = {
            "content": "+github_token: 368ac3edf9e850d1c0ff9d6c526496f8237ddf91\n",
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
                                "indice_start": 15,
                                "indice_end": 55,
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
            "content": "+FacebookAppId = 294790898041575; FacebookAppSecret = ce3f9f0362bbe5ab01dfc8ee565e4372;\n",
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
                                "indice_start": 17,
                                "indice_end": 32,
                                "name": "client_id",
                            },
                            {
                                "string_matched": "ce3f9f0362bbe5ab01dfc8ee565e4372",
                                "indice_start": 54,
                                "indice_end": 86,
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
            "content": "+Facebook = 294790898041575 | ce3f9f0362bbe5ab01dfc8ee565e4372;\n",
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
                                "indice_start": 12,
                                "indice_end": 27,
                                "name": "client_id",
                            },
                            {
                                "string_matched": "ce3f9f0362bbe5ab01dfc8ee565e4372",
                                "indice_start": 30,
                                "indice_end": 62,
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
            "content": "+FacebookAppId = 294790898041575;\n+FacebookAppSecret = ce3f9f0362bbe5ab01dfc8ee565e4372;\n",
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
                                "indice_start": 17,
                                "indice_end": 32,
                                "name": "client_id",
                            },
                            {
                                "string_matched": "ce3f9f0362bbe5ab01dfc8ee565e4372",
                                "indice_start": 55,
                                "indice_end": 87,
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
