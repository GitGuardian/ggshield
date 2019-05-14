import aiohttp
from typing import Dict, Union


class ScanningApiClient:
    URL = "https://scanning.api.dev.gitguardian.com/v2/scan/file"
    TIMEOUT = 10

    def __init__(
        self, apikey: str = "", url: str = URL, timeout: int = TIMEOUT
    ) -> None:
        self.apikey = apikey
        self.url = url
        self.timeout = timeout

    @property
    def headers(self) -> Dict:
        return {"apikey": self.apikey}

    async def scan_file(
        self, content: str, filename: str = None, check: Union[bool, None] = None
    ) -> Dict:
        """
        Calls Scanning API and returns response
        """
        payload = {"content": content}
        if filename:
            payload["filename"] = filename
        if isinstance(check, bool):
            payload["check"] = check

        async with aiohttp.ClientSession() as session:
            async with session.post(
                self.url, headers=self.headers, json=payload, timeout=self.timeout
            ) as resp:
                return await resp.json()
