"""A localhost stand-in for the GitGuardian API.

Serves just enough of /v1 for both the Python hook and ggshield-hook to run a
full scan without a single byte leaving the machine.

  MODE=clean   -> no policy breaks
  MODE=secret  -> one "AWS Keys" policy break, with matches located in the
                  document that was actually submitted

The indices matter: the Python side maps every match back onto the document's
lines and errors out if a match falls outside them, so the mock cannot return
fixed offsets — it has to find the strings in the body it was given, exactly as
the real backend does.

Requests are logged to $REQUEST_LOG (one JSON line each) so the harness can diff
what each implementation actually sent.
"""

import hashlib
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


MODE = os.environ.get("MODE", "clean")
REQUEST_LOG = os.environ.get("REQUEST_LOG")

# Fake credentials, shaped like AWS keys. Never valid anywhere.
CLIENT_ID = "AKIA4SVQEXAMPLE01"
CLIENT_SECRET = "bB0mVX8s2example5zRq7Nn1LxKp9Wc3TyUvGh4Jd"

METADATA = {
    "version": "mock",
    "preferences": {"general__maximum_payload_size": 2621440},
    "secret_scan_preferences": {
        "maximum_document_size": 1048576,
        "maximum_documents_per_scan": 20,
    },
}

API_TOKEN = {
    "id": "00000000-0000-4000-8000-000000000000",
    "name": "mock",
    "workspace_id": 1,
    "type": "personal_access_token",
    "status": "active",
    "created_at": "2024-01-01T00:00:00+00:00",
    "last_used_at": None,
    "expire_at": None,
    "revoked_at": None,
    "member_id": 1,
    "creator_id": 1,
    "scopes": ["scan"],
}


def ignore_sha(document):
    """The sha a user would paste into `ignored_matches` for `document`.

    `get_ignore_sha()` in ggshield/core/filter.py: sha256 over
    "<match>,<match_type>" for every match of the policy break, sorted by
    match_type. It is derived from the document rather than hardcoded, because
    it covers only the matches actually present — a file containing just the
    client id produces a different sha from a command containing both halves.
    """
    matches = [m for m in _matches(document)]
    pairs = sorted(((m["match"], m["type"]) for m in matches), key=lambda pair: pair[1])
    hashable = "".join(f"{match},{match_type}" for match, match_type in pairs)
    return hashlib.sha256(hashable.encode("UTF-8")).hexdigest()


def locate(document, needle, match_type):
    """Build a Match for `needle` if it occurs in `document`.

    index_end is the index of the LAST character of the match, not the one
    after it (see pygitguardian's Match docstring).
    """
    start = document.find(needle)
    if start < 0:
        return None
    end = start + len(needle) - 1
    return {
        "type": match_type,
        "match": needle,
        "index_start": start,
        "index_end": end,
        "line_start": document.count("\n", 0, start) + 1,
        "line_end": document.count("\n", 0, end) + 1,
    }


def _matches(document):
    """Every known fake credential occurring in `document`, in a stable order."""
    return [
        m
        for m in (
            locate(document, CLIENT_ID, "client_id"),
            locate(document, CLIENT_SECRET, "client_secret"),
        )
        if m is not None
    ]


def scan(document):
    matches = _matches(document)
    if MODE != "secret" or not matches:
        return {
            "policy_break_count": 0,
            "policies": ["Secrets detection"],
            "policy_breaks": [],
        }
    return {
        "policy_break_count": 1,
        "policies": ["Secrets detection"],
        "policy_breaks": [
            {
                "policy": "Secrets detection",
                "type": "AWS Keys",
                "detector_name": "aws_iam",
                "detector_group_name": "aws_iam",
                "documentation_url": None,
                "validity": "valid",
                "known_secret": True,
                "incident_url": "https://dashboard.gitguardian.com/workspace/1/incidents/9",
                "is_excluded": False,
                "exclude_reason": None,
                "matches": matches,
            }
        ],
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence the default stderr spam
        pass

    def _send(self, payload, status=200):
        body = json.dumps(payload).encode()
        self.send_response(status)
        # pygitguardian's is_ok() requires this exact content type.
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.endswith("/metadata"):
            self._send(METADATA)
        elif "api_tokens" in self.path:
            self._send(API_TOKEN)
        else:
            self._send({"detail": "not found"}, 404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        if REQUEST_LOG:
            with open(REQUEST_LOG, "a") as f:
                f.write(
                    json.dumps(
                        {
                            "path": self.path,
                            "client": self.headers.get("User-Agent", ""),
                            # Which token got here, so a case can assert *whose*
                            # credentials were used and not just that a scan ran.
                            "token": self.headers.get("Authorization", ""),
                            "body": raw.decode("utf-8", "replace"),
                        }
                    )
                    + "\n"
                )
        if "multiscan" not in self.path:
            self._send({"detail": "not found"}, 404)
            return
        documents = json.loads(raw)
        self._send([scan(doc.get("document", "")) for doc in documents])


if __name__ == "__main__":
    port = int(sys.argv[1])
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
