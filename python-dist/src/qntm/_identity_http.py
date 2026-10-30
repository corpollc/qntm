"""Bounded, non-redirecting HTTP reads for identity documents."""

import json
import urllib.request

MAX_IDENTITY_DOCUMENT_BYTES = 256 * 1024


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_opener = urllib.request.build_opener(_NoRedirect())


def read_identity_json(request, *, timeout):
    with _opener.open(request, timeout=timeout) as response:
        raw = response.read(MAX_IDENTITY_DOCUMENT_BYTES + 1)
    if len(raw) > MAX_IDENTITY_DOCUMENT_BYTES:
        raise ValueError("identity document exceeds size limit")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("identity document must be an object")
    return data
